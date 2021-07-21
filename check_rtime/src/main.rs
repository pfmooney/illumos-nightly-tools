use std::collections::BTreeMap;
use std::env;
use std::fs::File;
use std::io::{self, Result, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use exceptions::*;
use find_elf::*;

use structopt::StructOpt;
use tempfile::NamedTempFile;

mod checks;
mod exceptions;
mod find_elf;

#[derive(StructOpt, Debug)]
struct Opts {
    /// establish dependencies from `find_elf -r` file list
    #[structopt(short = "D", parse(from_os_str), name = "DEPFILE")]
    dep_file: Option<PathBuf>,

    /// establish dependencies from under directory\n";
    #[structopt(short = "d", parse(from_os_str), name = "DEPDIR")]
    dep_dir: Option<PathBuf>,

    /// direct error output to file
    #[structopt(short = "E", parse(from_os_str), name = "ERRFILE")]
    err_file: Option<PathBuf>,

    /// exceptions file
    #[structopt(short = "e", parse(from_os_str), name = "EXFILE")]
    ex_file: Option<PathBuf>,

    /// use file list produced by `find_elf -r`
    #[structopt(short = "f", parse(from_os_str), name = "LISTFILE")]
    list_file: Option<PathBuf>,

    /// direct informational output (-i, -v) to file
    #[structopt(short = "I", parse(from_os_str), name = "INFOFILE")]
    info_file: Option<PathBuf>,

    /// produce dynamic table entry information
    #[structopt(short = "i")]
    process_dyn_table: bool,

    /// process mcs(1) comments
    #[structopt(short = "m")]
    process_mcs: bool,

    /// produce one-liner output (prefixed with pathname)
    #[structopt(short = "o")]
    oneliner_output: bool,

    /// process .stab and .symtab entries
    #[structopt(short = "s")]
    process_stab: bool,

    /// process version definition entries
    #[structopt(short = "v")]
    process_verdef: bool,

    /// interpret all files relative to given directory
    #[structopt(short = "w", parse(from_os_str), name = "OUTDIR")]
    relative_outdir: Option<PathBuf>,

    #[structopt(parse(from_os_str))]
    path_list: Vec<PathBuf>,
}

struct AppState {
    opts: Opts,
    ws: Option<PathBuf>,
    exre: Option<Checker>,
    crle64: Option<NamedTempFile>,
    crle32: Option<NamedTempFile>,
    fp_info: Box<dyn Write>,
    fp_err: Box<dyn Write>,
    output_combined: bool,
}
impl AppState {
    fn new(
        opts: Opts,
        ws: Option<PathBuf>,
        info: Option<File>,
        err: Option<File>,
    ) -> Self {
        let (fp_info, fp_err, combine): (Box<dyn Write>, Box<dyn Write>, bool) =
            match (info, err) {
                (None, None) => {
                    (Box::new(io::stdout()), Box::new(io::stdout()), true)
                }
                (None, Some(efp)) => {
                    (Box::new(io::stdout()), Box::new(efp), false)
                }
                (Some(ifp), None) => {
                    (Box::new(ifp), Box::new(io::stdout()), false)
                }
                (Some(ifp), Some(efp)) => {
                    //TODO: could be more robust with this check
                    let same = opts.info_file.as_ref().unwrap()
                        == opts.err_file.as_ref().unwrap();

                    (Box::new(ifp), Box::new(efp), same)
                }
            };
        Self {
            opts,
            ws,
            fp_info,
            fp_err,
            output_combined: combine,
            exre: None,
            crle64: None,
            crle32: None,
        }
    }
    fn excepted(&self, exc: ExcRtime, path: &str) -> bool {
        if let Some(checker) = &self.exre {
            checker.check(exc, path)
        } else {
            false
        }
    }

    fn crle_env(&self) -> Option<String> {
        let crle32 = self.crle32.as_ref().map(|tf| tf.path().to_string_lossy());
        let crle64 = self.crle64.as_ref().map(|tf| tf.path().to_string_lossy());
        match (crle32, crle64) {
            (None, None) => None,
            (Some(c32), None) => Some(format!("LD_FLAGS=config_32={}", c32)),
            (None, Some(c64)) => Some(format!("LD_FLAGS=config_64={}", c64)),
            (Some(c32), Some(c64)) => {
                Some(format!("LD_FLAGS=config_64={},config_32={}", c64, c32))
            }
        }
    }

    fn config(&self) -> Config {
        Config::new(&self.opts, self.exre.as_ref(), self.crle_env())
    }
}

pub(crate) struct Config<'a> {
    pub process_dyn_table: bool,
    pub process_mcs: bool,
    pub process_stab: bool,
    pub process_verdef: bool,
    pub oneliner_output: bool,
    exception_list: Option<&'a Checker>,
    ldd_crle_env: Option<String>,
}
impl<'a> Config<'a> {
    pub fn new(
        opts: &Opts,
        exre: Option<&'a Checker>,
        ldd_crle_env: Option<String>,
    ) -> Self {
        Self {
            process_dyn_table: opts.process_dyn_table,
            process_mcs: opts.process_mcs,
            process_stab: opts.process_stab,
            process_verdef: opts.process_verdef,
            oneliner_output: opts.oneliner_output,
            exception_list: exre,
            ldd_crle_env,
        }
    }
    pub fn excepted(&self, exc: ExcRtime, item: &str) -> bool {
        if let Some(checker) = &self.exception_list {
            checker.check(exc, item)
        } else {
            false
        }
    }
    pub fn crle_env(&self) -> Option<&String> {
        self.ldd_crle_env.as_ref()
    }
}

fn load_exceptions(
    opts: &Opts,
    wsdir: Option<&PathBuf>,
) -> Result<Option<Checker>> {
    if let Some(exf) = opts.ex_file.as_ref().filter(|f| f.is_file()) {
        let fp = File::open(exf)?;
        return Ok(Some(Checker::load(fp)));
    } else if let Some(ws) = wsdir {
        let mut target = ws.clone();
        target.push("exception_lists");
        target.push("check_rtime");

        if target.is_file() {
            let fp = File::open(target)?;
            return Ok(Some(Checker::load(fp)));
        }
    }
    Ok(None)
}

fn build_crle_conf(
    entries: Vec<(String, String)>,
    is_64bit: bool,
) -> Option<NamedTempFile> {
    if entries.is_empty() {
        return None;
    }
    let mut cmd = Command::new("crle");
    if is_64bit {
        cmd.arg("-64");
    }

    for (path, dir) in entries {
        cmd.args(["-o", &dir, "-a", &format!("/{}", path)]);
    }

    let tf = NamedTempFile::new().ok()?;
    cmd.args(["-c", tf.path().to_str()?]);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    let _ = cmd.output().ok()?;

    Some(tf)
}

// Recurse through a directory hierarchy looking for appropriate dependencies to map from their
// standard system locations to the proto area via a crle config file.
fn alt_object_config(state: &mut AppState) -> Result<()> {
    let fe = if let Some(dep_file) = &state.opts.dep_file {
        find_elf::FindElf::from_file(dep_file)?
    } else {
        // Locate proto dir, either as passed in via CLI or from WS env
        let proto = state
            .opts
            .dep_dir
            .as_ref()
            .cloned()
            .or_else(|| state.ws.clone())
            .filter(|d| d.is_dir());

        if let Some(dir) = proto {
            find_elf::FindElf::from_cmd(dir, true)?
        } else {
            return Ok(());
        }
    };

    // Entries of `path` and `dir`
    let mut crle32: Vec<(String, String)> = Vec::new();
    let mut crle64: Vec<(String, String)> = Vec::new();

    let prefix = PathBuf::from(fe.prefix().unwrap());
    let mut last_dyn: Option<find_elf::Object> = None;
    for item in fe {
        let obj = match item.record {
            find_elf::Record::Object(o) => {
                if !o.is_exec {
                    last_dyn = None;
                    continue;
                }
                last_dyn = Some(o);
                o
            }
            find_elf::Record::Alias(_src) => {
                if let Some(ld) = &last_dyn {
                    *ld
                } else {
                    continue;
                }
            }
        };

        if state.excepted(ExcRtime::NoCrleAlt, &item.path) {
            continue;
        }

        let mut full = prefix.clone();
        full.push(&item.path);

        let dir_part = if full.file_name().is_some() {
            full.parent().unwrap()
        } else {
            full.as_path()
        }
        .to_string_lossy()
        .to_string();

        if obj.is_64bit {
            crle64.push((item.path, dir_part));
        } else {
            crle32.push((item.path, dir_part));
        }
    }

    state.crle32 = build_crle_conf(crle32, false);
    state.crle64 = build_crle_conf(crle64, true);

    Ok(())
}

fn prep(opts: Opts) -> Result<AppState> {
    // Change dir if requested
    if let Some(path) = &opts.relative_outdir {
        env::set_current_dir(path.as_path())?;
    }

    let info = opts.info_file.as_ref().map(File::create).transpose()?;
    let err = opts.err_file.as_ref().map(File::create).transpose()?;
    let mut state = AppState::new(
        opts,
        env::var("CODEMSG_WS").ok().map(PathBuf::from),
        info,
        err,
    );

    // load exception lists
    state.exre = load_exceptions(&state.opts, state.ws.as_ref())?;

    // generate crle configs
    alt_object_config(&mut state)?;

    Ok(state)
}

#[derive(Default)]
struct Results {
    info: Vec<String>,
    errors: Vec<String>,
}
impl Results {
    fn push_err(&mut self, msg: &str) {
        self.errors.push(msg.to_string())
    }
    fn push_info(&mut self, info: String) {
        self.info.push(info)
    }
    fn is_empty(&self) -> bool {
        self.info.is_empty() && self.errors.is_empty()
    }
    fn squash(self) -> Option<Self> {
        if self.info.is_empty() && self.errors.is_empty() {
            None
        } else {
            Some(self)
        }
    }
    fn append(&mut self, mut other: Self) {
        self.info.append(&mut other.info);
        self.errors.append(&mut other.errors);
    }
}

fn format_results(state: &mut AppState, obj: &str, res: &Results) {
    let oneliner = state.opts.oneliner_output;
    let combined = state.output_combined;

    let write_hdr = |fp: &mut Box<dyn Write>| {
        let _ = write!(fp, "==== {} ====\n", obj);
    };

    if combined && !oneliner {
        // Write a shared header for combined output
        write_hdr(&mut state.fp_info);
    }

    for (kind_fp, kind_res) in
        [(&mut state.fp_err, &res.errors), (&mut state.fp_info, &res.info)]
    {
        if !kind_res.is_empty() {
            if !combined && !oneliner {
                write_hdr(kind_fp);
            }
            for msg in kind_res.iter() {
                if oneliner {
                    let _ = write!(kind_fp, "{}: {}\n", obj, msg);
                } else {
                    let _ = write!(kind_fp, "\t{}\n", msg);
                }
            }
        }
    }
}

fn process(state: &mut AppState, fe: FindElf) {
    let prefix = fe.prefix().unwrap();
    let cfg = state.config();
    let mut results = BTreeMap::new();
    for item in fe {
        if let Record::Object(o) = item.record {
            if let Ok(Some(res)) =
                checks::process_file(&cfg, &prefix, &item.path, o)
            {
                results.insert(item.path, res);
            }
        }
    }
    for (obj, res) in results.iter() {
        if !res.is_empty() {
            format_results(state, obj, res);
        }
    }
}

fn main() {
    let opts = Opts::from_args();

    let mut cfg = match prep(opts) {
        Err(e) => {
            eprintln!("Error during setup: {:?}", e);
            std::process::exit(1);
        }
        Ok(s) => s,
    };

    if let Some(path) = &cfg.opts.list_file {
        let fe = FindElf::from_file(path).unwrap();
        process(&mut cfg, fe);
    }
    let cli_paths = cfg.opts.path_list.clone();
    for path in cli_paths {
        if let Ok(fe) = FindElf::from_cmd(path, false) {
            process(&mut cfg, fe);
        }
    }
}
