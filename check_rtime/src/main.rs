use std::fs::File;
use std::io::Result;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use exceptions::*;
use structopt::StructOpt;
use tempfile::NamedTempFile;

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
    produce_dyn_table: bool,

    /// process mcs(1) comments
    #[structopt(short = "m")]
    process_mcs: bool,

    /// produce one-liner output (prefixed with pathname)
    #[structopt(short = "o")]
    produce_oneliner: bool,

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

#[derive(Default)]
struct Config {
    ws: Option<PathBuf>,
    exre: Option<Checker>,
    crle64: Option<NamedTempFile>,
    crle32: Option<NamedTempFile>,
}
impl Config {
    fn new() -> Self {
        Self {
            ws: std::env::var("CODEMSG_WS").ok().map(PathBuf::from),
            ..Default::default()
        }
    }
    fn exre_check(&self, exc: ExcRtime, path: &str) -> bool {
        if let Some(checker) = self.exre.as_ref() {
            checker.check(exc, path)
        } else {
            false
        }
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
fn alt_object_config(opts: &Opts, cfg: &mut Config) -> Result<()> {
    let fe = if let Some(dep_file) = opts.dep_file.as_ref() {
        find_elf::FindElf::from_file(dep_file)?
    } else {
        // Locate proto dir, either as passed in via CLI or from WS env
        let proto = opts
            .dep_dir
            .as_ref()
            .map(|d| d.clone())
            .or_else(|| cfg.ws.clone())
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
                if !o.is_dyn {
                    last_dyn = None;
                    continue;
                }
                last_dyn = Some(o);
                o
            }
            find_elf::Record::Alias(_src) => {
                if let Some(ld) = last_dyn.as_ref() {
                    *ld
                } else {
                    continue;
                }
            }
        };

        if cfg.exre_check(ExcRtime::NoCrleAlt, &item.path) {
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

    cfg.crle32 = build_crle_conf(crle32, false);
    cfg.crle64 = build_crle_conf(crle64, true);

    Ok(())
}

fn prep(opts: &Opts) -> Result<Config> {
    let mut cfg = Config::new();

    // Change dir if requested
    if let Some(path) = opts.relative_outdir.as_ref() {
        std::env::set_current_dir(path.as_path())?;
    }

    // load exception lists
    cfg.exre = load_exceptions(opts, cfg.ws.as_ref())?;

    // generate crle configs
    alt_object_config(opts, &mut cfg)?;

    Ok(cfg)
}

fn main() {
    let opts = Opts::from_args();

    let cfg = match prep(&opts) {
        Err(e) => {
            eprintln!("Error during setup: {:?}", e);
            std::process::exit(1);
        }
        Ok(s) => s,
    };
    println!("opts: {:?}", opts);
}

// if ((getopts('D:d:E:e:f:I:imosvw:', \%opt) == 0) ||
//     (!$opt{f} && ($#ARGV == -1))) {
// 	print "usage: $Prog [-imosv] [-D depfile | -d depdir] [-E errfile]\n";
// 	print "\t\t[-e exfile] [-f listfile] [-I infofile] [-w outdir]\n";
// 	print "\t\t[file | dir]...\n";
// 	print "\n";
// 	print "\t[-D depfile]\testablish dependencies from 'find_elf -r' file list\n";
// 	print "\t[-d depdir]\testablish dependencies from under directory\n";
// 	print "\t[-E errfile]\tdirect error output to file\n";
// 	print "\t[-e exfile]\texceptions file\n";
// 	print "\t[-f listfile]\tuse file list produced by find_elf -r\n";
// 	print "\t[-I infofile]\tdirect informational output (-i, -v) to file\n";
// 	print "\t[-i]\t\tproduce dynamic table entry information\n";
// 	print "\t[-m]\t\tprocess mcs(1) comments\n";
// 	print "\t[-o]\t\tproduce one-liner output (prefixed with pathname)\n";
// 	print "\t[-s]\t\tprocess .stab and .symtab entries\n";
// 	print "\t[-v]\t\tprocess version definition entries\n";
// 	print "\t[-w outdir]\tinterpret all files relative to given directory\n";
// 	exit 1;
// }
