use std::collections::BTreeMap;
use std::env;
use std::fs::File;
use std::io::{self, Result, Write};
use std::io::{BufRead, BufReader, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use elf_util::*;
use exceptions::*;
use find_elf::*;
use utils::*;

use goblin::elf::{self, Elf};
use structopt::StructOpt;
use tempfile::NamedTempFile;

mod elf_util;
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
    fn exre_check(&self, exc: ExcRtime, path: &str) -> bool {
        if let Some(checker) = &self.exre {
            checker.check(exc, path)
        } else {
            false
        }
    }
    fn get_config(&self) -> Config {
        // TODO: build crle string
        let crle_env = String::new();
        Config::new(&self.opts, self.exre.as_ref(), crle_env)
    }
}

struct Config<'a> {
    pub process_dyn_table: bool,
    pub process_mcs: bool,
    pub process_stab: bool,
    pub process_verdef: bool,
    pub oneliner_output: bool,
    exception_list: Option<&'a Checker>,
    ldd_crle_env: String,
}
impl<'a> Config<'a> {
    pub fn new(
        opts: &Opts,
        exre: Option<&'a Checker>,
        ldd_crle_env: String,
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
    pub fn exre_check(&self, exc: ExcRtime, item: &str) -> bool {
        if let Some(checker) = &self.exception_list {
            checker.check(exc, item)
        } else {
            false
        }
    }
    pub fn clre_env(&self) -> &str {
        &self.ldd_crle_env
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

        if state.exre_check(ExcRtime::NoCrleAlt, &item.path) {
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

const MODE_SUID_GUID: u32 = 0o6000;

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

fn check_ldd(cfg: &Config, path: &str, full_path: &str) -> Results {
    let mut cmd = Command::new("ldd");
    cmd.arg("-rU");
    //cmd.arg(CRLE stuff);
    cmd.arg(full_path);
    cmd.stdin(Stdio::null());

    let out = cmd.output().unwrap();

    // 	# Use ldd(1) to determine the objects relocatability and use.
    // 	# By default look for all unreferenced dependencies.  However,
    // 	# some objects have legitimate dependencies that they do not
    // 	# reference.
    // 	@Ldd = split(/\n/, `ldd -rU $Env $LDDFullPath 2>&1`);
    // 	if ($Secure) {
    // 		unlink $LDDFullPath;
    // 	}
    // }

    // Number of missing symbols we will complain about before gagging the
    // output to cut down on excess noise.
    let mut missing: Option<usize> = Some(5);
    let mut check_undep = true;
    let mut res = Results::default();

    for (nr, line) in BufReader::new(out.stdout.chain(&out.stderr[..]))
        .lines()
        .map(Result::unwrap)
        .enumerate()
    {
        if nr == 0 {
            // Make sure ldd(1) worked.
            if line.contains("usage:") {
                res.push_err(&format!("{}\t<old ldd(1)?>", line));
            } else if line.contains("execution failed") {
                res.push_err(&line);
            }
            // It's possible this binary can't be executed, ie. we've
            // found a sparc binary while running on an intel system,
            // or a sparcv9 binary on a sparcv7/8 system.
            if line.contains("wrong class") {
                res.push_err("has wrong class or data encoding");
                continue;
            }

            // Historically, ldd(1) likes executable objects to have
            // their execute bit set.
            if line.contains("not executable") {
                res.push_err("is not executable");
                continue;
            }
        }

        // Look for "file" or "versions" that aren't found.  Note that
        // these lines will occur before we find any symbol referencing
        // errors.
        if missing.is_some() && line.contains("not found") {
            if line.contains("file not found)") {
                res.push_err(&format!("{}\t<no -zdefs?>", line));
            } else {
                res.push_err(&line);
            }
            continue;
        }
        // Look for relocations whose symbols can't be found.  Note, we
        // only print out the first 5 relocations for any file as this
        // output can be excessive.
        if missing.is_some() && line.contains("symbol not found") {
            // Determine if this file is allowed undefined references.
            if cfg.exre_check(ExcRtime::UndefRef, path) {
                missing = None;
                continue;
            }
            missing = match missing {
                Some(1) => {
                    if !cfg.oneliner_output {
                        res.push_err("continued ...");
                    }
                    None
                }
                Some(x) => {
                    // Just print the symbol name.
                    res.push_err(&format!("{}\t<no -zdefs>?", line));
                    Some(x - 1)
                }
                None => None,
            };
            continue;
        }

        // Look for any unused search paths.
        if line.contains("unused search path=") {
            if cfg.exre_check(ExcRtime::UnusedRpath, &line) {
                continue;
            }
            // if ($Secure) {
            //     $Line =~ s!$Tmpdir/!!;
            // }
            // $Line =~ s/^[ \t]*(.*)/\t$1\t<remove search path?>/;
            // onbld_elfmod::OutMsg($ErrFH, $ErrTtl, $RelPath, $Line);
            todo!("XXX FINISH ME");
            //continue;
        }

        // Look for unreferenced dependencies.  Note, if any unreferenced
        // objects are ignored, then set $UnDep so as to suppress any
        // associated unused-object messages.
        if line.contains("unreferenced object=") {
            if cfg.exre_check(ExcRtime::UnrefObj, &line) {
                check_undep = false;
                continue;
            }
            // if ($Secure) {
            //     $Line =~ s!$Tmpdir/!!;
            // }
            // $Line =~ s/^[ \t]*(.*)/$1\t<remove lib or -zignore?>/;
            // onbld_elfmod::OutMsg($ErrFH, $ErrTtl, $RelPath, $Line);
            // next;
            todo!("XXX FINISH ME");
            //continue;
        }

        //  Look for any unused dependencies.
        if check_undep && line.contains("unused") {
            // Skip if object is allowed to have unused dependencies
            if cfg.exre_check(ExcRtime::UnusedDeps, path) {
                continue;
            }

            // Skip if dependency is always allowed to be unused
            if cfg.exre_check(ExcRtime::UnusedObj, &line) {
                continue;
            }

            // $Line =~ s!$Tmpdir/!! if $Secure;
            // $Line =~ s/^[ \t]*(.*)/$1\t<remove lib or -zignore?>/;
            // onbld_elfmod::OutMsg($ErrFH, $ErrTtl, $RelPath, $Line);
            continue;
        }
    }
    res
}

fn process_file(
    cfg: &Config,
    prefix: &str,
    path: &str,
    obj: Object,
) -> Result<Option<Results>> {
    let full_path = format!("{}/{}", prefix, path);
    let meta = std::fs::symlink_metadata(&full_path)?;

    // Ignore symbolic links
    if meta.file_type().is_symlink() {
        return Ok(None);
    }

    // Is this an object or directory hierarchy we don't care about?
    if cfg.exre_check(ExcRtime::Skip, path) {
        return Ok(None);
    }

    let mut res = Results::default();

    // # Determine whether we have access to inspect the file.
    let fp = match File::open(&full_path) {
        Ok(fp) => fp,
        Err(e) => {
            res.push_err("unable to inspect file: permission denied");
            return Ok(Some(res));
        }
    };

    let mmap = RoMMap::new(fp.as_raw_fd(), meta.len() as usize)?;
    let rodata = mmap.take();
    let elf = match Elf::parse(rodata) {
        Ok(v) => v,
        Err(_e) => {
            // TODO: emit error?
            return Ok(None);
        }
    };

    // On x86, check for for PT_LOAD segments with RWX permissions
    if elf.header.e_machine == elf::header::EM_386
        || elf.header.e_machine == elf::header::EM_X86_64
    {
        if elf.program_headers.iter().any(|phdr| {
            phdr.p_type == elf::program_header::PT_LOAD
                && phdr.is_read()
                && phdr.is_write()
                && phdr.is_executable()
        }) {
            if !cfg.exre_check(ExcRtime::ExecData, path) {
                res.push_err("application requires non-executable data\t<no -Mmapfile_noexdata?>");
            }
        }
    }

    // Applications should contain a non-executable stack definition.
    if obj.is_exec {
        if !elf
            .program_headers
            .iter()
            .any(|phdr| phdr.p_type == elf::program_header::PT_SUNWSTACK)
        {
            if !cfg.exre_check(ExcRtime::ExecStack, path) {
                res.push_err(
                    "non-executable stack required\t<no -Mmapfile_noexstk?>",
                );
            }
        }
    }

    // Determine whether this ELF executable or shared object has a conforming
    // mcs(1) comment section.
    if cfg.process_mcs && !cfg.exre_check(ExcRtime::NoComment, path) {
        let mut conform = false;
        if let Some(comment_data) = find_shdr(&elf, ".comment")
            .map(elf::SectionHeader::file_range)
            .flatten()
        {
            let br = BufReader::new(NullToNewline::new(&rodata[comment_data]));
            let lines: Vec<_> = br.lines().map(Result::unwrap).collect();

            // If the correct $(POST_PROCESS) macros are used, only a 2 or 3
            // line .comment section should exist containing one or two
            // "@(#)illumos" identifying comments (one comment for a non-debug
            // build, and two for a debug build).  An empty line may also follow
            // this as well.
            if lines[0].is_empty() && lines[1].starts_with("@(#)illumos") {
                conform = match (lines.get(2), lines.get(3)) {
                    (None, None) => true,
                    (Some(l2), None) => {
                        l2.is_empty() || l2.starts_with("@(#)illumos")
                    }
                    (Some(l2), Some(l3)) => {
                        l2.starts_with("@(#)illumos")
                            && l3.is_empty()
                            && lines.len() == 4
                    }
                    _ => false,
                };
            }
        }

        if !conform {
            res.push_err(
                "non-conforming mcs(1) comment\t<no $(POST_PROCESS)?>",
            );
        }
    }
    // Having caught any static executables in the mcs(1) check and non-
    // executable stack definition check, continue with dynamic objects
    // from now on.
    if !elf
        .section_headers
        .iter()
        .any(|shdr| shdr.sh_type == elf::section_header::SHT_DYNAMIC)
    {
        return Ok(res.squash());
    }

    // Perform ldd(1) checks
    let ldd_res = if (meta.mode() & MODE_SUID_GUID) == 0 {
        check_ldd(cfg, &path, &full_path)
    } else {
        // The execution of a secure application over an nfs file
        // system mounted nosuid will result in warning messages
        // being sent to /var/adm/messages.  As this type of
        // environment can occur with root builds, move the file
        // being investigated to a safe place first.  In addition
        // remove its secure permission so that it can be
        // influenced by any alternative dependency mappings.

        // Copy into a temp file where we control the permissions
        let mut lddtmp = NamedTempFile::new()?;
        lddtmp.write_all(rodata)?;
        lddtmp
            .as_file_mut()
            .set_permissions(PermissionsExt::from_mode(0o0555))?;

        check_ldd(cfg, &path, &lddtmp.path().to_string_lossy())
    };
    res.append(ldd_res);

    let (mut has_sunreloc, mut has_stabs, mut has_symtab, mut has_symsort) =
        (false, false, false, false);
    let mut syminfo: Option<elf::SectionHeader> = None;
    for shdr in elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(shdr.sh_name) {
            match name {
                // $Sun
                ".SUNW_reloc" => has_sunreloc = true,
                // $Stab
                ".stab" => has_stabs = true,
                // $SymSort
                ".SUNW_dynsymsort" | ".SUNW_dyntlssort" => has_symsort = true,
                // !$Strip
                ".symtab" => has_symtab = true,
                ".SUNW_syminfo" => syminfo = Some(shdr),
                _ => {}
            }
        }
    }

    let mut has_direct_binding = false;
    // Look into the Syminfo section.
    // Does this object have at least one Directly Bound symbol?
    if let Some(si_hdr) = &syminfo {
        if let Some(si_entries) = parse_syminfo(rodata, si_hdr) {
            has_direct_binding = si_entries
                .iter()
                .any(|si| (si.si_flags & SYMINFO_FLG_DIRECTBIND) != 0);
        }
    }

    if let Some(edyn) = &elf.dynamic {
        let info = &edyn.info;

        if info.flags_1 & elf::dynamic::DF_1_DIRECT != 0 {
            has_direct_binding = true;
        }

        // Determine if this file is allowed text relocations.
        if info.textrel {
            if !cfg.exre_check(ExcRtime::TextRel, path) {
                res.push_err("TEXTREL .dynamic tag\t\t\t<no -Kpic?>");
            }
        }

        let relsz = usize::max(info.relsz, info.relasz);
        let pltsz = info.pltrelsz;

        // A shared object, that contains non-plt relocations, should have a
        // combined relocation section indicating it was built with -z combreloc.
        if !obj.is_exec && relsz != 0 && relsz != pltsz && !has_sunreloc {
            res.push_err(".SUNW_reloc section missing\t\t<no -zcombreloc?>");
        }

        // # Identify an object that is not built with either -B direct or
        // # -z direct.
        if relsz != 0
            && !has_direct_binding
            && !cfg.exre_check(ExcRtime::NoDirect, path)
        {
            res.push_err(
                "object has no direct bindings\t<no -B direct or -z direct?>",
            );
        }

        // Does this object specify a runpath?
        let dynstrtab = &elf.dynstrtab;
        if let Some(rpath) = edyn
            .dyns
            .iter()
            .find(|d| d.d_tag == elf::dynamic::DT_RPATH)
            .map(|d| dynstrtab.get_at(d.d_val as usize))
            .flatten()
        {
            res.push_info(format!("RPATH={}", rpath));
        }
    }
    for need in elf.libraries {
        // Catch any old (unnecessary) dependencies.
        if cfg.exre_check(ExcRtime::OldDep, need) {
            res.push_err(&format!(
                "NEEDED={}\t<dependency no longer necessary>",
                need
            ));
        } else if cfg.exre_check(ExcRtime::Forbidden, need)
            && !cfg.exre_check(ExcRtime::ForbiddenDep, need)
        {
            res.push_err(&format!(
                "NEEDED={}\t<forbidden dependency, missing -nodefaultlibs?>",
                need
            ));
        } else if cfg.process_dyn_table {
            res.push_info(format!("NEEDED={}", need));
        }
    }

    // No objects released to a customer should have any .stabs sections
    // remaining, they should be stripped.
    if cfg.process_stab
        && has_stabs
        && !cfg.exre_check(ExcRtime::Forbidden, path)
    {
        res.push_err("debugging sections should be deleted\t<no strip -x?>");
    }

    // All objects should have a full symbol table to provide complete
    // debugging stack traces.
    if !has_symtab {
        res.push_err("symbol table should not be stripped\t<remove -s?>");
    }

    // If there are symbol sort sections in this object, report on
    // any that have duplicate addresses.
    if has_symsort && !cfg.exre_check(ExcRtime::NoSymSort, path) {
        // ProcSymSort($FullPath, $RelPath)
    }

    // If -v was specified, and the object has a version definition
    // section, generate output showing each public symbol and the
    // version it belongs to.
    if obj.has_verdef && cfg.process_verdef {
        // ProcVerdef($FullPath, $RelPath)
    }
    Ok(res.squash())
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
    let cfg = state.get_config();
    let mut results = BTreeMap::new();
    for item in fe {
        if let Record::Object(o) = item.record {
            if let Ok(Some(res)) = process_file(&cfg, &prefix, &item.path, o) {
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
