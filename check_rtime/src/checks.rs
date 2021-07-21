use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::io::{Result, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::process::{Command, Stdio};

use super::exceptions::*;
use super::find_elf::*;
use super::{Config, Results};
use utils::*;

use goblin::elf::{self, Elf};
use tempfile::NamedTempFile;

const SYMINFO_FLG_DIRECTBIND: u16 = 0x10;

#[repr(C)]
struct Syminfo {
    pub si_boundto: u16,
    pub si_flags: u16,
}

fn parse_syminfo<'a>(
    file_data: &'a [u8],
    shdr: &elf::SectionHeader,
) -> Option<&'a [Syminfo]> {
    let contents = &file_data[shdr.file_range()?];

    // Safety: Syminfo is made up of primitive integers and contains no padding,
    // so constructing it from the raw data is safe here.
    let (_prefix, items, _suffix) = unsafe { contents.align_to::<Syminfo>() };

    Some(items)
}

fn find_shdr<'a>(
    elf: &'a elf::Elf,
    name: &str,
) -> Option<&'a elf::SectionHeader> {
    elf.section_headers.iter().find(|shdr| {
        elf.shdr_strtab.get_at(shdr.sh_name).map(|n| n == name).unwrap_or(false)
    })
}

/// Convert any NULs to newlines like mcs(1) does
struct CommentFilter<R: Read> {
    inner: R,
}
impl<R: Read> CommentFilter<R> {
    pub fn new(inner: R) -> Self {
        Self { inner }
    }
}
impl<R: Read> Read for CommentFilter<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.inner.read(buf) {
            Ok(c) => {
                for b in buf[..c].iter_mut() {
                    if *b == b'\0' {
                        *b = b'\n'
                    }
                }
                Ok(c)
            }
            e => e,
        }
    }
}

fn check_ldd(cfg: &Config, path: &str, full_path: &str) -> Results {
    let mut cmd = Command::new("ldd");
    cmd.arg("-rU");
    if let Some(env) = cfg.crle_env() {
        cmd.args(&["-e", env]);
    }
    cmd.arg(full_path);
    cmd.stdin(Stdio::null());
    let out = cmd.output().unwrap();

    let sanitize = |m: String| -> String { m.replace(full_path, path) };

    // Number of missing symbols we will complain about before gagging the
    // output to cut down on excess noise.
    const MISSING_LIMIT: usize = 5;
    let mut missing_sym: usize = 0;
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
            // It's possible this binary can't be executed, ie. we've found a
            // sparc binary while running on an intel system, or a sparcv9
            // binary on a sparcv7/8 system.
            if line.contains("wrong class") {
                res.push_err("has wrong class or data encoding");
                continue;
            }

            // Historically, ldd(1) likes executable objects to have their
            // execute bit set.
            if line.contains("not executable") {
                res.push_err("is not executable");
                continue;
            }
        }

        // Look for "file" or "versions" that aren't found.  Note that these
        // lines will occur before we find any symbol referencing errors.
        if missing_sym == 0 && line.contains("not found)") {
            if line.contains("file not found)") {
                res.push_err(&format!("{}\t<no -zdefs?>", line));
            } else {
                res.push_err(&line);
            }
            continue;
        }

        // Look for relocations whose symbols can't be found.  Note, we only
        // print out the first 5 relocations for any file as this output can be
        // excessive.
        if missing_sym < MISSING_LIMIT && line.contains("symbol not found") {
            // Determine if this file is allowed undefined references.
            if cfg.excepted(ExcRtime::UndefRef, path) {
                missing_sym = MISSING_LIMIT;
                continue;
            }
            missing_sym += 1;
            if missing_sym == MISSING_LIMIT {
                if !cfg.oneliner_output {
                    res.push_err("continued ...");
                }
            } else {
                // Just print the symbol name.
                res.push_err(&format!("{}\t<no -zdefs>?", sanitize(line)));
            }
            continue;
        }

        // Look for any unused search paths.
        if line.contains("unused search path=") {
            // The RPATH exception check must be performed on the sanitized
            // line, since those exceptions match against the object path.
            let clean_line = sanitize(line);
            if cfg.excepted(ExcRtime::UnusedRpath, &clean_line) {
                continue;
            }
            res.push_err(&format!(
                "{}\t<remove search path?>",
                clean_line.trim_start()
            ));
            continue;
        }

        // Look for unreferenced dependencies.  Note, if any unreferenced
        // objects are ignored, then set $UnDep so as to suppress any associated
        // unused-object messages.
        if line.contains("unreferenced object=") {
            if cfg.excepted(ExcRtime::UnrefObj, &line) {
                check_undep = false;
                continue;
            }
            res.push_err(&format!(
                "{}\t<remove lib or -zignore?>",
                sanitize(line).trim_start()
            ));
            continue;
        }

        //  Look for any unused dependencies.
        if check_undep && line.contains("unused") {
            // Skip if object is allowed to have unused dependencies
            if cfg.excepted(ExcRtime::UnusedDeps, path) {
                continue;
            }

            // Skip if dependency is always allowed to be unused
            if cfg.excepted(ExcRtime::UnusedObj, &line) {
                continue;
            }

            res.push_err(&format!(
                "{}\t<remove lib or -zignore?>",
                sanitize(line).trim_start()
            ));
            continue;
        }
    }
    res
}

pub(crate) fn process_file(
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
    if cfg.excepted(ExcRtime::Skip, path) {
        return Ok(None);
    }

    let mut res = Results::default();

    // # Determine whether we have access to inspect the file.
    let fp = match File::open(&full_path) {
        Ok(fp) => fp,
        Err(_e) => {
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
            if !cfg.excepted(ExcRtime::ExecData, path) {
                res.push_err(
                    "application requires non-executable data\
                    \t<no -Mmapfile_noexdata?>",
                );
            }
        }
    }

    // Applications should contain a non-executable stack definition.
    if obj.is_exec
        && !elf
            .program_headers
            .iter()
            .any(|phdr| phdr.p_type == elf::program_header::PT_SUNWSTACK)
    {
        if !cfg.excepted(ExcRtime::ExecStack, path) {
            res.push_err(
                "non-executable stack required\t<no -Mmapfile_noexstk?>",
            );
        }
    }

    // Determine whether this ELF executable or shared object has a conforming
    // mcs(1) comment section.
    if cfg.process_mcs && !cfg.excepted(ExcRtime::NoComment, path) {
        let mut conform = false;
        if let Some(comment_data) = find_shdr(&elf, ".comment")
            .map(elf::SectionHeader::file_range)
            .flatten()
        {
            let br = BufReader::new(CommentFilter::new(&rodata[comment_data]));
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
    const MODE_SUID_GUID: u32 = 0o6000;
    let ldd_res = if (meta.mode() & MODE_SUID_GUID) == 0 {
        check_ldd(cfg, &path, &full_path)
    } else {
        // The execution of a secure application over an nfs file system mounted
        // nosuid will result in warning messages being sent to
        // /var/adm/messages.  As this type of environment can occur with root
        // builds, move the file being investigated to a safe place first.  In
        // addition, remove its secure permission so that it can be influenced by
        // any alternative dependency mappings.

        // Copy into a temp file where we control the permissions
        let mut lddtmp = NamedTempFile::new()?;
        lddtmp.write_all(rodata)?;
        lddtmp
            .as_file_mut()
            .set_permissions(PermissionsExt::from_mode(0o0555))?;
        let lddtmp_path: &str = &lddtmp.path().to_string_lossy();

        check_ldd(cfg, &path, &lddtmp_path)
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
            if !cfg.excepted(ExcRtime::TextRel, path) {
                res.push_err("TEXTREL .dynamic tag\t\t\t<no -Kpic?>");
            }
        }

        let relsz = usize::max(info.relsz, info.relasz);
        let pltsz = info.pltrelsz;

        // A shared object, that contains non-plt relocations, should have a
        // combined relocation section indicating it was built with
        // "-z combreloc".
        if !obj.is_exec && relsz != 0 && relsz != pltsz && !has_sunreloc {
            res.push_err(".SUNW_reloc section missing\t\t<no -zcombreloc?>");
        }

        // Identify an object that is not built with either "-B direct" or
        // "-z direct".
        if relsz != 0
            && !has_direct_binding
            && !cfg.excepted(ExcRtime::NoDirect, path)
        {
            res.push_err(
                "object has no direct bindings\t<no -B direct or -z direct?>",
            );
        }
    }

    // Catch any old (unnecessary) dependencies.
    for need in elf.libraries {
        if cfg.excepted(ExcRtime::OldDep, need) {
            res.push_err(&format!(
                "NEEDED={}\t<dependency no longer necessary>",
                need
            ));
        } else if cfg.excepted(ExcRtime::Forbidden, need)
            && !cfg.excepted(ExcRtime::ForbiddenDep, path)
        {
            res.push_err(&format!(
                "NEEDED={}\t<forbidden dependency, missing -nodefaultlibs?>",
                need
            ));
        } else if cfg.process_dyn_table {
            res.push_info(format!("NEEDED={}", need));
        }
    }

    // Does this object specify a runpath?
    if let Some(edyn) = &elf.dynamic {
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

    // No objects released to a customer should have any .stabs sections
    // remaining, they should be stripped.
    if cfg.process_stab && has_stabs && !cfg.excepted(ExcRtime::Forbidden, path)
    {
        res.push_err("debugging sections should be deleted\t<no strip -x?>");
    }

    // All objects should have a full symbol table to provide complete debugging
    // stack traces.
    if !has_symtab {
        res.push_err("symbol table should not be stripped\t<remove -s?>");
    }

    // If there are symbol sort sections in this object, report on any that have
    // duplicate addresses.
    if has_symsort && !cfg.excepted(ExcRtime::NoSymSort, path) {
        // ProcSymSort($FullPath, $RelPath)
    }

    // If -v was specified, and the object has a version definition section,
    // generate output showing each public symbol and the version it belongs to.
    if obj.has_verdef && cfg.process_verdef {
        // ProcVerdef($FullPath, $RelPath)
    }
    Ok(res.squash())
}
