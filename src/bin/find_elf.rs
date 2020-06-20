use std::collections::BTreeMap;
use std::fs::{File, Metadata};
use std::io::{Error, ErrorKind, Result};
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use goblin::elf::dynamic::DT_VERDEF;
use goblin::elf::header;
use goblin::elf::Elf;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "options")]
struct Opts {
    /// expand symlink aliases
    #[structopt(short = "a")]
    expand_alias: bool,

    /// use filename at node to speed search
    #[structopt(short = "f")]
    filename_heuristic: bool,

    /// report relative paths
    #[structopt(short = "r")]
    relative: bool,

    /// only remote sharable (ET_DYN) objects
    #[structopt(short = "s")]
    only_remote: bool,

    #[structopt(parse(from_os_str), name = "PATH", required = true)]
    path: PathBuf,
}

struct MMap {
    ptr: std::ptr::NonNull<u8>,
    size: usize,
}

impl MMap {
    fn new(path: impl AsRef<Path>, len: usize) -> Result<Self> {
        let fp = File::open(path)?;
        let fd = fp.as_raw_fd();
        unsafe {
            let prot = libc::PROT_READ;
            let flags = libc::MAP_SHARED;
            let res = libc::mmap(std::ptr::null_mut(), len, prot, flags, fd, 0);
            if let Some(ptr) = std::ptr::NonNull::new(res as *mut u8) {
                Ok(Self { ptr, size: len })
            } else {
                Err(Error::last_os_error())
            }
        }
    }

    fn take<'a>(&'a self) -> &'a [u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ref(), self.size) }
    }
}

impl Drop for MMap {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr.as_ptr() as *mut core::ffi::c_void, self.size);
        }
    }
}

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone)]
struct FileId {
    dev: u64,
    ino: u64,
}

impl FileId {
    fn from_meta(meta: &impl MetadataExt) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
        }
    }
}

struct ObjDetail {
    is_64bit: bool,
    etype: u16,
    has_verdef: bool,
}

struct AliasCheck(PathBuf, Metadata, Option<PathBuf>);

fn process_dir<F>(path: PathBuf, each_file: &mut F) -> Result<(Vec<PathBuf>, Vec<AliasCheck>)>
where
    F: FnMut(PathBuf, &Metadata),
{
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut links: Vec<AliasCheck> = Vec::new();
    for ent in path.read_dir()? {
        if let Ok(entry) = ent {
            let child = entry.path();
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(e) => {
                    patherror(e, child);
                    continue;
                }
            };
            let ft = meta.file_type();

            if ft.is_dir() {
                dirs.push(child);
            } else if ft.is_symlink() {
                let child_meta = match child.metadata() {
                    Ok(m) => m,
                    Err(e) => {
                        patherror(e, child);
                        continue;
                    }
                };
                if child_meta.file_type().is_dir() {
                    let child_target = match child.read_link() {
                        Ok(t) => t,
                        Err(e) => {
                            patherror(e, child);
                            continue;
                        }
                    };
                    links.push(AliasCheck(child, child_meta, Some(child_target)));
                } else {
                    links.push(AliasCheck(child, child_meta, None));
                };
            } else if ft.is_file() {
                each_file(child, &meta);
            }
        }
    }

    Ok((dirs, links))
}

fn is_self_path(path: &Path) -> bool {
    let compare: &Path = ".".as_ref();
    path == compare
}

fn patherror(err: Error, p: impl AsRef<Path>) {
    let path: &Path = p.as_ref();
    eprintln!("{}: {}", path.to_string_lossy(), err)
}

fn process_link<F>(ent: AliasCheck, each_alias: &mut F) -> Result<Option<Vec<AliasCheck>>>
where
    F: FnMut(PathBuf, &Metadata),
{
    let AliasCheck(path, meta, link_target) = ent;
    let ft = meta.file_type();

    if ft.is_file() {
        each_alias(path, &meta);
        Ok(None)
    } else if ft.is_dir() {
        let self_linked = match link_target {
            Some(target) => is_self_path(&target),
            None => false,
        };
        let mut follow: Vec<AliasCheck> = Vec::new();

        for ent in path.read_dir()? {
            if let Ok(entry) = ent {
                let child: PathBuf = entry.path();
                let ft = match entry.metadata() {
                    Ok(m) => m.file_type(),
                    Err(e) => {
                        patherror(e, child);
                        continue;
                    }
                };
                let child_meta = match child.metadata() {
                    Ok(m) => m,
                    Err(e) => {
                        patherror(e, child);
                        continue;
                    }
                };

                if ft.is_file() {
                    follow.push(AliasCheck(child, child_meta, None));
                } else if ft.is_dir() && !self_linked {
                    // The original script skipped crawling directories under a self link.
                    // (For example dirs under '32' -> '.')
                    follow.push(AliasCheck(child, child_meta, None));
                } else if ft.is_symlink() {
                    let child_target = match child.read_link() {
                        Ok(m) => m,
                        Err(e) => {
                            patherror(e, child);
                            continue;
                        }
                    };
                    // Do not recurse infinitely through self links
                    if child_meta.file_type().is_file() || !self_linked {
                        follow.push(AliasCheck(child, child_meta, Some(child_target)));
                    }
                }
            }
        }
        Ok(Some(follow))
    } else {
        // Would not expect to find a symlink as path.metadata() should follow it.
        Ok(None)
    }
}

fn find_operation<F, G>(start: PathBuf, each_file: &mut F, each_alias: &mut G) -> Result<()>
where
    F: FnMut(PathBuf, &Metadata),
    G: FnMut(PathBuf, &Metadata),
{
    let mut dirq: Vec<PathBuf> = Vec::new();
    let mut linkq: Vec<AliasCheck> = Vec::new();

    dirq.push(start);

    // Traverse regular (non-symlink) directories first
    while let Some(item) = dirq.pop() {
        let (mut dirs, mut links) = process_dir(item, each_file)?;
        dirq.extend(dirs.drain(..));
        linkq.extend(links.drain(..));
    }
    // Walk anything behind a symlink (directory or otherwise) after
    while let Some(item) = linkq.pop() {
        let children = process_link(item, each_alias)?;
        if let Some(mut entries) = children {
            linkq.extend(entries.drain(..));
        }
    }
    Ok(())
}

fn process_entry(path: &Path, meta: &Metadata) -> Result<ObjDetail> {
    let mapped = MMap::new(path, meta.len() as usize)?;
    match Elf::parse(mapped.take()) {
        Ok(obj) => {
            let has_verdef = if let Some(dynamic) = obj.dynamic {
                dynamic.dyns.iter().any(|d| d.d_tag == DT_VERDEF)
            } else {
                false
            };
            Ok(ObjDetail {
                is_64bit: obj.is_64,
                etype: obj.header.e_type,
                has_verdef,
            })
        }
        Err(e) => match e {
            goblin::error::Error::IO(io) => Err(io),
            _ => Err(Error::new(ErrorKind::InvalidData, "could not parse ELF")),
        },
    }
}

fn main() {
    let opts = Opts::from_args();
    let path = opts.path.clone();

    let mut file_detail: BTreeMap<FileId, (Vec<PathBuf>, ObjDetail)> = BTreeMap::new();
    let mut aliases: BTreeMap<FileId, Vec<PathBuf>> = BTreeMap::new();

    let mut each_file = |p: PathBuf, m: &Metadata| {
        let id = FileId::from_meta(m);
        if let Some((names, _detail)) = file_detail.get_mut(&id) {
            names.push(p);
            return;
        }
        if let Ok(res) = process_entry(p.as_path(), m) {
            let mut names = Vec::new();
            names.push(p);
            file_detail.insert(id, (names, res));
        }
    };
    let mut each_alias = |p: PathBuf, m: &Metadata| {
        let id = FileId::from_meta(m);
        if let Some(entry) = aliases.get_mut(&id) {
            entry.push(p);
        } else {
            let mut list: Vec<PathBuf> = Vec::new();
            list.push(p);
            aliases.insert(id, list);
        }
    };

    find_operation(path, &mut each_file, &mut each_alias).unwrap();

    let mut res: BTreeMap<PathBuf, (ObjDetail, Vec<PathBuf>)> = BTreeMap::new();
    for (id, (mut names, detail)) in file_detail {
        // Pick first hard link as primary entry
        names.sort_unstable();
        let k = names.remove(0);

        if let Some(mut entry_aliases) = aliases.remove(&id) {
            names.extend(entry_aliases.drain(..));
            names.sort_unstable();
        }
        res.insert(k, (detail, names));
    }
    for (k, (detail, alias_list)) in res.iter() {
        let bitness = match detail.is_64bit {
            true => "64",
            false => "32",
        };
        let verdef = match detail.has_verdef {
            true => "VERDEF",
            false => "NOVERDEF",
        };
        let etype = match detail.etype {
            header::ET_DYN => "DYN",
            header::ET_EXEC => "EXEC",
            _ => continue,
        };
        println!(
            "OBJECT {} {:4} {:8} {}",
            bitness,
            etype,
            verdef,
            k.to_string_lossy()
        );
        for p in alias_list.iter() {
            println!(
                "{:<23} {}\t{}",
                "ALIAS",
                k.to_string_lossy(),
                p.to_string_lossy(),
            );
        }
    }
}
