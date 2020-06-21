use std::collections::BTreeMap;
use std::fs::{File, Metadata};
use std::io::{Error, ErrorKind, Result};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
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

    fn take(&self) -> &[u8] {
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
struct FileId(u64, u64);

impl FileId {
    fn from_meta(meta: &impl MetadataExt) -> Self {
        Self(meta.dev(), meta.ino())
    }
}

#[derive(Copy, Clone)]
struct ObjDetail {
    is_64bit: bool,
    etype: u16,
    has_verdef: bool,
}

/// Represents a directory (behind a symlink) to crawl.  If the path itself is the symlink, its
/// target (as the Option-al PathBuf) is included.
type LinkedDir = (PathBuf, Option<PathBuf>);

/// Given a directory (`path`), inspect the type of each child.  Files are handled simply by
/// running `each_file` function upon them.  Directories and symlinks (to directories) are
/// collected in respective lists to be queued for subsequent processing.  Symlinks to files are
/// processed immediately with `each_linked`.
fn dir_children<F, G>(
    path: PathBuf,
    each_file: &mut F,
    each_linked: &mut G,
) -> Result<(Vec<PathBuf>, Vec<LinkedDir>)>
where
    F: FnMut(PathBuf, &Metadata),
    G: FnMut(PathBuf, &Metadata),
{
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut link_dirs: Vec<LinkedDir> = Vec::new();

    for entry in path.read_dir()?.filter_map(|e| e.ok()) {
        let child = entry.path();
        let meta = if let Ok(m) = entry.metadata() {
            m
        } else {
            // Disregard unreadable entries
            continue;
        };
        let ft = meta.file_type();

        if ft.is_file() {
            each_file(child, &meta);
        } else if ft.is_dir() {
            dirs.push(child);
        } else if ft.is_symlink() {
            let child_meta = if let Ok(m) = child.metadata() {
                m
            } else {
                // Disegard links no nowhere
                continue;
            };
            if child_meta.file_type().is_dir() {
                let child_target = if let Ok(t) = child.read_link() {
                    t
                } else {
                    // Disregard links which change during the scan
                    continue;
                };
                link_dirs.push((child, Some(child_target)));
            } else {
                // symlinks to files can be processed immediately
                each_linked(child, &child_meta);
            };
        }
    }

    Ok((dirs, link_dirs))
}

/// Given a symlink (`ent`) perform conditional processing based the type of its target:
/// - file: run the `each_linked` function on it
/// - dir: iterate through its entries, queuing them for subsequent traversal
fn linked_children<F>(
    path: PathBuf,
    link_target: Option<PathBuf>,
    each_linked: &mut F,
) -> Result<Vec<LinkedDir>>
where
    F: FnMut(PathBuf, &Metadata),
{
    let self_linked = link_target.map_or(false, |t| t.as_path().eq(".".as_ref() as &Path));
    let mut children: Vec<(PathBuf, Option<PathBuf>)> = Vec::new();

    for dirent in path.read_dir()?.filter_map(|e| e.ok()) {
        let child: PathBuf = dirent.path();
        let ft = if let Ok(m) = dirent.metadata() {
            m.file_type()
        } else {
            // Directory entries gone missing while we scan are not a concern
            continue;
        };
        let child_meta = if let Ok(m) = child.metadata() {
            m
        } else {
            // Symlinks to invalid locations are not a concern
            continue;
        };

        if ft.is_file() || child_meta.file_type().is_file() {
            each_linked(child, &child_meta);
        } else if ft.is_dir() && !self_linked {
            children.push((child, None));
        } else if ft.is_symlink() && child_meta.file_type().is_dir() && !self_linked {
            // The original script skipped crawling directories under a self link.
            // (For example dirs under '32' -> '.')
            let child_target = if let Ok(l) = child.read_link() {
                l
            } else {
                // Directory entries gone missing while we scan are not a concern
                continue;
            };
            children.push((child, Some(child_target)));
        }
    }
    Ok(children)
}

fn walk_tree<F, G>(start: &Path, each_file: &mut F, each_linked: &mut G) -> Result<()>
where
    F: FnMut(PathBuf, &Metadata),
    G: FnMut(PathBuf, &Metadata),
{
    let mut dirq: Vec<PathBuf> = Vec::new();
    let mut linkq: Vec<LinkedDir> = Vec::new();

    dirq.push(start.to_path_buf());

    // Traverse regular (non-symlink) directories first
    while let Some(item) = dirq.pop() {
        let (mut dirs, mut links) = dir_children(item, each_file, each_linked)?;
        dirq.extend(dirs.drain(..));
        linkq.extend(links.drain(..));
    }
    // Walk anything behind a symlink (directory or otherwise) after
    while let Some((path, link_target)) = linkq.pop() {
        let mut children = linked_children(path, link_target, each_linked)?;
        linkq.extend(children.drain(..));
    }
    Ok(())
}

fn query_elf_info(path: &Path, meta: &Metadata) -> Result<ObjDetail> {
    let len = meta.len() as usize;

    // Do not bother checking if it does not even fit a 32-bit ehdr
    if len < header::header32::SIZEOF_EHDR {
        return Err(Error::new(ErrorKind::InvalidData, "file too small"));
    }

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

fn collate_results(
    file_detail: BTreeMap<FileId, (ObjDetail, Vec<PathBuf>)>,
    mut alias_list: BTreeMap<FileId, Vec<PathBuf>>,
    expand_aliases: bool,
) -> BTreeMap<PathBuf, (ObjDetail, Vec<PathBuf>)> {
    let mut result = BTreeMap::new();
    for (id, (detail, mut hard_links)) in file_detail {
        if expand_aliases {
            // Copy file detail for all hard and symbolic links as if they were all separate files,
            // rather than aliases to the same object.
            for hard_link in hard_links {
                result.insert(hard_link, (detail, Vec::new()));
            }
            if let Some(entry_aliases) = alias_list.remove(&id) {
                for symlink in entry_aliases {
                    result.insert(symlink, (detail, Vec::new()));
                }
            }
        } else {
            // Pick first hard link as primary entry
            hard_links.sort_unstable();
            let k = hard_links.remove(0);

            let mut names = hard_links;
            if let Some(mut entry_aliases) = alias_list.remove(&id) {
                names.extend(entry_aliases.drain(..));
                names.sort_unstable();
            }
            result.insert(k, (detail, names));
        }
    }
    result
}

fn format_output(
    prefix_path: &Path,
    strip_prefix: bool,
    results: BTreeMap<PathBuf, (ObjDetail, Vec<PathBuf>)>,
) {
    if strip_prefix {
        println!("PREFIX {}", prefix_path.display());
    }
    for (obj_path, (detail, aliases)) in results.iter() {
        let bitness = if detail.is_64bit { "64" } else { "32" };
        let verdef = if detail.has_verdef {
            "VERDEF"
        } else {
            "NOVERDEF"
        };
        let etype = match detail.etype {
            header::ET_DYN => "DYN",
            header::ET_EXEC => "EXEC",
            _ => continue,
        };
        let obj_path = if strip_prefix {
            obj_path.strip_prefix(prefix_path).unwrap()
        } else {
            obj_path
        };
        println!(
            "OBJECT {} {:4} {:8} {}",
            bitness,
            etype,
            verdef,
            obj_path.display(),
        );
        for alias_path in aliases.iter() {
            let alias_path = if strip_prefix {
                alias_path.strip_prefix(prefix_path).unwrap()
            } else {
                alias_path
            };
            println!(
                "{:<23} {}\t{}",
                "ALIAS",
                obj_path.display(),
                alias_path.display(),
            );
        }
    }
}

fn main() {
    let opts = Opts::from_args();

    let mut file_detail: BTreeMap<FileId, (ObjDetail, Vec<PathBuf>)> = BTreeMap::new();
    let mut alias_list: BTreeMap<FileId, Vec<PathBuf>> = BTreeMap::new();

    let mut each_file = |p: PathBuf, m: &Metadata| {
        if opts.filename_heuristic {
            let is_named_so = p
                .file_name()
                .and_then(|n| n.to_str())
                .map_or(false, |name_str| {
                    name_str.ends_with(".so") || name_str.contains(".so.")
                });
            let is_executable = (m.permissions().mode() & 0o111) != 0;

            // Skip files which do not have '.so' in the name and are not executable
            if !is_named_so && !is_executable {
                return;
            }
        }

        let id = FileId::from_meta(m);
        if let Some((_detail, hard_links)) = file_detail.get_mut(&id) {
            hard_links.push(p);
            return;
        }
        if let Ok(res) = query_elf_info(p.as_path(), m) {
            if opts.only_remote && res.etype != header::ET_DYN {
                return;
            }

            let mut hard_links = Vec::new();
            hard_links.push(p);
            file_detail.insert(id, (res, hard_links));
        }
    };
    let mut each_linked = |p: PathBuf, m: &Metadata| {
        let id = FileId::from_meta(m);
        if let Some(entry) = alias_list.get_mut(&id) {
            entry.push(p);
        } else {
            let mut list: Vec<PathBuf> = Vec::new();
            list.push(p);
            alias_list.insert(id, list);
        }
    };

    let target_meta = match opts.path.metadata() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{}: {}", opts.path.display(), e);
            return;
        }
    };
    if target_meta.file_type().is_dir() {
        // perform the directory walk
        walk_tree(opts.path.as_path(), &mut each_file, &mut each_linked).unwrap();

        let results = collate_results(file_detail, alias_list, opts.expand_alias);
        format_output(opts.path.as_path(), opts.relative, results);
    } else {
        // scan just the one file
        each_file(opts.path.clone(), &target_meta);

        let results = collate_results(file_detail, alias_list, opts.expand_alias);
        format_output(opts.path.parent().unwrap(), opts.relative, results);
    };
}
