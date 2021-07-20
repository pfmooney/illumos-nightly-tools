use std::fs::File;
use std::io::Result;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};

enum Source {
    File(BufReader<File>),
    Cmd(BufReader<ChildStdout>, Child),
    Complete,
}

pub struct FindElf {
    inner: Source,
    prefix: Option<String>,
}

impl FindElf {
    pub fn prefix(&self) -> Option<String> {
        self.prefix.clone()
    }
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let fp = File::open(path)?;
        let mut reader = BufReader::new(fp);
        let prefix = read_line(&mut reader).map(|l| parse_prefix(&l)).flatten();
        Ok(Self { inner: Source::File(reader), prefix })
    }
    pub fn from_cmd(path: PathBuf, only_dyn: bool) -> Result<Self> {
        let mut cmd = Command::new("find_elf");
        cmd.arg("-fr");
        if only_dyn {
            cmd.arg("-s");
        }
        cmd.arg(path.into_os_string());
        cmd.stdout(Stdio::piped()).stdin(Stdio::null());
        let mut child = cmd.spawn()?;
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        let prefix = read_line(&mut reader).map(|l| parse_prefix(&l)).flatten();
        Ok(Self { inner: Source::Cmd(reader, child), prefix })
    }
}

#[derive(Clone, Copy)]
pub struct Object {
    pub is_64bit: bool,
    pub has_verdef: bool,
    pub is_exec: bool,
}

#[derive(Clone)]
pub enum Record {
    Object(Object),
    Alias(String),
}

#[derive(Clone)]
pub struct Item {
    pub path: String,
    pub record: Record,
}

impl Iterator for FindElf {
    type Item = Item;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let line = match &mut self.inner {
                Source::File(reader) => read_line(reader),
                Source::Cmd(reader, _child) => read_line(reader),
                Source::Complete => None,
            };

            match line {
                None => {
                    // hit EOF, so we are done
                    self.inner = Source::Complete;
                    return None;
                }
                Some(l) => {
                    let parsed = parse_item(&l);
                    if parsed.is_some() {
                        return parsed;
                    }
                    // If this line did not parse successfully, try the next one.
                }
            }
        }
    }
}

fn read_line(reader: &mut impl BufRead) -> Option<String> {
    let mut buf = String::new();
    match reader.read_line(&mut buf) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(buf),
    }
}
fn parse_prefix(buf: &str) -> Option<String> {
    let mut fields = buf.split_whitespace();
    if let Some("PREFIX") = fields.next() {
        Some(fields.next()?.to_string())
    } else {
        None
    }
}
fn parse_item(buf: &str) -> Option<Item> {
    let mut fields = buf.split_whitespace();
    match fields.next()? {
        "OBJECT" => {
            let is_64bit = fields
                .next()
                .map(|x| match x {
                    "64" => Some(true),
                    "32" => Some(false),
                    _ => None,
                })
                .flatten()?;
            let is_exec = fields
                .next()
                .map(|x| match x {
                    "EXEC" => Some(true),
                    "DYN" => Some(false),
                    _ => None,
                })
                .flatten()?;
            let has_verdef = fields
                .next()
                .map(|x| match x {
                    "VERDEF" => Some(true),
                    "NOVERDEF" => Some(false),
                    _ => None,
                })
                .flatten()?;
            let path = fields.next()?.to_string();
            Some(Item {
                path,
                record: Record::Object(Object { is_64bit, has_verdef, is_exec }),
            })
        }
        "ALIAS" => {
            let src = fields.next()?.to_string();
            let path = fields.next()?.to_string();
            Some(Item { path, record: Record::Alias(src) })
        }
        _ => None,
    }
}
