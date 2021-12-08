use std::collections::hash_map::HashMap;
use std::io::Result;
use std::io::{BufRead, BufReader, Read};
use std::iter::Enumerate;

use lazy_static::lazy_static;
use regex::Regex;

#[derive(Debug, Eq, PartialEq, Copy, Clone, Hash)]
pub enum ExcRtime {
    ExecData,
    ExecStack,
    NoCrleAlt,
    NoDirect,
    NoSymSort,
    ForbiddenDep,
    Forbidden,
    OldDep,
    Skip,
    STab,
    TextRel,
    UndefRef,
    UnrefObj,
    UnusedDeps,
    UnusedObj,
    UnusedRpath,
    NoComment,
    NotKmod,
}
impl ExcRtime {
    fn try_from_ident(name: &str) -> Option<Self> {
        let upper = name.to_uppercase();
        match &upper as &str {
            "EXEC_DATA" => Some(ExcRtime::ExecData),
            "EXEC_STACK" => Some(ExcRtime::ExecStack),
            "NOCRLEALT" => Some(ExcRtime::NoCrleAlt),
            "NODIRECT" => Some(ExcRtime::NoDirect),
            "NOSYMSORT" => Some(ExcRtime::NoSymSort),
            "FORBIDDEN_DEP" => Some(ExcRtime::ForbiddenDep),
            "FORBIDDEN" => Some(ExcRtime::Forbidden),
            "OLDDEP" => Some(ExcRtime::OldDep),
            "SKIP" => Some(ExcRtime::Skip),
            "STAB" => Some(ExcRtime::STab),
            "TEXTREL" => Some(ExcRtime::TextRel),
            "UNDEF_REF" => Some(ExcRtime::UndefRef),
            "UNREF_OBJ" => Some(ExcRtime::UnrefObj),
            "UNUSED_DEPS" => Some(ExcRtime::UnusedDeps),
            "UNUSED_OBJ" => Some(ExcRtime::UnusedObj),
            "UNUSED_RPATH" => Some(ExcRtime::UnusedRpath),
            "NO_COMMENT" => Some(ExcRtime::NoComment),
            "NOT_KMOD" => Some(ExcRtime::NotKmod),
            _ => None,
        }
    }
}

struct GetLine<I: Iterator<Item = String>> {
    inner: Enumerate<I>,
}
impl<I: Iterator<Item = String>> GetLine<I> {
    fn new(iter: I) -> Self {
        Self { inner: iter.enumerate() }
    }
}
impl<I: Iterator<Item = String>> Iterator for GetLine<I> {
    type Item = (usize, String);

    fn next(&mut self) -> Option<Self::Item> {
        lazy_static! {
            static ref RE_CONT: Regex = Regex::new(r"\s+\\$").unwrap();
            static ref RE_COMMENT: Regex = Regex::new(r"\s+#.*$").unwrap();
        }
        let mut line = String::new();
        loop {
            let (nr, mut buf) = self.inner.next()?;
            let mut cont = false;

            // check for continuations
            if let Some(m) = RE_CONT.find(&buf) {
                let range = m.range();
                buf.replace_range(range, "");
                cont = true;
            } else if buf == "\\" {
                continue;
            }

            // Strip comments
            if buf.starts_with('#') {
                continue;
            }
            if let Some(r) = RE_COMMENT.find(&buf).map(|m| m.range()) {
                buf.replace_range(r, "")
            }

            // trim leading/trailing whitespace
            let trimmed = buf.trim();

            if !trimmed.is_empty() {
                if !line.is_empty() {
                    line.push(' ');
                }
                line.push_str(trimmed);
            }

            if !cont && !line.is_empty() {
                return Some((nr + 1, line));
            }
        }
    }
}

fn parse_exception(line: &str) -> Option<(ExcRtime, String)> {
    lazy_static! {
        static ref RE_FMT: Regex = Regex::new(r"^([^\s]+)\s+(.*)$").unwrap();
        static ref RE_MACH: Regex = Regex::new(r"MACH\(([^)]+)\)").unwrap();
    }
    if let Some(cap) = RE_FMT.captures(line) {
        let ident = ExcRtime::try_from_ident(cap.get(1).unwrap().as_str())?;
        let pattern = RE_MACH
            .replace_all(cap.get(2).unwrap().as_str(), "$1(/amd64|/sparcv9)?");
        // The shipped exception file escapes spaces as '\ ', which the rust
        // regex parse is not keen on.  Fix it here.
        let res = pattern.replace(r"\ ", " ");
        Some((ident, res))
    } else {
        None
    }
}

pub struct Checker {
    loaded: HashMap<ExcRtime, Vec<(String, Regex)>>,
}
impl Checker {
    pub fn load(read: impl Read) -> Self {
        let gl = GetLine::new(
            BufReader::new(read).lines().map(Result::ok).flatten(),
        );
        let mut map: HashMap<ExcRtime, Vec<(String, Regex)>> = HashMap::new();
        for (_nr, line) in gl {
            if let Some((kind, pattern)) = parse_exception(&line) {
                // TODO: report regex error
                let re = Regex::new(&pattern).unwrap();
                if let Some(v) = map.get_mut(&kind) {
                    v.push((pattern, re));
                } else {
                    map.insert(kind, vec![(pattern, re)]);
                }
            } else {
                todo!("emit error")
            }
        }

        Self { loaded: map }
    }
    /// Do any of the loaded exceptions of a specified type apply to the path
    pub fn check(&self, kind: ExcRtime, path: &str) -> bool {
        if let Some(list) = self.loaded.get(&kind) {
            for (_raw, re) in list.iter() {
                if re.is_match(path) {
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::BufRead;
    use std::io::BufReader;

    #[test]
    fn get_line() {
        let corpus = r#"first
second
#comment
# comment two
cont \
one

cont \
\
two

 strip whitespace 

 strip all # asdf"#;

        let buf = BufReader::new(corpus.as_bytes());
        let gl = GetLine::new(buf.lines().map(Result::ok).flatten());
        let expected = vec![
            (1, "first".to_string()),
            (2, "second".to_string()),
            (6, "cont one".to_string()),
            (10, "cont two".to_string()),
            (12, "strip whitespace".to_string()),
            (14, "strip all".to_string()),
        ];
        let actual: Vec<(usize, String)> = gl.collect();
        assert_eq!(expected, actual);
    }

    #[test]
    fn exception_parse() {
        assert_eq!(
            parse_exception("SKIP    ^usr/lib/libc/"),
            Some((ExcRtime::Skip, "^usr/lib/libc/".to_string()))
        );
        assert_eq!(
            parse_exception("SKIP ^usr/MACH(lib)/lddstub$"),
            Some((
                ExcRtime::Skip,
                "^usr/lib(/amd64|/sparcv9)?/lddstub$".to_string()
            ))
        );
    }

    #[test]
    fn full_check() {
        let input_file = r#"# A few examples from the repo
SKIP		^usr/lib/libc/			# optimized libc
EXEC_DATA	^MACH(lib)/ld\.so\.1$
UNREF_OBJ	/lib.*\ of\ .*libssl3\.so
UNUSED_RPATH	/etc/ppp/plugins.*\ from\ .*pppd
        "#;
        let c = Checker::load(input_file.as_bytes());
        assert!(c.check(ExcRtime::Skip, "usr/lib/libc/foo.so"));
        assert!(!c.check(ExcRtime::Skip, "usr/lib/baz/bar.foo"));
        assert!(c.check(ExcRtime::ExecData, "lib/ld.so.1"));
        assert!(c.check(ExcRtime::ExecData, "lib/amd64/ld.so.1"));
        assert!(c.check(ExcRtime::ExecData, "lib/sparcv9/ld.so.1"));
        assert!(!c.check(ExcRtime::ExecData, "lib/mips/ld.so.1"));
        assert!(c.check(
            ExcRtime::UnrefObj,
            "/lib/foo.so thought of /usr/lib/libssl3.so"
        ));
        assert!(c.check(
            ExcRtime::UnusedRpath,
            "unused search path=/etc/ppp/plugins  (RUNPATH/RPATH from file usr/bin/pppd)"
        ));
    }
}
