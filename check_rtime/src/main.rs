use std::io::{Error, Result};
use std::path::PathBuf;

use structopt::StructOpt;

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

fn prep(opts: &Opts) -> Result<()> {
    if let Some(path) = opts.relative_outdir.as_ref() {
        std::env::set_current_dir(path.as_path())?;
    }

    Ok(())
}

fn find_proto_dir(opts: &Opts) -> Option<PathBuf> {
    let proto_dir = match opts.dep_dir.as_ref() {
        Some(d) => Some(d.clone()),
        // If proto dir was passed via CLI, try to find it via the env
        None => std::env::var("CODEMSG_WS").ok().map(PathBuf::from),
    };
    if let Some(dir) = proto_dir {
        if std::fs::metadata(dir.as_path()).ok()?.is_dir() {
            return Some(dir);
        }
    }
    None
}

// Recurse through a directory hierarchy looking for appropriate dependencies to map from their
// standard system locations to the proto area via a crle config file.
fn alt_object_config(opts: &Opts) -> Result<Vec<find_elf::Item>> {
    if let Some(dep_file) = opts.dep_file.as_ref() {
        let mut fe = find_elf::FindElf::from_file(dep_file)?;
        Ok(fe.collect())
    } else {
        Ok(vec![])
    }
}

fn main() {
    let opts = Opts::from_args();

    if let Err(e) = prep(&opts) {
        eprintln!("Error during setup: {:?}", e);
        std::process::exit(1);
    }
    println!("{:?}", opts);
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
