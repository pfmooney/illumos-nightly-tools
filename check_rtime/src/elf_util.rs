use goblin::elf;
use std::io::Read;

pub const SYMINFO_FLG_DIRECTBIND: u16 = 0x10;

#[repr(C)]
pub struct Syminfo {
    pub si_boundto: u16,
    pub si_flags: u16,
}

pub fn parse_syminfo<'a>(
    file_data: &'a [u8],
    shdr: &elf::SectionHeader,
) -> Option<&'a [Syminfo]> {
    let contents = &file_data[shdr.file_range()?];

    // Safety: Syminfo is made up of primitive integers and contains no padding,
    // so constructing it from the raw data is safe here.
    let (_prefix, items, _suffix) = unsafe { contents.align_to::<Syminfo>() };

    Some(items)
}

pub fn find_shdr<'a>(
    elf: &'a elf::Elf,
    name: &str,
) -> Option<&'a elf::SectionHeader> {
    elf.section_headers.iter().find(|shdr| {
        elf.shdr_strtab.get_at(shdr.sh_name).map(|n| n == name).unwrap_or(false)
    })
}

pub struct NullToNewline<R: Read> {
    inner: R,
}
impl<R: Read> NullToNewline<R> {
    pub fn new(inner: R) -> Self {
        Self { inner }
    }
}
impl<R: Read> Read for NullToNewline<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.inner.read(buf) {
            Ok(c) => {
                // Conver any NULs to newlines like mcs(1)
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
