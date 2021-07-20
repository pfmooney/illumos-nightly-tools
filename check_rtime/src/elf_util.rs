use goblin::elf;

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
