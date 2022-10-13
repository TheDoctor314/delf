use std::convert::TryFrom;

#[test]
fn try_from_enums() {
    use crate::{Machine, Type};
    assert_eq!(Type::Dyn as u16, 0x03);
    assert_eq!(Machine::X86_64 as u16, 0x3e);

    assert_eq!(Machine::try_from(0x03), Ok(Machine::X86));
    assert_eq!(Machine::try_from(0xFA), Err(0xFA));
}

#[test]
fn try_bitflags() {
    use crate::SegmentFlag;
    use enumflags2::BitFlags;

    // could have read this from an ELF file
    let flags_int: u32 = 6;
    let flags = BitFlags::<SegmentFlag>::from_bits(flags_int).unwrap();

    assert_eq!(flags, SegmentFlag::Read | SegmentFlag::Write);
    assert_eq!(flags.bits(), flags_int);

    assert!(BitFlags::<SegmentFlag>::from_bits(1992).is_err());
}
