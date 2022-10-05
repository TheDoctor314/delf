use std::convert::TryFrom;

use crate::{Machine, Type};

#[test]
fn try_from_enums() {
    assert_eq!(Type::Dyn as u16, 0x03);
    assert_eq!(Machine::X86_64 as u16, 0x3e);

    assert_eq!(Machine::try_from(0x03), Ok(Machine::X86));
    assert_eq!(Machine::try_from(0xFA), Err(0xFA));
}
