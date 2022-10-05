use std::fmt;

use derive_more::*;
use derive_try_from_primitive::TryFromPrimitive;

pub mod parser;

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub struct File {
    typ: Type,
    machine: Machine,
    entry_point: Addr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum Type {
    None = 0,
    Rel = 1,
    Exec = 2,
    Dyn = 3,
    Core = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum Machine {
    X86 = 0x03,
    X86_64 = 0x3e,
}

impl_parse_for_enum!(Type, le_u16);
impl_parse_for_enum!(Machine, le_u16);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Add, Sub)]
pub struct Addr(pub u64);

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:08x}", self.0)
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl From<u64> for Addr {
    fn from(x: u64) -> Self {
        Self(x)
    }
}

impl From<Addr> for u64 {
    fn from(x: Addr) -> Self {
        x.0
    }
}

impl From<Addr> for usize {
    fn from(x: Addr) -> Self {
        x.0 as usize
    }
}

impl Addr {
    pub fn parse(i: parser::Input) -> parser::Result<Self> {
        use nom::{combinator::map, number::complete::le_u64};

        map(le_u64, From::from)(i)
    }
}

pub struct HexDump<'a>(&'a [u8]);

impl<'a> fmt::Debug for HexDump<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for &x in self.0.iter().take(20) {
            write!(f, "{x:02x} ")?;
        }

        Ok(())
    }
}
