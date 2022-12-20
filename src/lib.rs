#![warn(missing_debug_implementations)]

use std::{fmt, ops::Range};

use derive_more::*;
use derive_try_from_primitive::TryFromPrimitive;
use enumflags2::{bitflags, BitFlags};

pub mod parser;

#[cfg(test)]
mod tests;

#[derive(Debug, thiserror::Error)]
pub enum ReadRelaError {
    #[error("Rela dynamic entry not found")]
    RelaNotFound,
    #[error("RelaSz dynamic entry not found")]
    RelaSzNotFound,
    #[error("RelaEnt dynamic entry not found")]
    RelaEntNotFound,
    #[error("RelaSeg dynamic entry not found")]
    RelaSegNotFound,
    #[error("Parsing error")]
    ParsingErr(parser::ErrorKind),
}

#[derive(Debug, thiserror::Error)]
pub enum GetStringError {
    #[error("StrTab dynamic entry not found")]
    StrTabNotFound,
    #[error("StrTab segment not found")]
    StrTabSegmentNotFound,
    #[error("String not found")]
    StringNotFound,
}

#[derive(Debug)]
pub struct File {
    pub typ: Type,
    pub machine: Machine,
    pub entry_point: Addr,
    pub program_headers: Vec<ProgramHdr>,
    pub section_headers: Vec<SectionHdr>,
}

impl File {
    /// Finds the segment whose memory range contains the given address.
    pub fn segment_at(&self, addr: Addr) -> Option<&ProgramHdr> {
        self.program_headers
            .iter()
            .filter(|ph| ph.typ == SegmentType::Load)
            .find(|ph| ph.mem_range().contains(&addr))
    }

    /// Finds the first segment of the matching `SegmentType`.
    pub fn segment_of_type(&self, typ: SegmentType) -> Option<&ProgramHdr> {
        self.program_headers.iter().find(|ph| ph.typ == typ)
    }

    /// Returns a slice containing the contents of the relevant Load segment
    /// starting at `mem_addr` until the end of that segment, or None if no
    /// suitable segment is found.
    pub fn slice_at(&self, mem_addr: Addr) -> Option<&[u8]> {
        self.segment_at(mem_addr)
            .map(|seg| &seg.data[(mem_addr - seg.mem_range().start).into()..])
    }

    /// Gets the dynamic entries in the segment.
    pub fn dynamic_table(&self) -> Option<&[DynamicEntry]> {
        if let Some(ProgramHdr {
            contents: SegmentContents::Dynamic(entries),
            ..
        }) = self.segment_of_type(SegmentType::Dynamic)
        {
            Some(entries)
        } else {
            None
        }
    }

    /// Gets the matching dynamic entries.
    pub fn dynamic_entries(&self, tag: DynamicTag) -> impl Iterator<Item = Addr> + '_ {
        self.dynamic_table()
            .unwrap_or_default()
            .iter()
            .filter(move |e| e.tag == tag)
            .map(|e| e.addr)
    }

    /// Gets the first matching dynamic entry.
    pub fn dynamic_entry(&self, tag: DynamicTag) -> Option<Addr> {
        self.dynamic_entries(tag).next()
    }

    pub fn read_rela_entries(&self) -> Result<Vec<Rela>, ReadRelaError> {
        use DynamicTag as DT;
        use ReadRelaError as E;

        let addr = self.dynamic_entry(DT::Rela).ok_or(E::RelaNotFound)?;
        let len = self.dynamic_entry(DT::RelaSz).ok_or(E::RelaSzNotFound)?;
        let ent = self.dynamic_entry(DT::RelaEnt).ok_or(E::RelaEntNotFound)?;

        let i = self.slice_at(addr).ok_or(E::RelaSegNotFound)?;
        let i = &i[..len.into()];

        let n = (len.0 / ent.0) as usize;

        use nom::multi::many_m_n;

        match many_m_n(n, n, Rela::parse)(i) {
            Ok((_, entries)) => Ok(entries),
            Err(nom::Err::Error(err) | nom::Err::Failure(err)) => {
                let (_input, error_kind) = &err.errors[0];
                Err(E::ParsingErr(error_kind.clone()))
            }
            // nom::Err::Incomplete(_) is unlikely since we don't use any streaming parsers
            _ => unreachable!(),
        }
    }

    pub fn get_string(&self, offset: Addr) -> Result<String, GetStringError> {
        use DynamicTag as DT;
        use GetStringError as E;

        let addr = self.dynamic_entry(DT::StrTab).ok_or(E::StrTabNotFound)?;
        let slice = self
            .slice_at(addr + offset)
            .ok_or(E::StrTabSegmentNotFound)?;

        // the strings are null-terminated so we split the string and take the first item.
        let string_slice = slice.split(|&c| c == 0).next().ok_or(E::StringNotFound)?;

        Ok(String::from_utf8_lossy(string_slice).into())
    }

    pub fn dynamic_entry_strings(&self, tag: DynamicTag) -> impl Iterator<Item = String> + '_ {
        // This will silently ignore the strings we are unable to retrieve.
        self.dynamic_entries(tag)
            .filter_map(|addr| self.get_string(addr).ok())
    }
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

impl_parse_for_enum!(Type, le_u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum Machine {
    X86 = 0x03,
    X86_64 = 0x3e,
}

impl_parse_for_enum!(Machine, le_u16);

pub struct ProgramHdr {
    pub typ: SegmentType,
    pub flags: BitFlags<SegmentFlag>,
    pub offset: Addr,
    pub vaddr: Addr,
    pub paddr: Addr,
    pub filesz: Addr,
    pub memsz: Addr,
    pub align: Addr,
    pub data: Vec<u8>,
    pub contents: SegmentContents,
}

impl ProgramHdr {
    /// File range where the segment is stored.
    pub fn file_range(&self) -> Range<Addr> {
        self.offset..self.offset + self.filesz
    }

    /// Memory range where the segment is mapped.
    pub fn mem_range(&self) -> Range<Addr> {
        self.vaddr..self.vaddr + self.memsz
    }
}

impl fmt::Debug for ProgramHdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "file {:?} | mem {:?} | align {:?} | {} {:?}",
            self.file_range(),
            self.mem_range(),
            self.align,
            &[
                (SegmentFlag::Read, "R"),
                (SegmentFlag::Write, "W"),
                (SegmentFlag::Execute, "X"),
            ]
            .iter()
            .map(|&(flag, ch)| {
                if self.flags.contains(flag) {
                    ch
                } else {
                    "."
                }
            })
            .collect::<Vec<_>>()
            .join(""),
            self.typ,
        )
    }
}

#[derive(Debug)]
pub struct SectionHdr {
    pub name: Addr,
    pub typ: u32,
    pub flags: u64,
    pub addr: Addr,
    pub off: Addr,
    pub size: Addr,
    pub link: u32,
    pub info: u32,
    pub addralign: Addr,
    pub entsize: Addr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u32)]
pub enum SegmentType {
    Null = 0,
    Load = 1,
    Dynamic = 2,
    Interp = 3,
    Note = 4,
    ShLib = 5,
    PHdr = 6,
    TLS = 7,
    LoOs = 0x6000_0000,
    HiOs = 0x6FFF_FFFF,
    LoProc = 0x7000_0000,
    HiProc = 0x7FFF_FFFF,
    GnuEhFrame = 0x6474_E550,
    GnuStack = 0x6474_E551,
    GnuRelRo = 0x6474_E552,
    GnuProperty = 0x6474_E553,
}

impl_parse_for_enum!(SegmentType, le_u32);

#[bitflags]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SegmentFlag {
    Execute = 1,
    Write = 2,
    Read = 4,
}

impl_parse_for_bitflags!(SegmentFlag, le_u32);

#[derive(Debug)]
pub enum SegmentContents {
    Dynamic(Vec<DynamicEntry>),
    Unknown,
}

#[derive(Debug)]
pub struct DynamicEntry {
    pub tag: DynamicTag,
    pub addr: Addr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u64)]
pub enum DynamicTag {
    Null = 0,
    Needed = 1,
    PltRelSz = 2,
    PltGot = 3,
    Hash = 4,
    StrTab = 5,
    SymTab = 6,
    Rela = 7,
    RelaSz = 8,
    RelaEnt = 9,
    StrSz = 10,
    SymEnt = 11,
    Init = 12,
    Fini = 13,
    SoName = 14,
    RPath = 15,
    Symbolic = 16,
    Rel = 17,
    RelSz = 18,
    RelEnt = 19,
    PltRel = 20,
    Debug = 21,
    TextRel = 22,
    JmpRel = 23,
    BindNow = 24,
    InitArray = 25,
    FiniArray = 26,
    InitArraySz = 27,
    FiniArraySz = 28,

    Flags = 30,

    // OS-specific tags
    LoOs = 0x6000_0000,
    GnuHash = 0x6fff_fef5,
    VerSym = 0x6fff_fff0,
    RelACount = 0x6fff_fff9,
    Flags1 = 0x6fff_fffb,
    VerDef = 0x6fff_fffc,
    VerDefNum = 0x6fff_fffd,
    VerNeed = 0x6fff_fffe,
    VerNeedNum = 0x6fff_ffff,
    LoProc = 0x7000_0000,
    HiProc = 0x7fff_ffff,
}

impl_parse_for_enum!(DynamicTag, le_u64);

#[derive(Debug)]
pub struct Rela {
    pub offset: Addr,
    pub typ: RelType,
    pub sym: u32,
    pub addend: Addr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u32)]
pub enum KnownRelType {
    _64 = 1,
    Copy = 5,
    GlobDat = 6,
    JumpSlot = 7,
    Relative = 8,
}

impl_parse_for_enum!(KnownRelType, le_u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelType {
    Known(KnownRelType),
    Unknown(u32),
}

#[derive(Debug)]
pub struct Sym {
    pub name: Addr,
    pub bind: Option<SymBind>,
    pub typ: Option<SymType>,
    pub shnidx: SectionIdx,
    pub value: Addr,
    pub size: u64,
}

#[derive(Debug, Clone, Copy, TryFromPrimitive)]
#[repr(u8)]
pub enum SymBind {
    Local = 0,
    Global = 1,
    Weak = 2,
}

#[derive(Debug, Clone, Copy, TryFromPrimitive)]
#[repr(u8)]
pub enum SymType {
    None = 0,
    Object = 1,
    Func = 2,
    Section = 3,
}

pub struct SectionIdx(pub u16);

impl SectionIdx {
    pub fn is_undef(&self) -> bool {
        self.0 == 0
    }

    pub fn is_special(&self) -> bool {
        self.0 >= 0xff00
    }

    pub fn get(&self) -> Option<usize> {
        if self.is_undef() || self.is_special() {
            None
        } else {
            Some(self.0 as usize)
        }
    }
}

impl fmt::Debug for SectionIdx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_special() {
            write!(f, "Special({:04x})", self.0)
        } else if self.is_undef() {
            write!(f, "Undef")
        } else {
            write!(f, "{}", self.0)
        }
    }
}

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
