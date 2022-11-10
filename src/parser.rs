use crate::*;

pub type Input<'a> = &'a [u8];
pub type Result<'a, O> = nom::IResult<Input<'a>, O, nom::error::VerboseError<Input<'a>>>;

#[macro_export]
macro_rules! impl_parse_for_enum {
    ($type: ident, $number_parser: ident) => {
        impl $type {
            pub fn parse(i: parser::Input) -> parser::Result<Self> {
                use nom::{
                    combinator::map_res,
                    error::{context, ErrorKind},
                    number::complete::$number_parser,
                };

                let parser = map_res($number_parser, |x| {
                    Self::try_from(x).map_err(|_| ErrorKind::Alt)
                });

                context(stringify!($type), parser)(i)
            }
        }
    };
}

#[macro_export]
macro_rules! impl_parse_for_bitflags {
    ($type: ident, $number_parser: ident) => {
        impl $type {
            pub fn parse(i: parser::Input) -> parser::Result<enumflags2::BitFlags<Self>> {
                use nom::{
                    combinator::map_res,
                    error::{context, ErrorKind},
                    number::complete::$number_parser,
                };

                let parser = map_res($number_parser, |x| {
                    enumflags2::BitFlags::<Self>::from_bits(x).map_err(|_| ErrorKind::Alt)
                });

                context(stringify!($type), parser)(i)
            }
        }
    };
}

impl File {
    const MAGIC: &'static [u8] = &[0x7f, 0x45, 0x4c, 0x46];

    pub fn parse_or_print_err(i: Input) -> Option<Self> {
        match Self::parse(i) {
            Ok((_, file)) => Some(file),
            Err(nom::Err::Error(err) | nom::Err::Failure(err)) => {
                eprintln!("Parsing failed:");
                for (input, err) in err.errors {
                    use nom::Offset;
                    let offset = i.offset(input);

                    eprintln!("{:?} at position {offset}:", err);
                    eprintln!("{:>08x}: {:?}", offset, HexDump(input));
                }

                None
            }
            Err(_) => panic!("Unexpected nom error"),
        }
    }

    #[allow(unused_variables)]
    pub fn parse(i: Input) -> self::Result<Self> {
        use nom::{
            bytes::complete::{tag, take},
            combinator::{map, verify},
            error::context,
            number::complete::{le_u16, le_u32},
            sequence::tuple,
        };

        let full_input = i;

        let (i, _) = tuple((
            context("Magic", tag(Self::MAGIC)),
            context("Class", tag(&[0x2])),
            context("Endian", tag(&[0x1])),
            context("Version", tag(&[0x1])),
            context("OS ABI", nom::branch::alt((tag(&[0x0]), tag(&[0x3])))),
            context("Padding", take(8usize)),
        ))(i)?;

        let (i, (typ, machine)) = tuple((Type::parse, Machine::parse))(i)?;
        // should always be set to 1.
        let (i, _) = context("Version", verify(le_u32, |&x| x == 1))(i)?;
        let (i, entry_point) = Addr::parse(i)?;

        // reads u16 and casts to usize
        // let u16_usize = map(le_u16, |x| x as usize);

        // ph = program header, sh = section header
        let (i, (ph_offset, sh_offset)) = tuple((Addr::parse, Addr::parse))(i)?;
        let (i, (flags, hdr_size)) = tuple((le_u32, le_u16))(i)?;

        // TODO: Figure out why we can't send the `u16_usize` instance to `tuple()`
        let (i, (ph_entsize, ph_count)) =
            tuple((map(le_u16, |x| x as usize), map(le_u16, |x| x as usize)))(i)?;
        let (i, (sh_entsize, sh_count, sh_nidx)) = tuple((
            map(le_u16, |x| x as usize),
            map(le_u16, |x| x as usize),
            map(le_u16, |x| x as usize),
        ))(i)?;

        let ph_slices = full_input[ph_offset.into()..].chunks(ph_entsize);
        let mut program_headers = Vec::new();
        for ph_slice in ph_slices.take(ph_count) {
            let (_, ph) = ProgramHdr::parse(full_input, ph_slice)?;
            program_headers.push(ph);
        }

        Ok((
            i,
            Self {
                typ,
                machine,
                entry_point,
                program_headers,
            },
        ))
    }
}

impl ProgramHdr {
    pub fn parse<'a>(full_input: Input<'a>, i: Input<'a>) -> self::Result<'a, Self> {
        use nom::sequence::tuple;

        let (i, (typ, flags)) = tuple((SegmentType::parse, SegmentFlag::parse))(i)?;

        let ap = Addr::parse;
        let (i, (offset, vaddr, paddr, filesz, memsz, align)) = tuple((ap, ap, ap, ap, ap, ap))(i)?;

        use nom::{
            combinator::{map, verify},
            multi::many_till,
        };
        let slice = &full_input[offset.into()..][..filesz.into()];
        let (_, contents) = match typ {
            SegmentType::Dynamic => map(
                many_till(
                    DynamicEntry::parse,
                    verify(DynamicEntry::parse, |e| e.tag == DynamicTag::Null),
                ),
                |(entries, _last)| SegmentContents::Dynamic(entries),
            )(slice)?,
            _ => (slice, SegmentContents::Unknown),
        };

        let res = Self {
            typ,
            flags,
            offset,
            vaddr,
            paddr,
            filesz,
            memsz,
            align,
            data: slice.to_vec(),
            contents,
        };

        Ok((i, res))
    }
}

impl DynamicEntry {
    pub fn parse(i: Input) -> self::Result<Self> {
        use nom::sequence::tuple;
        let (i, (tag, addr)) = tuple((DynamicTag::parse, Addr::parse))(i)?;
        Ok((i, Self { tag, addr }))
    }
}

impl Rela {
    pub fn parse(i: Input) -> self::Result<Self> {
        use nom::{number::complete::le_u32, sequence::tuple};

        let (i, (offset, typ, sym, addend)) =
            tuple((Addr::parse, RelType::parse, le_u32, Addr::parse))(i)?;

        Ok((
            i,
            Self {
                offset,
                typ,
                sym,
                addend,
            },
        ))
    }
}

impl RelType {
    pub fn parse(i: Input) -> self::Result<Self> {
        use nom::{branch::alt, combinator::map, number::complete::le_u32};

        alt((
            map(KnownRelType::parse, Self::Known),
            map(le_u32, Self::Unknown),
        ))(i)
    }
}
