use crate::{File, HexDump, Machine, Type};

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
                    number::complete::le_u16,
                };

                let parser = map_res($number_parser, |x| {
                    Self::try_from(x).map_err(|_| ErrorKind::Alt)
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

    pub fn parse(i: Input) -> self::Result<Self> {
        use nom::{
            bytes::complete::{tag, take},
            error::context,
            sequence::tuple,
        };

        let (i, _) = tuple((
            context("Magic", tag(Self::MAGIC)),
            context("Class", tag(&[0x2])),
            context("Endian", tag(&[0x1])),
            context("Version", tag(&[0x1])),
            context("OS ABI", nom::branch::alt((tag(&[0x0]), tag(&[0x3])))),
            context("Padding", take(8usize)),
        ))(i)?;

        let (i, (typ, machine)) = tuple((Type::parse, Machine::parse))(i)?;

        Ok((i, Self { typ, machine }))
    }
}
