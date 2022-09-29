use crate::{File, HexDump, Machine, Type};

pub type Input<'a> = &'a [u8];
pub type Result<'a, O> = nom::IResult<Input<'a>, O, nom::error::VerboseError<Input<'a>>>;

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
            combinator::map,
            error::context,
            number::complete,
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

        let (i, (typ, machine)) = tuple((
            context(
                "Type",
                map(complete::le_u16, |x| Type::try_from(x).unwrap()),
            ),
            context(
                "Machine",
                map(complete::le_u16, |x| Machine::try_from(x).unwrap()),
            ),
        ))(i)?;

        Ok((i, Self { typ, machine }))
    }
}
