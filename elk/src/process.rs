use std::path::{Path, PathBuf};

use custom_debug_derive::Debug as CustomDebug;
use mmap::MemoryMap;

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("ELF object not found: {0}")]
    NotFound(String),
    #[error("An invalid or unsupported path was encountered")]
    InvalidPath(PathBuf),
    #[error("I/O error on {0}: {1}")]
    IO(PathBuf, std::io::Error),
    #[error("ELF object could not be parsed: {0}")]
    ParseError(PathBuf),
}

#[derive(Debug)]
pub struct Process {
    pub objects: Vec<Object>,
    pub search_path: Vec<PathBuf>,
}

impl Process {
    pub fn new() -> Self {
        Self {
            objects: Vec::new(),
            search_path: vec!["/usr/lib/".into()],
        }
    }

    pub fn load_object(&mut self, path: impl AsRef<Path>) -> Result<usize, LoadError> {
        let path = path.as_ref();
        let path = path
            .canonicalize()
            .map_err(|e| LoadError::IO(path.to_path_buf(), e))?;
        let input = std::fs::read(&path).map_err(|e| LoadError::IO(path.to_path_buf(), e))?;

        println!("Loading {:?}", path);
        let file = delf::File::parse_or_print_err(&input[..])
            .ok_or_else(|| LoadError::ParseError(path.clone()))?;

        let origin = path
            .parent()
            .ok_or_else(|| LoadError::InvalidPath(path.clone()))?
            .to_str()
            .ok_or_else(|| LoadError::InvalidPath(path.clone()))?;

        self.search_path.extend(
            file.dynamic_entry_strings(delf::DynamicTag::RPath)
                .map(|path| path.replace("$ORIGIN", origin))
                .inspect(|path| println!("Found RPATH entry {:?}", path))
                .map(PathBuf::from),
        );

        let deps: Vec<_> = file
            .dynamic_entry_strings(delf::DynamicTag::Needed)
            .collect();

        let res = Object {
            path,
            base: delf::Addr(0x40_0000),
            maps: Vec::new(),
            file,
        };

        let index = self.objects.len();
        self.objects.push(res);

        for dep in deps {
            self.load_object(self.object_path(&dep)?)?;
        }
        Ok(index)
    }

    pub fn object_path(&self, name: &str) -> Result<PathBuf, LoadError> {
        self.search_path
            .iter()
            .filter_map(|prefix| prefix.join(name).canonicalize().ok())
            .find(|path| path.exists())
            .ok_or_else(|| LoadError::NotFound(name.into()))
    }
}

#[derive(CustomDebug)]
pub struct Object {
    pub path: PathBuf,
    pub base: delf::Addr,
    #[debug(skip)]
    pub file: delf::File,
    #[debug(skip)]
    pub maps: Vec<MemoryMap>,
}
