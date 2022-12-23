use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

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

pub enum GetResult {
    Cached(usize),
    Fresh(usize),
}

impl GetResult {
    pub fn fresh(self) -> Option<usize> {
        if let Self::Fresh(i) = self {
            Some(i)
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct Process {
    pub objects: Vec<Object>,
    pub objects_by_path: HashMap<PathBuf, usize>,
    pub search_path: Vec<PathBuf>,
}

impl Process {
    pub fn new() -> Self {
        Self {
            objects: Vec::new(),
            objects_by_path: HashMap::new(),
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

        let res = Object {
            path: path.clone(),
            base: delf::Addr(0x40_0000),
            maps: Vec::new(),
            file,
        };

        let index = self.objects.len();
        self.objects.push(res);
        self.objects_by_path.insert(path, index);

        Ok(index)
    }

    pub fn load_object_and_deps(&mut self, path: impl AsRef<Path>) -> Result<usize, LoadError> {
        let index = self.load_object(path)?;
        let mut a = vec![index];

        while !a.is_empty() {
            a = a
                .into_iter()
                .map(|i| &self.objects[i].file)
                .flat_map(|file| file.dynamic_entry_strings(delf::DynamicTag::Needed))
                .collect::<Vec<_>>()
                .into_iter()
                .map(|dep| self.get_object(&dep))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .filter_map(GetResult::fresh)
                .collect();
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

    pub fn get_object(&mut self, name: &str) -> Result<GetResult, LoadError> {
        let path = self.object_path(name)?;
        self.objects_by_path
            .get(&path)
            .map(|&i| Ok(GetResult::Cached(i)))
            .unwrap_or_else(|| self.load_object(path).map(GetResult::Fresh))
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
