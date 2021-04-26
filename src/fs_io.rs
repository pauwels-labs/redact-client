use std::{boxed::Box, fs, io, iter::Iterator, path};

/**
 * These traits and structs interface out our interactions with the fs package.
 * By using these abstractions, we can tightly control our access to the filesystem,
 * handle any future changes in the fs API, optionally extend the API, and fully
 * mock out fs access for testing purposes.
 *
 * In general, it's best to match the existing fs api without extension. This way
 * we can use fs docs knowing that *Container traits are pass through functions to the
 * underlying fs crate.
 *
 * If a pass through function does not exist for the method you need, simply add it to
 * the trait and add a pass-through implementation.
 */
pub trait MetadataContainer {
    fn is_file(&self) -> bool;
    fn is_dir(&self) -> bool;
}

pub struct Metadata(fs::Metadata);

impl MetadataContainer for Metadata {
    fn is_file(&self) -> bool {
        self.0.is_file()
    }

    fn is_dir(&self) -> bool {
        self.0.is_dir()
    }
}

pub trait DirEntryContainer {
    fn path(&self) -> path::PathBuf;
}

pub struct DirEntry(fs::DirEntry);

impl DirEntryContainer for DirEntry {
    fn path(&self) -> path::PathBuf {
        self.0.path()
    }
}

pub trait ReadDirContainer: Iterator<Item = io::Result<Box<dyn DirEntryContainer>>> {}

pub struct ReadDir(fs::ReadDir);

impl Iterator for ReadDir {
    type Item = io::Result<Box<dyn DirEntryContainer>>;

    fn next(&mut self) -> Option<io::Result<Box<dyn DirEntryContainer>>> {
        match self.0.next() {
            Some(de) => match de {
                Ok(de) => Some(io::Result::Ok(Box::new(DirEntry(de)))),
                Err(e) => Some(io::Result::Err(e)),
            },
            None => None,
        }
    }
}

impl ReadDirContainer for ReadDir {}

pub trait FsReadWriter {
    fn read_dir(&self, path: &str) -> io::Result<Box<dyn ReadDirContainer>>;
    fn metadata(&self, path: &path::Path) -> io::Result<Box<dyn MetadataContainer>>;
}

pub struct Fs {}

impl FsReadWriter for Fs {
    fn read_dir(&self, path: &str) -> io::Result<Box<dyn ReadDirContainer>> {
        match fs::read_dir(path) {
            Ok(rd) => io::Result::Ok(Box::new(ReadDir(rd))),
            Err(e) => io::Result::Err(e),
        }
    }

    fn metadata(&self, path: &path::Path) -> io::Result<Box<dyn MetadataContainer>> {
        match fs::metadata(path) {
            Ok(metadata) => io::Result::Ok(Box::new(Metadata(metadata))),
            Err(e) => io::Result::Err(e),
        }
    }
}

pub struct FilterResult {
    pub paths: Vec<String>,
    pub io_errors: Vec<io::Error>,
}

pub struct FsFilterer<FS: FsReadWriter> {
    fs_rw: FS,
}

impl FsFilterer<Fs> {
    pub fn new() -> FsFilterer<Fs> {
        FsFilterer { fs_rw: Fs {} }
    }
}

impl<FS: FsReadWriter> FsFilterer<FS> {
    pub fn new_custom(fs_rw: FS) -> FsFilterer<FS> {
        FsFilterer { fs_rw }
    }

    pub fn dir(
        &self,
        path: &str,
        file_dir_filter: u8,
        hidden_filter: u8,
        extension_filter: Option<&str>,
    ) -> Result<FilterResult, io::Error> {
        let mut io_errors: Vec<io::Error> = Vec::new();
        let paths: Vec<String> = self
            .fs_rw
            .read_dir(path)?
            .filter_map(|entry| match entry {
                Ok(entry) => Some(entry),
                Err(e) => {
                    io_errors.push(e);
                    None
                }
            })
            .filter_map(|entry| {
                let path = entry.path();
                match (self.fs_rw.metadata(&path), path.file_stem()) {
                    (Ok(metadata), Some(file_stem)) => {
                        let extension = path.extension();
                        let is_file = metadata.is_file() as u8;
                        let is_dir = (metadata.is_dir() as u8) << 1;
                        let extension_check = match extension_filter {
                            Some(extension_filter) => {
                                if let Some(extension) = extension {
                                    extension_filter == extension
                                } else {
                                    false
                                }
                            }
                            None => true,
                        };
                        let hidden_check = if file_stem.to_str().unwrap().starts_with('.') {
                            2
                        } else {
                            1
                        };

                        if ((is_file | is_dir) & file_dir_filter) != 0
                            && !file_stem.is_empty()
                            && extension_check
                            && (hidden_check & hidden_filter) != 0
                        {
                            if let Some(path_str) = path.to_str() {
                                Some(path_str.to_owned())
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            })
            .collect();
        Ok(FilterResult { paths, io_errors })
    }
}

#[cfg(test)]
pub mod tests {
    use super::{DirEntryContainer, FsFilterer, FsReadWriter, MetadataContainer, ReadDirContainer};
    use mockall::predicate::*;
    use mockall::*;
    use std::io;

    mock! {
    pub Fs {}
    impl FsReadWriter for Fs {
        fn read_dir(&self, path: &str) -> io::Result<Box<dyn ReadDirContainer>>;
        fn metadata(&self, path: &std::path::Path) -> io::Result<Box<dyn MetadataContainer>>;
    }
    }

    mock! {
    pub ReadDir {}
    impl Iterator for ReadDir {
        type Item = io::Result<Box<dyn DirEntryContainer>>;
        fn next(&mut self) -> Option<io::Result<Box<dyn DirEntryContainer>>>;
    }
    impl ReadDirContainer for ReadDir {}
    }

    mock! {
    pub DirEntry {}
    impl DirEntryContainer for DirEntry {
        fn path(&self) -> std::path::PathBuf;
    }
    }

    mock! {
    pub Metadata {}
    impl MetadataContainer for Metadata {
    fn is_file(&self) -> bool;
    fn is_dir(&self) -> bool;
    }
    }

    #[test]
    fn test_filter_dir_empty_dir_returns_no_paths() {
        let mut read_dir = MockReadDir::new();
        read_dir.expect_next().times(1).returning(|| None);
        let mut fs_rw = MockFs::new();
        fs_rw
            .expect_read_dir()
            .with(predicate::eq("test/path"))
            .times(1)
            .return_once(move |_| io::Result::Ok(Box::new(read_dir)));

        let filter = FsFilterer::new_custom(fs_rw);
        let filter_result = filter.dir("test/path", 1, 1, None).unwrap();
        assert!(filter_result.paths.is_empty());
    }

    #[test]
    fn test_filter_dir_directories_are_returned() {
        let mut mock_seq = Sequence::new();
        let mut metadata = MockMetadata::new();
        metadata.expect_is_file().times(1).returning(|| false);
        metadata.expect_is_dir().times(1).returning(|| true);
        let mut dir_entry = MockDirEntry::new();
        dir_entry
            .expect_path()
            .times(1)
            .returning(|| std::path::PathBuf::from("test/path/dir1"));
        let mut read_dir = MockReadDir::new();
        read_dir
            .expect_next()
            .times(1)
            .in_sequence(&mut mock_seq)
            .return_once(|| Some(io::Result::Ok(Box::new(dir_entry))));
        read_dir
            .expect_next()
            .times(1)
            .in_sequence(&mut mock_seq)
            .returning(|| None);
        let mut fs_rw = MockFs::new();
        fs_rw
            .expect_metadata()
            .with(predicate::eq(std::path::Path::new("test/path/dir1")))
            .times(1)
            .return_once(move |_| io::Result::Ok(Box::new(metadata)));
        fs_rw
            .expect_read_dir()
            .with(predicate::eq("test/path"))
            .times(1)
            .return_once(move |_| io::Result::Ok(Box::new(read_dir)));

        let filter = FsFilterer::new_custom(fs_rw);
        let filter_result = filter.dir("test/path", 2, 1, None).unwrap();
        assert!(filter_result.paths.len() == 1);
    }
}
