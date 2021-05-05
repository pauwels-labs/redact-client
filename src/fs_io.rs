use std::{boxed::Box, fs, io, iter::Iterator, path};

use path::{Path, PathBuf};

/// These traits and structs interface out our interactions with the fs package.
/// By using these abstractions, we can tightly control our access to the filesystem,
/// handle any future changes in the fs API, optionally extend the API, and fully
/// mock out fs access for testing purposes.
///
/// In general, it's best to match the existing fs api without extension. This way
/// we can use fs docs knowing thatContainer traits are pass through functions to the
/// underlying fs crate.
///
/// If a pass through function does not exist for the method you need, simply add it to
/// the trait and add a pass-through implementation.

/// Pass-through trait to std::fs::Metadata
pub trait MetadataContainer {
    fn is_file(&self) -> bool;
    fn is_dir(&self) -> bool;
}

/// Owns an std::fs::Metadata struct
pub struct Metadata(fs::Metadata);

impl MetadataContainer for Metadata {
    fn is_file(&self) -> bool {
        self.0.is_file()
    }

    fn is_dir(&self) -> bool {
        self.0.is_dir()
    }
}

/// Pass-through trait to std::fs::DirEntry
pub trait DirEntryContainer {
    fn path(&self) -> PathBuf;
}

/// Owns an std::fs::DirEntry
pub struct DirEntry(fs::DirEntry);

impl DirEntryContainer for DirEntry {
    fn path(&self) -> PathBuf {
        self.0.path()
    }
}

/// Pass-through trait to std::fs::ReadDir
pub trait ReadDirContainer: Iterator<Item = io::Result<Box<dyn DirEntryContainer>>> {}

/// Owns an std::fs::ReadDir
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

/// Primary interface into the std::fs methods
pub trait FsReadWriter {
    fn read_dir(&self, path: &str) -> io::Result<Box<dyn ReadDirContainer>>;
    fn metadata(&self, path: &Path) -> io::Result<Box<dyn MetadataContainer>>;
}

/// Provides access to the filesystem. This struct should be extended when necessary
/// to access more underlying std::fs methods. std::fs should NOT be used directly.
pub struct Fs {}

impl FsReadWriter for Fs {
    fn read_dir(&self, path: &str) -> io::Result<Box<dyn ReadDirContainer>> {
        match fs::read_dir(path) {
            Ok(rd) => io::Result::Ok(Box::new(ReadDir(rd))),
            Err(e) => io::Result::Err(e),
        }
    }

    fn metadata(&self, path: &Path) -> io::Result<Box<dyn MetadataContainer>> {
        match fs::metadata(path) {
            Ok(metadata) => io::Result::Ok(Box::new(Metadata(metadata))),
            Err(e) => io::Result::Err(e),
        }
    }
}

/// Contains a list of paths that passed through the filter. Also
/// contains a list of IO errors that were encountered when attempting
/// to read entries in the directory.
pub struct FilterResult {
    pub paths: Vec<PathBuf>,
    pub io_errors: Vec<io::Error>,
}

/// Filters entries in a directory
pub struct FsFilterer<FS: FsReadWriter> {
    fs_rw: FS,
}

impl FsFilterer<Fs> {
    /// This is the default constructor. It instantiates FsFilterer with an instance
    /// of the Fs struct which will access the underlying filesystem.
    pub fn new() -> FsFilterer<Fs> {
        FsFilterer { fs_rw: Fs {} }
    }
}

impl<FS: FsReadWriter> FsFilterer<FS> {
    /// Use this constructor when providing a custom implementation of the FsReadWriter
    /// struct. This allows plugging in mocks or new libs if using std::fs is undesirable.
    pub fn new_custom(fs_rw: FS) -> FsFilterer<FS> {
        FsFilterer { fs_rw }
    }

    /// Filters the entries in a directory based on whether the entry:
    /// - Is a file or directory
    /// - Is hidden or not hidden (name preceded with a '.')
    /// - Has an extension of a particular type
    ///
    /// Parameters are provided as binary arguments. Therefore:
    /// - 0b01 keeps files, 0b10 keeps directories, 0b11 keeps both
    /// - 0b01 keeps non-hidden files, 0b10 keeps hidden files, 0b11 keeps both
    /// - Some("ext") keeps entries with filename extension ".ext", None keeps entries
    ///   with no extension at all
    pub fn dir(
        &self,
        path: &str,
        file_dir_filter: u8,
        hidden_filter: u8,
        extension_filter: Option<&str>,
    ) -> Result<FilterResult, io::Error> {
        let mut io_errors: Vec<io::Error> = Vec::new();
        let paths: Vec<PathBuf> = self
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
                            Some(path)
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
        // Mock fs to return a ReadDir iterator that has no items
        let mut read_dir = MockReadDir::new();
        read_dir.expect_next().times(1).returning(|| None);
        let mut fs_rw = MockFs::new();
        fs_rw
            .expect_read_dir()
            .with(predicate::eq("test/path"))
            .times(1)
            .return_once(move |_| io::Result::Ok(Box::new(read_dir)));

        // Execute filter with the mocked fs
        let filter = FsFilterer::new_custom(fs_rw);
        let filter_result = filter.dir("test/path", 1, 1, None).unwrap();
        assert!(filter_result.paths.is_empty());
    }

    #[test]
    fn test_filter_dir_only_non_hidden_directories() {
        // Mock metadata identifies the entry as a directory/file
        let mut dir_metadata = MockMetadata::new();
        dir_metadata.expect_is_file().times(1).returning(|| false);
        dir_metadata.expect_is_dir().times(1).returning(|| true);
        let mut file_metadata = MockMetadata::new();
        file_metadata.expect_is_file().times(1).returning(|| true);
        file_metadata.expect_is_dir().times(1).returning(|| false);

        // Mock directory entry points to an entry a test/path/dir1
        let mut dir_entry = MockDirEntry::new();
        dir_entry
            .expect_path()
            .times(1)
            .returning(|| std::path::PathBuf::from("test/path/dir1"));

        // Mock directory entry points to an entry a test/path/file1
        let mut file_entry = MockDirEntry::new();
        file_entry
            .expect_path()
            .times(1)
            .returning(|| std::path::PathBuf::from("test/path/file1"));

        // Mock read dir results is an iterator that returns a mocked directory
        // entry at test/path/dir1, one at test/path/file1, and then None
        let mut mock_seq = Sequence::new();
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
            .return_once(|| Some(io::Result::Ok(Box::new(file_entry))));
        read_dir
            .expect_next()
            .times(1)
            .in_sequence(&mut mock_seq)
            .returning(|| None);

        // Mock fs expects a metadata call for test/path/dir1 and returns a mock metadata
        // struct identifying the entry as a directory
        // It also expects a read_dir call for test/path and returns the mocked readdir iterator
        let mut fs_rw = MockFs::new();
        fs_rw
            .expect_metadata()
            .with(predicate::eq(std::path::Path::new("test/path/dir1")))
            .times(1)
            .return_once(move |_| io::Result::Ok(Box::new(dir_metadata)));
        fs_rw
            .expect_metadata()
            .with(predicate::eq(std::path::Path::new("test/path/file1")))
            .times(1)
            .return_once(move |_| io::Result::Ok(Box::new(file_metadata)));
        fs_rw
            .expect_read_dir()
            .with(predicate::eq("test/path"))
            .times(1)
            .return_once(move |_| io::Result::Ok(Box::new(read_dir)));

        // Execute the filter with the mocked fs sequence
        let filter = FsFilterer::new_custom(fs_rw);
        let filter_result = filter.dir("test/path", 2, 1, None).unwrap();
        assert!(
            filter_result.paths.len() == 1
                && filter_result.paths.first().unwrap()
                    == &std::path::PathBuf::from("test/path/dir1")
        );
    }

    #[test]
    fn test_filter_dir_only_non_hidden_files() {
        // Mock metadata identifies the entry as a directory/file
        let mut dir_metadata = MockMetadata::new();
        dir_metadata.expect_is_file().times(1).returning(|| false);
        dir_metadata.expect_is_dir().times(1).returning(|| true);
        let mut file_metadata = MockMetadata::new();
        file_metadata.expect_is_file().times(1).returning(|| true);
        file_metadata.expect_is_dir().times(1).returning(|| false);

        // Mock directory entry points to an entry a test/path/dir1
        let mut dir_entry = MockDirEntry::new();
        dir_entry
            .expect_path()
            .times(1)
            .returning(|| std::path::PathBuf::from("test/path/dir1"));

        // Mock directory entry points to an entry a test/path/file1
        let mut file_entry = MockDirEntry::new();
        file_entry
            .expect_path()
            .times(1)
            .returning(|| std::path::PathBuf::from("test/path/file1"));

        // Mock read dir results is an iterator that returns a mocked directory
        // entry at test/path/dir1, one at test/path/file1, and then None
        let mut mock_seq = Sequence::new();
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
            .return_once(|| Some(io::Result::Ok(Box::new(file_entry))));
        read_dir
            .expect_next()
            .times(1)
            .in_sequence(&mut mock_seq)
            .returning(|| None);

        // Mock fs expects a metadata call for test/path/dir1 and returns a mock metadata
        // struct identifying the entry as a directory
        // It also expects a read_dir call for test/path and returns the mocked readdir iterator
        let mut fs_rw = MockFs::new();
        fs_rw
            .expect_metadata()
            .with(predicate::eq(std::path::Path::new("test/path/dir1")))
            .times(1)
            .return_once(move |_| io::Result::Ok(Box::new(dir_metadata)));
        fs_rw
            .expect_metadata()
            .with(predicate::eq(std::path::Path::new("test/path/file1")))
            .times(1)
            .return_once(move |_| io::Result::Ok(Box::new(file_metadata)));
        fs_rw
            .expect_read_dir()
            .with(predicate::eq("test/path"))
            .times(1)
            .return_once(move |_| io::Result::Ok(Box::new(read_dir)));

        // Execute the filter with the mocked fs sequence
        let filter = FsFilterer::new_custom(fs_rw);
        let filter_result = filter.dir("test/path", 1, 1, None).unwrap();
        assert!(
            filter_result.paths.len() == 1
                && filter_result.paths.first().unwrap()
                    == &std::path::PathBuf::from("test/path/file1")
        );
    }

    #[test]
    fn test_filter_dir_only_hidden_directories() {
        // Mock metadata identifies the entry as a directory/file
        let mut dir1_metadata = MockMetadata::new();
        dir1_metadata.expect_is_file().times(1).returning(|| false);
        dir1_metadata.expect_is_dir().times(1).returning(|| true);
        let mut dir2_metadata = MockMetadata::new();
        dir2_metadata.expect_is_file().times(1).returning(|| false);
        dir2_metadata.expect_is_dir().times(1).returning(|| true);

        // Mock directory entry points to an entry a test/path/dir1
        let mut dir1_entry = MockDirEntry::new();
        dir1_entry
            .expect_path()
            .times(1)
            .returning(|| std::path::PathBuf::from("test/path/.dir1"));

        // Mock directory entry points to an entry a test/path/dir2
        let mut dir2_entry = MockDirEntry::new();
        dir2_entry
            .expect_path()
            .times(1)
            .returning(|| std::path::PathBuf::from("test/path/dir2"));

        // Mock read dir results is an iterator that returns a mocked directory
        // entry at test/path/dir1, one at test/path/file1, and then None
        let mut mock_seq = Sequence::new();
        let mut read_dir = MockReadDir::new();
        read_dir
            .expect_next()
            .times(1)
            .in_sequence(&mut mock_seq)
            .return_once(|| Some(io::Result::Ok(Box::new(dir1_entry))));
        read_dir
            .expect_next()
            .times(1)
            .in_sequence(&mut mock_seq)
            .return_once(|| Some(io::Result::Ok(Box::new(dir2_entry))));
        read_dir
            .expect_next()
            .times(1)
            .in_sequence(&mut mock_seq)
            .returning(|| None);

        // Mock fs expects a metadata call for test/path/dir1 and returns a mock metadata
        // struct identifying the entry as a directory
        // It also expects a read_dir call for test/path and returns the mocked readdir iterator
        let mut fs_rw = MockFs::new();
        fs_rw
            .expect_metadata()
            .with(predicate::eq(std::path::Path::new("test/path/.dir1")))
            .times(1)
            .return_once(move |_| io::Result::Ok(Box::new(dir1_metadata)));
        fs_rw
            .expect_metadata()
            .with(predicate::eq(std::path::Path::new("test/path/dir2")))
            .times(1)
            .return_once(move |_| io::Result::Ok(Box::new(dir2_metadata)));
        fs_rw
            .expect_read_dir()
            .with(predicate::eq("test/path"))
            .times(1)
            .return_once(move |_| io::Result::Ok(Box::new(read_dir)));

        // Execute the filter with the mocked fs sequence
        let filter = FsFilterer::new_custom(fs_rw);
        let filter_result = filter.dir("test/path", 2, 2, None).unwrap();
        assert!(
            filter_result.paths.len() == 1
                && filter_result.paths.first().unwrap()
                    == &std::path::PathBuf::from("test/path/.dir1")
        );
    }

    #[test]
    fn test_filter_dir_only_hidden_files() {
        // Mock metadata identifies the entry as a directory/file
        let mut file1_metadata = MockMetadata::new();
        file1_metadata.expect_is_file().times(1).returning(|| true);
        file1_metadata.expect_is_dir().times(1).returning(|| false);
        let mut file2_metadata = MockMetadata::new();
        file2_metadata.expect_is_file().times(1).returning(|| true);
        file2_metadata.expect_is_dir().times(1).returning(|| false);

        // Mock directory entry points to an entry a test/path/dir1
        let mut file1_entry = MockDirEntry::new();
        file1_entry
            .expect_path()
            .times(1)
            .returning(|| std::path::PathBuf::from("test/path/file1"));

        // Mock directory entry points to an entry a test/path/dir2
        let mut file2_entry = MockDirEntry::new();
        file2_entry
            .expect_path()
            .times(1)
            .returning(|| std::path::PathBuf::from("test/path/.file2"));

        // Mock read dir results is an iterator that returns a mocked directory
        // entry at test/path/dir1, one at test/path/file1, and then None
        let mut mock_seq = Sequence::new();
        let mut read_dir = MockReadDir::new();
        read_dir
            .expect_next()
            .times(1)
            .in_sequence(&mut mock_seq)
            .return_once(|| Some(io::Result::Ok(Box::new(file1_entry))));
        read_dir
            .expect_next()
            .times(1)
            .in_sequence(&mut mock_seq)
            .return_once(|| Some(io::Result::Ok(Box::new(file2_entry))));
        read_dir
            .expect_next()
            .times(1)
            .in_sequence(&mut mock_seq)
            .returning(|| None);

        // Mock fs expects a metadata call for test/path/dir1 and returns a mock metadata
        // struct identifying the entry as a directory
        // It also expects a read_dir call for test/path and returns the mocked readdir iterator
        let mut fs_rw = MockFs::new();
        fs_rw
            .expect_metadata()
            .with(predicate::eq(std::path::Path::new("test/path/file1")))
            .times(1)
            .return_once(move |_| io::Result::Ok(Box::new(file1_metadata)));
        fs_rw
            .expect_metadata()
            .with(predicate::eq(std::path::Path::new("test/path/.file2")))
            .times(1)
            .return_once(move |_| io::Result::Ok(Box::new(file2_metadata)));
        fs_rw
            .expect_read_dir()
            .with(predicate::eq("test/path"))
            .times(1)
            .return_once(move |_| io::Result::Ok(Box::new(read_dir)));

        // Execute the filter with the mocked fs sequence
        let filter = FsFilterer::new_custom(fs_rw);
        let filter_result = filter.dir("test/path", 1, 2, None).unwrap();
        assert!(
            filter_result.paths.len() == 1
                && filter_result.paths.first().unwrap()
                    == &std::path::PathBuf::from("test/path/.file2")
        );
    }

    #[test]
    fn test_filter_dir_only_hidden_and_non_hidden_directories() {
        // Mock metadata identifies the entry as a directory/file
        let mut dir1_metadata = MockMetadata::new();
        dir1_metadata.expect_is_file().times(1).returning(|| false);
        dir1_metadata.expect_is_dir().times(1).returning(|| true);
        let mut dir2_metadata = MockMetadata::new();
        dir2_metadata.expect_is_file().times(1).returning(|| false);
        dir2_metadata.expect_is_dir().times(1).returning(|| true);
        let mut file1_metadata = MockMetadata::new();
        file1_metadata.expect_is_file().times(1).returning(|| true);
        file1_metadata.expect_is_dir().times(1).returning(|| false);

        // Mock directory entries
        let mut dir1_entry = MockDirEntry::new();
        dir1_entry
            .expect_path()
            .times(1)
            .returning(|| std::path::PathBuf::from("test/path/dir1"));
        let mut dir2_entry = MockDirEntry::new();
        dir2_entry
            .expect_path()
            .times(1)
            .returning(|| std::path::PathBuf::from("test/path/.dir2"));
        let mut file1_entry = MockDirEntry::new();
        file1_entry
            .expect_path()
            .times(1)
            .returning(|| std::path::PathBuf::from("test/path/file1"));

        // Mock read dir results is an iterator that return mock directory entires
        let mut mock_seq = Sequence::new();
        let mut read_dir = MockReadDir::new();
        read_dir
            .expect_next()
            .times(1)
            .in_sequence(&mut mock_seq)
            .return_once(|| Some(io::Result::Ok(Box::new(dir1_entry))));
        read_dir
            .expect_next()
            .times(1)
            .in_sequence(&mut mock_seq)
            .return_once(|| Some(io::Result::Ok(Box::new(file1_entry))));
        read_dir
            .expect_next()
            .times(1)
            .in_sequence(&mut mock_seq)
            .return_once(|| Some(io::Result::Ok(Box::new(dir2_entry))));
        read_dir
            .expect_next()
            .times(1)
            .in_sequence(&mut mock_seq)
            .returning(|| None);

        // Mock fs returns the appropriate metadata struct for each path
        // It also expects a read_dir call for test/path and returns the mocked readdir iterator
        let mut fs_rw = MockFs::new();
        fs_rw
            .expect_metadata()
            .with(predicate::eq(std::path::Path::new("test/path/file1")))
            .times(1)
            .return_once(move |_| io::Result::Ok(Box::new(file1_metadata)));
        fs_rw
            .expect_metadata()
            .with(predicate::eq(std::path::Path::new("test/path/.dir2")))
            .times(1)
            .return_once(move |_| io::Result::Ok(Box::new(dir2_metadata)));
        fs_rw
            .expect_metadata()
            .with(predicate::eq(std::path::Path::new("test/path/dir1")))
            .times(1)
            .return_once(move |_| io::Result::Ok(Box::new(dir1_metadata)));
        fs_rw
            .expect_read_dir()
            .with(predicate::eq("test/path"))
            .times(1)
            .return_once(move |_| io::Result::Ok(Box::new(read_dir)));

        // Execute the filter with the mocked fs sequence
        let filter = FsFilterer::new_custom(fs_rw);
        let filter_result = filter.dir("test/path", 2, 3, None).unwrap();
        assert!(
            filter_result.paths.len() == 2
                && filter_result.paths.get(0).unwrap()
                    == &std::path::PathBuf::from("test/path/dir1")
                && filter_result.paths.get(1).unwrap()
                    == &std::path::PathBuf::from("test/path/.dir2")
        );
    }

    #[test]
    fn test_filter_dir_only_hidden_and_non_hidden_files() {
        // Mock metadata identifies the entry as a directory/file
        let mut file1_metadata = MockMetadata::new();
        file1_metadata.expect_is_file().times(1).returning(|| true);
        file1_metadata.expect_is_dir().times(1).returning(|| false);
        let mut file2_metadata = MockMetadata::new();
        file2_metadata.expect_is_file().times(1).returning(|| true);
        file2_metadata.expect_is_dir().times(1).returning(|| false);
        let mut dir1_metadata = MockMetadata::new();
        dir1_metadata.expect_is_file().times(1).returning(|| false);
        dir1_metadata.expect_is_dir().times(1).returning(|| true);

        // Mock directory entries
        let mut file1_entry = MockDirEntry::new();
        file1_entry
            .expect_path()
            .times(1)
            .returning(|| std::path::PathBuf::from("test/path/file1"));
        let mut file2_entry = MockDirEntry::new();
        file2_entry
            .expect_path()
            .times(1)
            .returning(|| std::path::PathBuf::from("test/path/.file2"));
        let mut dir1_entry = MockDirEntry::new();
        dir1_entry
            .expect_path()
            .times(1)
            .returning(|| std::path::PathBuf::from("test/path/dir1"));

        // Mock read dir results is an iterator that return mock directory entires
        let mut mock_seq = Sequence::new();
        let mut read_dir = MockReadDir::new();
        read_dir
            .expect_next()
            .times(1)
            .in_sequence(&mut mock_seq)
            .return_once(|| Some(io::Result::Ok(Box::new(file1_entry))));
        read_dir
            .expect_next()
            .times(1)
            .in_sequence(&mut mock_seq)
            .return_once(|| Some(io::Result::Ok(Box::new(dir1_entry))));
        read_dir
            .expect_next()
            .times(1)
            .in_sequence(&mut mock_seq)
            .return_once(|| Some(io::Result::Ok(Box::new(file2_entry))));
        read_dir
            .expect_next()
            .times(1)
            .in_sequence(&mut mock_seq)
            .returning(|| None);

        // Mock fs returns the appropriate metadata struct for each path
        // It also expects a read_dir call for test/path and returns the mocked readdir iterator
        let mut fs_rw = MockFs::new();
        fs_rw
            .expect_metadata()
            .with(predicate::eq(std::path::Path::new("test/path/file1")))
            .times(1)
            .return_once(move |_| io::Result::Ok(Box::new(file1_metadata)));
        fs_rw
            .expect_metadata()
            .with(predicate::eq(std::path::Path::new("test/path/.file2")))
            .times(1)
            .return_once(move |_| io::Result::Ok(Box::new(file2_metadata)));
        fs_rw
            .expect_metadata()
            .with(predicate::eq(std::path::Path::new("test/path/dir1")))
            .times(1)
            .return_once(move |_| io::Result::Ok(Box::new(dir1_metadata)));
        fs_rw
            .expect_read_dir()
            .with(predicate::eq("test/path"))
            .times(1)
            .return_once(move |_| io::Result::Ok(Box::new(read_dir)));

        // Execute the filter with the mocked fs sequence
        let filter = FsFilterer::new_custom(fs_rw);
        let filter_result = filter.dir("test/path", 1, 3, None).unwrap();
        assert!(
            filter_result.paths.len() == 2
                && filter_result.paths.get(0).unwrap()
                    == &std::path::PathBuf::from("test/path/file1")
                && filter_result.paths.get(1).unwrap()
                    == &std::path::PathBuf::from("test/path/.file2")
        );
    }

    #[test]
    fn test_filter_dir_only_correct_extension() {
        // Mock metadata identifies the entry as a directory/file
        let mut file1_metadata = MockMetadata::new();
        file1_metadata.expect_is_file().times(1).returning(|| true);
        file1_metadata.expect_is_dir().times(1).returning(|| false);
        let mut file2_metadata = MockMetadata::new();
        file2_metadata.expect_is_file().times(1).returning(|| true);
        file2_metadata.expect_is_dir().times(1).returning(|| false);
        let mut dir1_metadata = MockMetadata::new();
        dir1_metadata.expect_is_file().times(1).returning(|| false);
        dir1_metadata.expect_is_dir().times(1).returning(|| true);
        let mut dir2_metadata = MockMetadata::new();
        dir2_metadata.expect_is_file().times(1).returning(|| false);
        dir2_metadata.expect_is_dir().times(1).returning(|| true);

        // Mock directory entries
        let mut file1_entry = MockDirEntry::new();
        file1_entry
            .expect_path()
            .times(1)
            .returning(|| std::path::PathBuf::from("test/path/file1.yay"));
        let mut file2_entry = MockDirEntry::new();
        file2_entry
            .expect_path()
            .times(1)
            .returning(|| std::path::PathBuf::from("test/path/.file2.nay"));
        let mut dir1_entry = MockDirEntry::new();
        dir1_entry
            .expect_path()
            .times(1)
            .returning(|| std::path::PathBuf::from("test/path/dir1.nay"));
        let mut dir2_entry = MockDirEntry::new();
        dir2_entry
            .expect_path()
            .times(1)
            .returning(|| std::path::PathBuf::from("test/path/dir2.yay"));

        // Mock read dir results is an iterator that return mock directory entires
        let mut mock_seq = Sequence::new();
        let mut read_dir = MockReadDir::new();
        read_dir
            .expect_next()
            .times(1)
            .in_sequence(&mut mock_seq)
            .return_once(|| Some(io::Result::Ok(Box::new(file1_entry))));
        read_dir
            .expect_next()
            .times(1)
            .in_sequence(&mut mock_seq)
            .return_once(|| Some(io::Result::Ok(Box::new(dir1_entry))));
        read_dir
            .expect_next()
            .times(1)
            .in_sequence(&mut mock_seq)
            .return_once(|| Some(io::Result::Ok(Box::new(file2_entry))));
        read_dir
            .expect_next()
            .times(1)
            .in_sequence(&mut mock_seq)
            .return_once(|| Some(io::Result::Ok(Box::new(dir2_entry))));
        read_dir
            .expect_next()
            .times(1)
            .in_sequence(&mut mock_seq)
            .returning(|| None);

        // Mock fs returns the appropriate metadata struct for each path
        // It also expects a read_dir call for test/path and returns the mocked readdir iterator
        let mut fs_rw = MockFs::new();
        fs_rw
            .expect_metadata()
            .with(predicate::eq(std::path::Path::new("test/path/file1.yay")))
            .times(1)
            .return_once(move |_| io::Result::Ok(Box::new(file1_metadata)));
        fs_rw
            .expect_metadata()
            .with(predicate::eq(std::path::Path::new("test/path/.file2.nay")))
            .times(1)
            .return_once(move |_| io::Result::Ok(Box::new(file2_metadata)));
        fs_rw
            .expect_metadata()
            .with(predicate::eq(std::path::Path::new("test/path/dir1.nay")))
            .times(1)
            .return_once(move |_| io::Result::Ok(Box::new(dir1_metadata)));
        fs_rw
            .expect_metadata()
            .with(predicate::eq(std::path::Path::new("test/path/dir2.yay")))
            .times(1)
            .return_once(move |_| io::Result::Ok(Box::new(dir2_metadata)));
        fs_rw
            .expect_read_dir()
            .with(predicate::eq("test/path"))
            .times(1)
            .return_once(move |_| io::Result::Ok(Box::new(read_dir)));

        // Execute the filter with the mocked fs sequence
        let filter = FsFilterer::new_custom(fs_rw);
        let filter_result = filter.dir("test/path", 3, 3, Some("yay")).unwrap();
        assert!(
            filter_result.paths.len() == 2
                && filter_result.paths.get(0).unwrap()
                    == &std::path::PathBuf::from("test/path/file1.yay")
                && filter_result.paths.get(1).unwrap()
                    == &std::path::PathBuf::from("test/path/dir2.yay")
        );
    }
}
