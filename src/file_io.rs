use std::{fs, io, iter::Iterator};

pub trait FsReadWriter {
    fn read_dir(&self, path: &str) -> io::Result<fs::ReadDir>;
}

pub struct Fs {}

impl FsReadWriter for Fs {
    fn read_dir(&self, path: &str) -> io::Result<fs::ReadDir> {
        fs::read_dir(path)
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
            .filter_map(|entry| -> Option<fs::DirEntry> {
                match entry {
                    Ok(entry) => Some(entry),
                    Err(e) => {
                        io_errors.push(e);
                        None
                    }
                }
            })
            .filter_map(|entry| {
                let path = entry.path();
                match (fs::metadata(&path), path.file_stem(), path.extension()) {
                    (Ok(metadata), Some(file_stem), Some(extension)) => {
                        let is_file = metadata.is_file() as u8;
                        let is_dir = (metadata.is_dir() as u8) << 1;
                        let extension_check = match extension_filter {
                            Some(extension_filter) => extension_filter == extension,
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
    use super::{FsFilterer, FsReadWriter};
    use mockall::predicate::*;
    use mockall::*;
    use std::{fs, io};

    mock! {
    pub Fs {}
    impl FsReadWriter for Fs {
        fn read_dir(&self, path: &str) -> io::Result<fs::ReadDir>;
    }
    }

    #[test]
    fn test_fsfilterer_empty_dir() {
        let mut fs_rw = MockFs::new();
        fs_rw
            .expect_read_dir()
            .with(predicate::eq("test/path"))
            .times(1)
            .returning(|_| fs::read_dir("."));

        let filter = FsFilterer::new_custom(fs_rw);
        filter.dir("test/path", 1, 1, None).unwrap();
    }
}
