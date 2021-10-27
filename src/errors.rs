use thiserror::Error;

#[derive(Error, Debug)]
pub enum MemoryError {
    #[error("IO Error")]
    IoError( #[from] std::io::Error ),
    #[error("Unable to read address {0}")]
    ReadPtrError(usize),
    #[error("Unable to write to address {0}")]
    WritePtrError(usize),
    #[error("Unable to find path `{0}`")]
    PathError(String),
    #[error("The library `{0}` has not been found")]
    LibraryNotFound(String),
    #[error("The process `{0}` given does not exist")]
    ProcessNotFound(i32),
    #[error("Could not inject `{0}`")]
    InjectionError(String),
    #[error("Could not create pattern `{0}`")]
    PatternError(String),
    #[error("No occurence for given pattern has been found for `{0}`")]
    PatternNotFound(String),
    #[error("Unknown error")]
    UnknownError,
    #[error("Not implemented")]
    NotImplemented,
}

impl From<hex::FromHexError> for MemoryError {
    fn from(error: hex::FromHexError) -> MemoryError {
        MemoryError::PatternError(format!("{}", error))
    }
}


impl From<widestring::NulError<u16>> for MemoryError {
    fn from(_: widestring::NulError<u16>) -> MemoryError {
        MemoryError::PathError("".to_string())
    }
}

impl From<std::ffi::NulError> for MemoryError {
    fn from(_: std::ffi::NulError) -> MemoryError {
        MemoryError::PathError("".to_string())
    }
}