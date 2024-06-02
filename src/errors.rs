use thiserror::Error;

#[derive(Error, Debug)]
pub enum MemoryError {
    #[error("IO Error")]
    IoError(#[from] std::io::Error),
    #[error("Unable to execute address {0:x}")]
    ExecPtrError(usize),
    #[error("Unable to read address {0:x}")]
    ReadPtrError(usize),
    #[error("Unable to write to address {0:x}")]
    WritePtrError(usize),
    #[error("Unable to find path `{0}`")]
    PathError(String),
    #[error("Unable to patch data in memory address {0}")]
    PatchError(usize),
    #[error("The library `{0}` has not been found")]
    LibraryNotFound(String),
    #[error("The process `{0}` given does not exist")]
    ProcessNotFound(u32),
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
    #[error("Allocation error: {0}")]
    AllocationError(String),
}

impl From<hex::FromHexError> for MemoryError {
    fn from(error: hex::FromHexError) -> MemoryError {
        MemoryError::PatternError(format!("{}", error))
    }
}

impl From<widestring::error::ContainsNul<u16>> for MemoryError {
    fn from(_: widestring::error::ContainsNul<u16>) -> MemoryError {
        MemoryError::PathError("".to_string())
    }
}

impl From<std::ffi::NulError> for MemoryError {
    fn from(_: std::ffi::NulError) -> MemoryError {
        MemoryError::PathError("".to_string())
    }
}

impl From<regex::Error> for MemoryError {
    fn from(_: regex::Error) -> MemoryError {
        MemoryError::PatternError("Could not build regexp".to_string())
    }
}
