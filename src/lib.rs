mod errors;
pub mod memory;
pub mod pattern;
pub mod injection;
pub use errors::MemoryError;

pub type Result<T> = std::result::Result<T, MemoryError>;
