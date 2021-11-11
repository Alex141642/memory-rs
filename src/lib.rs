mod errors;
pub mod injection;
pub mod memory;
pub mod pattern;
pub use errors::MemoryError;
pub mod utils;
pub type Result<T> = std::result::Result<T, MemoryError>;
