#![feature(const_try)]
#![feature(const_trait_impl)]

mod errors;
pub mod injection;
pub mod memory;
pub mod pattern;
pub use errors::MemoryError;
pub mod patcher;
pub type Result<T> = std::result::Result<T, MemoryError>;
pub mod hook_delphi;
pub use hook_delphi::create_trampoline;
