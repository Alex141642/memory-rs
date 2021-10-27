use super::Result;
use super::MemoryError;
use log::{trace};
use std::ptr::{read, write};
use std::mem::size_of;

#[cfg(target_os = "windows")]
use winapi::{
    ctypes::c_void,
    um::winbase::IsBadReadPtr,
    um::winbase::IsBadWritePtr,
};

pub fn read_ptr<T>(address: usize) -> Result<T> {
    #[cfg(target_os = "windows")]
    unsafe {
        match IsBadReadPtr(address as *const c_void, size_of::<T>()){
            0 => {
                trace!("Allowed to read at address {:#04x}", address);
            },
            _ => return Err(MemoryError::ReadPtrError(address))
        };
        Ok(read(address as *const T))
    }
}

pub fn write_ptr<T>(address: usize, value: T) -> Result<()> {
    #[cfg(target_os = "windows")]
    unsafe {
        match IsBadWritePtr(address as *mut c_void, size_of::<T>()){
            0 => {
                trace!("Allowed to write to address {:#04x}", address);
            },
            _ => return Err(MemoryError::WritePtrError(address))
        };
        Ok(write(address as *mut T, value))
    }
}