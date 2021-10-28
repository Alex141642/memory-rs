use super::Result;
use super::MemoryError;
use log::{trace};
use std::ptr::{read, write};
use std::mem::size_of;

#[cfg(target_os = "windows")]
use winapi::{
    um::winbase::IsBadReadPtr,
    um::winbase::IsBadWritePtr,
};

#[cfg(target_os = "windows")]
use winapi::{
    ctypes::c_void,
    um::{
        winnt::{
            PVOID,
            MEMORY_BASIC_INFORMATION,
            MEM_COMMIT,
            PAGE_NOACCESS,
            PAGE_EXECUTE,
            PAGE_EXECUTE_READ,
            PAGE_EXECUTE_READWRITE,
            PAGE_EXECUTE_WRITECOPY,
            PAGE_READONLY,
            PAGE_READWRITE,
            PAGE_WRITECOPY,
        },
        memoryapi::VirtualQuery,
    },
    shared::basetsd::SIZE_T,
};

#[cfg(target_os = "windows")]
unsafe fn can_read_ptr(address: usize) -> bool {
    let mut memory_info: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
    let bytes = VirtualQuery(
        address as PVOID,
        &mut memory_info,
        size_of::<MEMORY_BASIC_INFORMATION>() as SIZE_T,
    );
    if bytes == 0 {
        return false;
    }
    if memory_info.State != MEM_COMMIT {
        return false;
    }
    if memory_info.Protect == PAGE_NOACCESS | PAGE_EXECUTE {
        return false
    }
    /*
    match IsBadReadPtr(address as *const c_void, size_of::<T>()){
        0 => {
            trace!("Allowed to read at address {:#04x}", address);
        },
        _ => return Err(MemoryError::ReadPtrError(address))
    };
    */
    return true
}

#[cfg(not(target_os = "windows"))]
fn can_read_ptr(address: usize) -> bool {
    return true
}

pub fn read_ptr<T>(address: usize) -> Result<T> {
    unsafe {
        trace!("Checking if address is readable");
        if !can_read_ptr(address) {
            trace!("Address is not readable");
            return Err(MemoryError::ReadPtrError(address))
        }
        trace!("Address is readable");
        Ok(read(address as *const T))
    }
}

#[cfg(target_os = "windows")]
unsafe fn can_write_ptr(address: usize) -> bool {
    let mut memory_info: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
    let bytes = VirtualQuery(
        address as PVOID,
        &mut memory_info,
        size_of::<MEMORY_BASIC_INFORMATION>() as SIZE_T,
    );
    if bytes == 0 {
        return false;
    }
    if memory_info.State != MEM_COMMIT {
        return false;
    }
    todo!("Include checks");
    /*
    match IsBadWritePtr(address as *mut c_void, size_of::<T>()){
        0 => {
            trace!("Allowed to write to address {:#04x}", address);
        },
        _ => return Err(MemoryError::WritePtrError(address))
    };
    */
}

#[cfg(not(target_os = "windows"))]
unsafe fn can_write_ptr(address: usize) -> bool {
    return true;
}

pub fn write_ptr<T>(address: usize, value: T) -> Result<()> {
    unsafe {
        trace!("Checking if address is writable");
        if !can_write_ptr(address){
            trace!("Address is not writable");
        }
        trace!("Address is writable");
        Ok(write(address as *mut T, value))
    }
}