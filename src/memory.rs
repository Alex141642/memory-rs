use super::Result;
use super::MemoryError;
use log::{trace};
use std::ptr::{read, write};
use std::mem::size_of;

#[cfg(target_os = "windows")]
use winapi::{
    um::{
        winnt::{
            PVOID,
            MEMORY_BASIC_INFORMATION,
            MEM_COMMIT,
            PAGE_NOACCESS,
            PAGE_EXECUTE,
            PAGE_EXECUTE_READ,
            PAGE_READONLY,
            PAGE_READWRITE,
            PAGE_WRITECOPY
        },
        memoryapi::VirtualQuery,
    },
    shared::basetsd::SIZE_T,
};

#[cfg(target_os = "windows")]
pub unsafe fn can_read_ptr(address: usize) -> bool {
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
    return true
}

#[cfg(not(target_os = "windows"))]
pub fn can_read_ptr(address: usize) -> bool {
    // No check for linux/mac for the moment
    return true
}

pub unsafe fn read_ptr<T>(address: usize) -> Result<T> {
    trace!("Checking if address is readable");
    if !can_read_ptr(address) {
        trace!("Address is not readable");
        return Err(MemoryError::ReadPtrError(address))
    }
    trace!("Address is readable");
    Ok(read(address as *const T))
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
    if memory_info.Protect == PAGE_NOACCESS | PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_READONLY {
        return false
    }
    return true
}

#[cfg(not(target_os = "windows"))]
unsafe fn can_write_ptr(address: usize) -> bool {
    // No check for linux/mac for the moment
    return true;
}

pub unsafe fn write_ptr<T>(address: usize, value: T) -> Result<()> {
    trace!("Checking if address is writable");
    if !can_write_ptr(address){
        trace!("Address is not writable");
    }
    trace!("Address is writable");
    Ok(write(address as *mut T, value))
}

#[cfg(target_os = "windows")]
unsafe fn can_exec_ptr(address: usize) -> bool {
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
    if memory_info.Protect == PAGE_NOACCESS | PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY {
        return false
    }
    return true
}

#[cfg(not(target_os = "windows"))]
fn can_exec_ptr(address: usize) -> bool {
    return true
}

pub unsafe fn func_ptr<T>(address: usize) -> Result<*const T> {
    trace!("Checking if address is executable");
    if !can_exec_ptr(address){
        return Err(MemoryError::ExecPtrError(address))
    }
    trace!("Address is executable");
    Ok(std::mem::transmute::<*const usize, *const T>(address as *const usize))
}