use super::MemoryError;
use super::Result;
use log::trace;
use std::ptr::{read, write};

#[cfg(target_os = "windows")]
use {
    log::error,
    std::mem::size_of,
    winapi::{
        shared::basetsd::SIZE_T,
        shared::minwindef::DWORD,
        um::{
            memoryapi::{VirtualProtect, VirtualQuery},
            winnt::{
                MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE, PAGE_EXECUTE_READ,
                PAGE_EXECUTE_READWRITE, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
                PAGE_WRITECOPY, PVOID,
            },
        },
    },
};

/// can_read_ptr is a function wich will check if the memory page have required configuration for read access.
///
/// It takes in parameters:
/// * `address: usize` The address of the memory we want to check
///
/// Return true if the memory is readable
///
/// Example
/// ```rust
///    let addr: usize = 0x400000;
///    match memory_rs::memory::can_read_ptr(addr){
///       true => println!("We can read at address {:x}", addr),
///       false => println!("We can't read at address {:x}", addr),
///    }
/// ```
#[cfg(target_os = "windows")]
pub fn can_read_ptr(address: usize) -> bool {
    unsafe {
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
            return false;
        }
        return true;
    }
}

#[cfg(not(target_os = "windows"))]
pub fn can_read_ptr(_address: usize) -> bool {
    // No check for linux/mac for the moment
    return true;
}

/// read_ptr is a function wich get data from a specified address and cast it to the data given as T.
///
/// It takes in paramaters:
///    * `address: usize` The address of the data
///
/// By its operations, this function is unsafe.
///
/// Example
/// ```rust
/// let addr: usize = 0x400000;
/// unsafe {
///     let mydata: u8 = match memory_rs::memory::read_ptr(addr){
///         Ok(data) => data,
///         Err(_) => 3 // If not found
///     };
/// }
/// ```
pub unsafe fn read_ptr<T>(address: usize) -> Result<T> {
    trace!("Checking if address is readable");
    if !can_read_ptr(address) {
        trace!("Address is not readable");
        return Err(MemoryError::ReadPtrError(address));
    }
    trace!("Address is readable");
    Ok(read(address as *const T))
}

/// can_write_ptr is a function wich will check if the memory page have required configuration for write access.
///
/// It takes in parameters:
/// * `address: usize` The address of the memory we want to check
///
/// Return true if the memory is writable
///
/// Example
/// ```rust
///    let addr: usize = 0x400000;
///    match memory_rs::memory::can_write_ptr(addr){
///       true => println!("We can write at address {:x}", addr),
///       false => println!("We can't write at address {:x}", addr),
///    }
/// ```
#[cfg(target_os = "windows")]
pub fn can_write_ptr(address: usize) -> bool {
    unsafe {
        let mut memory_info: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        let bytes = VirtualQuery(
            address as PVOID,
            &mut memory_info,
            size_of::<MEMORY_BASIC_INFORMATION>() as SIZE_T,
        );

        if bytes == 0 {
            error!("Error while checking MemInfo");
            return false;
        }
        if memory_info.State != MEM_COMMIT {
            error!("Error while checking MemInfo");
            return false;
        }
        match memory_info.Protect {
            PAGE_NOACCESS | PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_READONLY => {
                trace!("Memory do not allow write");
                return false;
            }
            _ => {
                trace!("Memory allow write");
                return true;
            }
        };
    }
}

#[cfg(not(target_os = "windows"))]
pub unsafe fn can_write_ptr(_address: usize) -> bool {
    // No check for linux/mac for the moment
    return true;
}

/// write_ptr is a function wich write data to a specified address and cast it to the data given as T.
///
/// It takes in paramaters:
///    * `address: usize` The address of the data
///    * `value: T> The data given
///
/// By its operations, this function is unsafe.
///
/// Example
/// ```rust
///    let addr: usize = 0x400000;
///    let byte: u8 = 0x9;
///    unsafe {
///        match memory_rs::memory::write_ptr::<u8>(addr, byte) {
///            Ok(_) => println!("Written"),
///            Err(_) => println!("Not written"),
///        };
///    }
/// ```
pub unsafe fn write_ptr<T>(address: usize, value: T, force: bool) -> Result<()> {
    trace!("Checking if address is writable");
    if !can_write_ptr(address) {
        trace!("Address is not writable");
        if force {
            trace!("Force writting data");
            #[cfg(target_os = "windows")]
            let mut old_protection: DWORD = 0x00;
            #[cfg(target_os = "windows")]
            VirtualProtect(
                address as PVOID,
                size_of::<T>(),
                PAGE_EXECUTE_READWRITE,
                &mut old_protection,
            );
            write(address as *mut T, value);
            #[cfg(target_os = "windows")]
            VirtualProtect(
                address as PVOID,
                size_of::<T>(),
                old_protection,
                &mut old_protection,
            );
            return Ok(());
        }
        return Err(MemoryError::WritePtrError(address));
    } else {
        trace!("Address is writable");
        write(address as *mut T, value);
    }
    Ok(())
}

/// can_exec_ptr is a function wich will check if the memory page have required configuration for exec access.
///
/// It takes in parameters:
/// * `address: usize` The address of the memory we want to check
///
/// Return true if the memory is executable
///
/// Example
/// ```rust
///    let addr: usize = 0x400000;
///    match memory_rs::memory::can_exec_ptr(addr){
///       true => println!("We can exec at address {:x}", addr),
///       false => println!("We can't exec at address {:x}", addr),
///    }
/// ```
#[cfg(target_os = "windows")]
pub fn can_exec_ptr(address: usize) -> bool {
    unsafe {
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
            return false;
        }
        return true;
    }
}

#[cfg(not(target_os = "windows"))]
pub fn can_exec_ptr(_address: usize) -> bool {
    return true;
}

pub unsafe fn func_ptr<T>(address: usize) -> Result<T> {
    if can_exec_ptr(address) {
        return Ok(std::mem::transmute_copy::<usize, T>(&address));
    }
    Err(MemoryError::ExecPtrError(address))
}

#[macro_export]
macro_rules! make_fn {
    ($address:expr; $returntype:ty) => {
        unsafe { std::mem::transmute::<*const usize, $returntype>($address as *const usize) }
    };
}
