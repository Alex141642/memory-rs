use log::trace;
use std::path::{Path, PathBuf};
use sysinfo::{Pid, System, SystemExt};

#[cfg(target_os = "windows")]
use {
    std::ffi::CString,
    widestring::WideCString,
    winapi::um::handleapi::CloseHandle,
    winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress},
    winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory},
    winapi::um::processthreadsapi::{CreateRemoteThread, OpenProcess},
    winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PROCESS_ALL_ACCESS},
};

use super::MemoryError;
use super::Result;
/*
#[cfg(not(target_os = "windows"))]
use {
    nix::sys::signal::kill,
    nix::sys::signal::Signal::{SIGCONT, SIGSTOP},
};
*/

/// This structure provide 2 functions wich aims to simplify dll/so injection into process.
///
/// Example
/// ```rust
/// let own_inject = match Inject::new(std::process::id(), "/tmp/mylib.dll").unwrap();
/// unsafe { own_inject.inject(); }
/// ```

#[allow(dead_code)]
pub struct Inject {
    process_id: u32,
    library_path: PathBuf,
}
impl Inject {
    /// new function is the structure initializer.
    /// It takes in arguments the following:
    ///    * `process_id: i32`
    ///    * `library_path: &str`
    ///
    /// It returns a `Result<Inject, MemoryError>`, because the function check
    /// if the process and the lib path both exists.
    pub fn new(process_id: i32, library_path: &str) -> Result<Self> {
        trace!("Verify if library exist");
        let path = Path::new(library_path);
        if !path.exists() {
            return Err(MemoryError::LibraryNotFound(library_path.into()));
        }
        let path = path.canonicalize()?;
        trace!("Verify if process exist");
        let mut processes = System::new_all();
        processes.refresh_all();
        if processes.process(process_id as Pid).is_none() {
            trace!("Process has not been found");
            return Err(MemoryError::ProcessNotFound(process_id));
        }
        let inject = Inject {
            process_id: process_id as u32,
            library_path: path,
        };
        Ok(inject)
    }
    /// inject function is unsafe do to it's operations.
    ///
    /// inject function is the method used to inject to lib to the process.
    ///
    /// It returns a `Result<Inject, MemoryError>`, because the function can fail a lot of time.
    #[cfg(target_os = "windows")]
    pub fn inject(&self) -> Result<()> {
        let path = self.library_path.as_os_str();
        let path = WideCString::from_os_str(path)?;
        trace!("Opening process {}", self.process_id);
        unsafe {
            let process = OpenProcess(PROCESS_ALL_ACCESS, 0, self.process_id);
            trace!("Allocate memory for dll");
            let dll_address = VirtualAllocEx(
                process,
                std::ptr::null_mut(),
                (path.len() * 2) + 1,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_EXECUTE_READWRITE,
            );
            trace!("Inject dll in process");
            let result = WriteProcessMemory(
                process,
                dll_address,
                path.as_ptr() as *mut _,
                (path.len() * 2) + 1,
                std::ptr::null_mut(),
            );
            if result == 0 {
                return Err(MemoryError::InjectionError(
                    "WriteProcessMemory failed".to_string(),
                ));
            }
            trace!("Get LoadLibraryW function");
            let loadlib = GetProcAddress(
                GetModuleHandleA(CString::new("kernel32.dll")?.as_ptr()),
                CString::new("LoadLibraryW")?.as_ptr(),
            );
            trace!("Create remote thread");
            let htthread = CreateRemoteThread(
                process,
                std::ptr::null_mut(),
                0,
                Some(std::mem::transmute(loadlib)),
                dll_address,
                0,
                std::ptr::null_mut(),
            );
            CloseHandle(htthread);
        }
        trace!("Injection successful");
        Ok(())
    }

    // Concept based on https://github.com/DavidBuchanan314/dlinject/blob/master/dlinject.py
    #[cfg(not(target_os = "windows"))]
    pub fn inject(&self) -> Result<()> {
        trace!("Not implemented");
        Err(MemoryError::NotImplemented)
    }
}
