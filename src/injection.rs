use log::trace;
use sysinfo::{Pid, System, SystemExt};
use std::path::{PathBuf, Path};

#[cfg(target_os = "windows")]
use {
    std::ffi::CString,
    widestring::WideCString,
    winapi::um::handleapi::CloseHandle,
    winapi::um::memoryapi::{ VirtualAllocEx, WriteProcessMemory },
    winapi::um::libloaderapi::{ GetModuleHandleA, GetProcAddress },
    winapi::um::processthreadsapi::{ OpenProcess, CreateRemoteThread },
    winapi::um::winnt::{
        MEM_RESERVE, MEM_COMMIT,
        PAGE_EXECUTE_READWRITE,
        PROCESS_ALL_ACCESS
    },
};

use super::Result;
use super::MemoryError;

pub struct Inject {
    process_id: u32,
    library_path: PathBuf
}
impl Inject {
    pub fn new(process_id: i32, library_path: &str) -> Result<Self>{
        // Verify if path exist
        trace!("Verify if library exist");
        let path = Path::new(library_path);
        if ! path.exists() {
            return Err(MemoryError::LibraryNotFound(format!("{}", library_path)));
        }
        let path = path.canonicalize()?;
        trace!("Verify if process exist");
        let mut processes = System::new_all();
        processes.refresh_all();
        if let None = processes.process(process_id as Pid){
            trace!("Process has not been found");
            return Err(MemoryError::ProcessNotFound(process_id))
        }
        let inject = Inject {
            process_id: process_id as u32,
            library_path: path,
        };
        Ok(inject)
    }
    #[cfg(target_os = "windows")]
    pub unsafe fn inject(&self) -> Result<()> {
        let path = self.library_path.as_os_str();
        let path = WideCString::from_os_str(path)?;
        trace!("Opening process {}", self.process_id);
        let process = OpenProcess(PROCESS_ALL_ACCESS , 0, self.process_id);
        trace!("Allocate memory for dll");
        
        todo!("Include injector");
    }

    #[cfg(not(target_os = "windows"))]
    pub fn inject(&self) -> Result<()> {
        trace!("Not implemented");
        Err(MemoryError::NotImplemented)
    }
}