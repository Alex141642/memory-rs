use crate::memory::read_ptr;
use crate::{memory::write_ptr, MemoryError};
use winapi::shared::minwindef::DWORD;
use winapi::um::processthreadsapi::{FlushInstructionCache, GetCurrentProcess};
use winapi::um::winnt::{MEM_RELEASE, PAGE_EXECUTE_READWRITE, PVOID};
use winapi::um::{
    memoryapi::{VirtualAlloc, VirtualFree, VirtualProtect},
    winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE},
};

/// Hook delphi functions

#[repr(u8)]
enum AsmOp {
    PushAD = 0x60,
    PushFD = 0x9C,
    PopAD = 0x61,
    PopFD = 0x9D,
    Call = 0xE8,
    Jmp = 0xE9,
    Nop = 0x90,
    Ret = 0xC3,
}

/// # Safety
/// Not safe
pub unsafe fn create_trampoline(
    target_fn_addr: usize,
    hook_fn_addr: usize,
    backup: Vec<u8>,
    hook_size: usize,
) -> Result<usize, MemoryError> {
    let trampoline_size = hook_size + 14;
    let trampoline_addr = unsafe {
        VirtualAlloc(
            std::ptr::null_mut(),
            trampoline_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
    };
    if trampoline_addr.is_null() {
        return Err(MemoryError::AllocationError(
            "Could not alocate trampoline page".into(),
        ));
    }
    let push_regs_addr = trampoline_addr.addr();
    let hook_call_addr = push_regs_addr + 0x2;
    let pop_regs_addr = hook_call_addr + 0x5;
    let bytes_backup_addr = pop_regs_addr + 0x2;
    let back_jump_addr = bytes_backup_addr + hook_size;
    write_ptr(push_regs_addr, AsmOp::PushAD as u8, true)?;
    write_ptr(push_regs_addr + 0x1, AsmOp::PushFD as u8, true)?;
    write_ptr(hook_call_addr, AsmOp::Call as u8, true)?;
    write_ptr(
        hook_call_addr + 0x1,
        hook_fn_addr as isize - hook_call_addr as isize - 0x5,
        true,
    )?;

    write_ptr(pop_regs_addr, AsmOp::PopFD as u8, true)?;
    write_ptr(pop_regs_addr + 0x1, AsmOp::PopAD as u8, true)?;
    for (i, byte) in backup.into_iter().enumerate() {
        write_ptr(bytes_backup_addr + i, byte, true)?;
    }

    write_ptr(back_jump_addr, AsmOp::Jmp as u8, true)?;

    write_ptr(
        back_jump_addr + 0x1,
        (target_fn_addr + hook_size) as isize - back_jump_addr as isize - 0x5,
        true,
    )?;

    let mut old_protection: DWORD = 0x00;
    if VirtualProtect(
        trampoline_addr,
        trampoline_size,
        PAGE_EXECUTE_READ,
        &mut old_protection,
    )
    .is_negative()
        || FlushInstructionCache(GetCurrentProcess(), trampoline_addr, trampoline_size)
            .is_negative()
    {
        VirtualFree(trampoline_addr, 0, MEM_RELEASE);
        return Err(MemoryError::AllocationError(
            "Could not change page protection".into(),
        ));
    }
    Ok(trampoline_addr.addr())
}

/// # Safety
/// Not safe
pub unsafe fn hook_function(
    target_fn_addr: usize,
    hook_fn_addr: usize,
    hook_size: usize,
) -> Result<(), MemoryError> {
    let mut old_protection: DWORD = 0x00;
    if (VirtualProtect(
        target_fn_addr as PVOID,
        hook_size,
        PAGE_EXECUTE_READWRITE,
        &mut old_protection,
    ))
    .is_negative()
    {
        return Err(MemoryError::AllocationError(
            "Could not change the memory protetion".into(),
        ));
    }

    let mut backup: Vec<u8> = Vec::with_capacity(hook_size);
    for i in 0..hook_size {
        backup.push(read_ptr(target_fn_addr + i)?)
    }
    let trampoline_addr = create_trampoline(target_fn_addr, hook_fn_addr, backup, hook_size)?;
    write_ptr(target_fn_addr, AsmOp::Jmp, true)?;
    write_ptr(
        target_fn_addr + 0x1,
        trampoline_addr - target_fn_addr - 0x5,
        true,
    )?;
    write_ptr(target_fn_addr + 0x5, AsmOp::Nop, true)?;
    VirtualProtect(
        target_fn_addr as PVOID,
        hook_size,
        old_protection,
        &mut old_protection,
    );
    Ok(())
}

/// # Safety
/// Not safe
pub unsafe fn unhook_function(target_fn_addr: usize, hook_size: usize) -> Result<(), MemoryError> {
    //let offset: [u8; 5] = read_ptr(target_fn_addr + 0x1)?;
    // TODO: set real trampoline addr
    let trampoline_addr = target_fn_addr;
    let backup_addr = trampoline_addr + 9;

    let mut old_protection: DWORD = 0x00;
    if VirtualProtect(
        target_fn_addr as PVOID,
        hook_size,
        PAGE_EXECUTE_READWRITE,
        &mut old_protection,
    )
    .is_negative()
    {
        return Err(MemoryError::AllocationError(
            "Could not change the memory protetion".into(),
        ));
    }
    for i in 0..hook_size {
        let value: u8 = read_ptr(backup_addr + i)?;
        write_ptr(target_fn_addr + i, value, true)?;
    }
    if VirtualProtect(
        target_fn_addr as PVOID,
        hook_size,
        old_protection,
        &mut old_protection,
    )
    .is_negative()
    {
        return Err(MemoryError::AllocationError(
            "Could not change the memory protetion".into(),
        ));
    }
    Ok(())
}

/* TODO: Example of ptr copy
pub fn append(&mut self, other: &mut Self) {
        unsafe {
            self.append_elements(other.as_slice() as _);
            other.set_len(0);
        }
    }

unsafe fn append_elements(&mut self, other: *const [T]) {
        let count = unsafe { (*other).len() };
        self.reserve(count);
        let len = self.len();
        unsafe { ptr::copy_nonoverlapping(other as *const T, self.as_mut_ptr().add(len), count) };
        self.len += count;
    }
*/
