use std::convert::TryFrom;
use std::io::{Cursor, Read};

use crate::memory::read_ptr;
use crate::{memory::write_ptr, MemoryError};
use winapi::shared::minwindef::DWORD;
use winapi::um::processthreadsapi::{FlushInstructionCache, GetCurrentProcess};
use winapi::um::winnt::{MEM_RELEASE, PAGE_EXECUTE_READWRITE, PVOID};
use winapi::um::{
    memoryapi::{VirtualAlloc, VirtualFree, VirtualProtect},
    winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE},
};

// AsmOp represent the possible assembly instuctions that are set
#[repr(u8)]
enum AsmOp {
    PushAD = 0x60,
    PushFD = 0x9C,
    PopAD = 0x61,
    PopFD = 0x9D,
    Call = 0xE8,
    Jmp = 0xE9,
    Nop = 0x90,
}

#[derive(Clone, Debug)]
struct TrampolineMemory<const N: usize> {
    call_hook_instructions: [u8; 3],
    hook_transformed_fn_addr: isize,
    after_call_hook_instructions: [u8; 2],
    backup: [u8; N],
    call_original_instructions: [u8; 1],
    original_transformed_fn_addr: isize,
}

impl<const N: usize> From<TrampolineMemory<N>> for Vec<u8> {
    fn from(v: TrampolineMemory<N>) -> Self {
        let mut out = Vec::with_capacity(std::mem::size_of::<TrampolineMemory<N>>());
        out.extend_from_slice(&v.call_hook_instructions);
        out.extend_from_slice(&v.hook_transformed_fn_addr.to_le_bytes());
        out.extend_from_slice(&v.after_call_hook_instructions);
        out.extend_from_slice(&v.backup);
        out.extend_from_slice(&v.call_original_instructions);
        out.extend_from_slice(&v.original_transformed_fn_addr.to_le_bytes());
        out
    }
}

impl<const N: usize> TryFrom<Cursor<&[u8]>> for TrampolineMemory<N> {
    type Error = MemoryError;
    fn try_from(mut value: Cursor<&[u8]>) -> Result<Self, Self::Error> {
        let mut out = TrampolineMemory {
            call_hook_instructions: [0u8; 3],
            hook_transformed_fn_addr: 0,
            after_call_hook_instructions: [0u8; 2],
            backup: [0u8; N],
            call_original_instructions: [0u8; 1],
            original_transformed_fn_addr: 0,
        };
        let mut readen = value.read(&mut out.call_hook_instructions)?;
        if readen != out.call_hook_instructions.len() {
            return Err(MemoryError::AllocationError(format!(
                "Read {readen} bytes into a {} sized array",
                out.call_hook_instructions.len()
            )));
        }
        let mut hook_transformed_fn_addr = [0u8; 4];
        readen = value.read(&mut hook_transformed_fn_addr)?;
        if readen != hook_transformed_fn_addr.len() {
            return Err(MemoryError::AllocationError(format!(
                "Read {readen} bytes into a {} sized array",
                hook_transformed_fn_addr.len()
            )));
        }
        out.hook_transformed_fn_addr = isize::from_le_bytes(hook_transformed_fn_addr);
        readen = value.read(&mut out.after_call_hook_instructions)?;
        if readen != out.after_call_hook_instructions.len() {
            return Err(MemoryError::AllocationError(format!(
                "Read {readen} bytes into a {} sized array",
                out.after_call_hook_instructions.len()
            )));
        }
        readen = value.read(&mut out.backup)?;
        if readen != out.backup.len() {
            return Err(MemoryError::AllocationError(format!(
                "Read {readen} bytes into a {} sized array",
                out.backup.len()
            )));
        }
        readen = value.read(&mut out.call_original_instructions)?;
        if readen != out.call_original_instructions.len() {
            return Err(MemoryError::AllocationError(format!(
                "Read {readen} bytes into a {} sized array",
                out.call_original_instructions.len()
            )));
        }
        let mut original_transformed_fn_addr = [0u8; 4];
        readen = value.read(&mut original_transformed_fn_addr)?;
        if readen != original_transformed_fn_addr.len() {
            return Err(MemoryError::AllocationError(format!(
                "Read {readen} bytes into a {} sized array",
                original_transformed_fn_addr.len()
            )));
        }
        out.original_transformed_fn_addr = isize::from_le_bytes(original_transformed_fn_addr);
        Ok(out)
    }
}

/// # Safety
/// Not safe
pub unsafe fn create_trampoline<const N: usize>(
    target_fn_addr: usize,
    hook_fn_addr: usize,
    backup: [u8; N],
) -> Result<usize, MemoryError> {
    // Why 14?
    let trampoline_addr = unsafe {
        VirtualAlloc(
            std::ptr::null_mut(),
            std::mem::size_of::<TrampolineMemory<N>>(),
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
    let back_jump_addr = bytes_backup_addr + N;

    let trampoline_memory = TrampolineMemory {
        call_hook_instructions: [AsmOp::PushAD as u8, AsmOp::PushFD as u8, AsmOp::Call as u8],
        hook_transformed_fn_addr: (hook_fn_addr as isize - hook_call_addr as isize - 0x5),
        after_call_hook_instructions: [AsmOp::PopFD as u8, AsmOp::PopAD as u8],
        backup,
        call_original_instructions: [AsmOp::Jmp as u8],
        original_transformed_fn_addr: (target_fn_addr as isize + N as isize
            - back_jump_addr as isize
            - 0x5),
    };
    log::warn!("trampoline address: {:02X}", trampoline_addr.addr());
    log::trace!("trampoline data: {:?}", trampoline_memory);
    let bytes: Vec<u8> = trampoline_memory.into();
    log::trace!("trampoline data bytes: {:02X?}", bytes);

    for (i, byte) in bytes.into_iter().enumerate() {
        write_ptr(trampoline_addr.addr() + i, byte, true)?;
    }

    let mut old_protection: DWORD = 0x00;
    if VirtualProtect(
        trampoline_addr,
        std::mem::size_of::<TrampolineMemory<N>>(),
        PAGE_EXECUTE_READ,
        &mut old_protection,
    )
    .is_negative()
        || FlushInstructionCache(
            GetCurrentProcess(),
            trampoline_addr,
            std::mem::size_of::<TrampolineMemory<N>>(),
        )
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
pub unsafe fn hook_function<const N: usize>(
    target_fn_addr: usize,
    hook_fn_addr: usize,
) -> Result<(), MemoryError> {
    log::warn!("OLD ADDRESS IS {:02X}", target_fn_addr);
    let mut old_protection: DWORD = 0x00;
    if (VirtualProtect(
        target_fn_addr as PVOID,
        N,
        PAGE_EXECUTE_READWRITE,
        &mut old_protection,
    ))
    .is_negative()
    {
        return Err(MemoryError::AllocationError(
            "Could not change the memory protetion".into(),
        ));
    }
    let mut backup = [0u8; N];
    for (i, v) in backup.iter_mut().enumerate() {
        *v = read_ptr(target_fn_addr + i)?;
    }
    let trampoline_addr = create_trampoline(target_fn_addr, hook_fn_addr, backup)?;
    let mut bytes: Vec<u8> = Vec::new();
    bytes.push(AsmOp::Jmp as u8);
    bytes.extend_from_slice(
        // 0x5 is the place of the data
        &(trampoline_addr as isize - target_fn_addr as isize - 0x5).to_le_bytes(),
    );
    bytes.push(AsmOp::Nop as u8);
    for (i, byte) in bytes.into_iter().enumerate() {
        write_ptr(target_fn_addr + i, byte, true)?;
    }

    VirtualProtect(
        target_fn_addr as PVOID,
        N,
        old_protection,
        &mut old_protection,
    );
    Ok(())
}

/// # Safety
/// Not safe
pub unsafe fn unhook_function<const N: usize>(
    target_fn_addr: usize,
    hook_size: usize,
) -> Result<(), MemoryError> {
    log::warn!("target_fn_addr is {:02X}", target_fn_addr);
    let jmp_addr: isize = read_ptr(target_fn_addr + 0x1)?;
    log::warn!("jmp_addr is {:02X}", jmp_addr);
    let trampoline_addr = (jmp_addr + target_fn_addr as isize) as usize + 0x5;
    // We now have the address where are stored our data

    log::warn!("trampoline_addr ADDRESS IS {:02X}", trampoline_addr);

    let mut trampoline_bytes = Vec::new();
    for i in 0..std::mem::size_of::<TrampolineMemory<N>>() {
        trampoline_bytes.push(read_ptr(trampoline_addr + i)?);
    }
    log::warn!("unhook bytes readen {:02X?}", trampoline_bytes);

    let trampoline_data: TrampolineMemory<N> =
        TrampolineMemory::try_from(Cursor::new(trampoline_bytes.as_slice()))?;
    log::warn!("unhook trampoline data readen {:02X?}", trampoline_data);

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
        write_ptr(target_fn_addr + i, trampoline_data.backup[i], true)?;
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
