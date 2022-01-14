use crate::memory::{can_read_ptr, read_ptr, write_ptr};
use crate::{MemoryError, Result};
pub struct Patcher {
    address: usize,
    initial_mem: Vec<u8>,
    transformed_mem: Vec<u8>,
}
impl Patcher {
    pub unsafe fn new(address: usize, patch: &str) -> Result<Patcher> {
        if !can_read_ptr(address) {
            return Err(MemoryError::WritePtrError(address));
        }
        // Define byte vectors
        let mut initial_mem = vec![];
        let mut transformed_mem = vec![];

        // For each byte litteral in string, push it to transformed_mem.
        for byte in patch.split(" ") {
            let byte = hex::decode(byte)?[0];
            transformed_mem.push(byte);
        }

        // For each byte in memory to replace, copy it to initial_mem.
        for i in 0..transformed_mem.len() as usize {
            initial_mem.push(read_ptr(address + i)?);
        }
        return Ok(Patcher {
            address,
            initial_mem,
            transformed_mem,
        });
    }
    pub unsafe fn patch(&self) -> Result<()> {
        if self.initial_mem.len() != self.transformed_mem.len() {
            return Err(MemoryError::PatchError(self.address));
        }
        for i in 0..self.transformed_mem.len() {
            write_ptr(self.address + i, self.transformed_mem[i], true)?;
        }
        Ok(())
    }
    pub unsafe fn restore(&self) -> Result<()> {
        if self.initial_mem.len() != self.transformed_mem.len() {
            return Err(MemoryError::PatchError(self.address));
        }
        for i in 0..self.initial_mem.len() {
            write_ptr(self.address + i, self.initial_mem[i], true)?;
        }
        Ok(())
    }
}
