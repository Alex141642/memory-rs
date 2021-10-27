use super::Result;
use super::MemoryError;
use super::memory::read_ptr;

use log::{trace};

/*
    Action represent an offset:
      ?? => Ignore offset
      _  => Offset
*/
#[derive(Clone, Copy, Debug)]
pub enum Action {
    Offset(u8),
    Ignore,
}
impl Action {
    pub fn from(action: &str) -> Result<Self> {
        trace!("Create an action from {}", action);
        use Action::*;
        let action = match action {
            "??" => Ignore,
            _    => Offset(
                hex::decode(action)?[0]
            )
        };
        Ok(action)
    }
}
impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Action::*;
        match self {
            Ignore => write!(f, "??")?,
            Offset(offset) => write!(f, "{:#04x}", offset)?
        };
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub enum PatternKind {
    Address,
    Pointer,
    DoublePointer,
    TriplePointer,
}
impl PatternKind {
    pub fn transform(&self, address: usize, base: Option<usize>) -> Result<usize> {
        /*
            Specify a base address when transforming data
            Useful when manipulating a data dump with pointers
        */
        let base = match base {
            Some(base) => base,
            None => 0,
        };
        use PatternKind::*;
        match self {
            Address => Ok(address),
            Pointer => {
                let address = base + read_ptr::<usize>(address)?;
                Ok(address)
            }
            DoublePointer => {
                let mut address = base + read_ptr::<usize>(address)?;
                address = base + read_ptr::<usize>(address)?;
                Ok(address)
            }
            TriplePointer => {
                let mut address = base + read_ptr::<usize>(address)?;
                address = base + read_ptr::<usize>(address)?;
                address = base + read_ptr::<usize>(address)?;
                Ok(address)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct  Pattern {
    pub kind: PatternKind,
    pub shift: usize,
    pub offsets: Vec<Action>,
}
impl Pattern {
    pub fn new(pattern: &str, kind: PatternKind, shift: Option<usize>) -> Result<Self> {
        trace!("Create a new pattern structure");
        let mut offsets= Vec::new();
        let shift = match shift {
            Some(shift) => shift,
            None => 0
        };
        for offset in pattern.split(" "){
            let action = Action::from(offset)?;
            offsets.push(action);
        }
        Ok(Pattern {kind, shift, offsets})
    }

    pub fn find(&self, base: Option<usize>) -> Result<usize> {
        use Action::*;
        trace!("Trying to find address for pattern {}", self);
        let pattern_len = self.offsets.len();
        let base = match base {
            Some(base) => base,
            None => 0x400000,
        };
        let end = base * 2 - pattern_len;
        for address in 0..(end - base){
            let mut i = 0;
            for step in self.clone().offsets {
                let addr = base + address + i;
                match step {
                    Ignore => trace!("Address {:#04x}: skipping", addr),
                    Offset(offset) => {
                        trace!("Address {:#04x}: checking", addr);
                        let value = match read_ptr::<u8>(addr){
                            Ok(value) => value,
                            Err(err) => {
                                trace!("Address {:#04x}: error", addr);
                                break;
                            }
                        };
                        if value != offset {
                            trace!("Address {:#04x}: offset does not match", addr);
                            break;
                        }
                    }
                }
                if i == pattern_len - 1 {
                    trace!("Address {:#04x}: found pattern", addr);
                    return Ok(self.kind.transform(addr + self.shift, Some(base))?);
                }
                i += 1;
            }
        }
        Err(MemoryError::PatternNotFound(format!("{}", self)))
    }
}
impl std::fmt::Display for Pattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for action in self.clone().offsets {
            write!(f, "{} ", action)?
        };
        Ok(())
    }
}
