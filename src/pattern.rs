use super::memory::read_ptr;
use super::MemoryError;
use super::Result;

use log::debug;
use log::trace;
use regex::bytes::Regex;

/*
    Action represent an offset:
      ?? => Ignore offset
      _  => Offset
*/

/// Action is an enum wich define to types of actions for a pattern:
///    * `Ignore` => The byte analyzed will always be true
///    * `Offset(u8)` => The byte analyzed will have to match the given one
///
/// This enum should not be used for basic patterns, as it is build by the Pattern struct
///
/// Example
/// ```rust
///    use memory_rs::pattern::Action;
///    let action = Action::Ignore;
///    let action_from = Action::from("??");
///    let action = Action::from("2F");
///    let action = Action::Offset(0x2F);
/// ```
#[derive(Clone, Copy, Debug)]
pub enum Action {
    Offset(u8),
    Ignore,
}
impl Action {
    /// from is a function wich return an enum typed Action given an str entry
    pub fn from(action: &str) -> Result<Self> {
        trace!("Create an action from {action}");
        use Action::*;
        let action = match action {
            "??" => Ignore,
            _ => Offset(hex::decode(action)?[0]),
        };
        Ok(action)
    }
}
impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Action::*;
        match self {
            Ignore => write!(f, "??")?,
            Offset(offset) => write!(f, "{:#04x}", offset)?,
        };
        Ok(())
    }
}

/// PatternKind is a structure wich define the Pattern type.
/// This definition permits to know were to search the value after the pattern has been found.
///
/// If the pattern points to an address, no operations is done
/// Else, the address is read from the address found by the patternfinder.
#[derive(Clone, Copy, Debug)]
pub enum PatternKind {
    Address,
    Pointer,
    DoublePointer,
    TriplePointer,
}
impl PatternKind {
    unsafe fn get_ptr(&self, address: usize, base: usize) -> Result<usize> {
        Ok(base + read_ptr::<usize>(address)?)
    }
    unsafe fn transform(&self, address: usize, base: Option<usize>) -> Result<usize> {
        /*
            Specify a base address when transforming data
            Useful when manipulating a data dump with pointers
        */
        let base = base.unwrap_or(0);
        use PatternKind::*;
        match self {
            Address => Ok(address),
            Pointer => self.get_ptr(address, base),
            DoublePointer => {
                let mut addr = address;
                for _ in 0..2 {
                    addr = self.get_ptr(addr, base)?;
                }
                Ok(addr)
            }
            TriplePointer => {
                let mut addr = address;
                for _ in 0..3 {
                    addr = self.get_ptr(addr, base)?;
                }
                Ok(addr)
            }
        }
    }
}

/// Pattern is the structure used to define a pattern, wich will be used to get an address from a pattern.
///
/// Example
/// ```rust
/// use memory_rs::pattern::{PatternKind, Pattern};
/// let pattern = Pattern::new(
///     "?? 32 24 1D ?? ??",
///     PatternKind::Address,
///     None,
/// ).unwrap();
/// ```
#[derive(Clone, Debug)]
pub struct Pattern {
    pub kind: PatternKind,
    pub shift: usize,
    pub offsets: Vec<Action>,
}
impl Pattern {
    pub fn new(pattern: &str, kind: PatternKind, shift: Option<usize>) -> Result<Self> {
        trace!("Create a new pattern structure");
        let shift = shift.unwrap_or(0);
        let offsets: Vec<Action> = pattern
            .split(' ')
            .map(Action::from)
            .collect::<Result<Vec<Action>>>()?;
        Ok(Pattern {
            kind,
            shift,
            offsets,
        })
    }

    fn build_regexp(&self) -> Result<Regex> {
        let mut regexp = self
            .offsets
            .iter()
            .map(|x| match x {
                Action::Ignore => format!("."),
                Action::Offset(offset) => format!("\\x{:02x}", offset),
            })
            .collect::<Vec<_>>()
            .join("");
        debug!("{}", regexp);
        regexp.insert_str(0, "(?s-u)");
        Ok(Regex::new(&regexp)?)
    }

    pub fn find(&self, base: Option<usize>, size: Option<usize>) -> Result<usize> {
        trace!("Trying to find address for pattern {}", self);
        let base = base.unwrap_or(0x400000);
        let size = size.unwrap_or(0x400000);
        let regexp = self.build_regexp()?;
        let data = unsafe { std::slice::from_raw_parts::<u8>(base as *const _, size) };
        let address = match regexp.find(data) {
            None => return Err(MemoryError::PatternNotFound(format!("{}", self))),
            Some(matches) => matches.start() + base,
        };
        unsafe { self.kind.transform(address + self.shift, None) }
    }
}

impl std::fmt::Display for Pattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for action in &self.offsets {
            write!(f, "{} ", action)?
        }
        Ok(())
    }
}
