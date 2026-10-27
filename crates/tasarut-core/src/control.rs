//! Shared cooperative cancellation. A token belongs to one operation and is never reset.
use crate::{Error, Result};
use std::{
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

#[derive(Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
    pub fn check(&self) -> Result<()> {
        if self.is_cancelled() {
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    }
    pub(crate) fn check_io(&self) -> io::Result<()> {
        if self.is_cancelled() {
            Err(cancelled_io())
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
pub(crate) struct Cancelled;
impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("operation_cancelled")
    }
}
impl std::error::Error for Cancelled {}

pub(crate) fn cancelled_io() -> io::Error {
    // Interrupted would be retried by read_exact and could loop indefinitely.
    io::Error::other(Cancelled)
}

#[cfg(test)]
mod tests;
