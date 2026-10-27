//! Byte counts belong to one streaming phase, not to a fabricated time estimate.
//! An unknown total (KDF, publication, damaged compressed recovery) stays unknown.
use crate::{CancellationToken, Error, Result};
use serde::Serialize;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProgressPhase {
    #[default]
    Preparing,
    KeyDerivation,
    Encrypting,
    Authenticating,
    Decrypting,
    Splitting,
    Reassembling,
    Wrapping,
    Unwrapping,
    Recovering,
    Publishing,
    Complete,
    Failed,
    Cancelled,
    KeyStorage,
    Revoking,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ByteProgress {
    pub phase: ProgressPhase,
    /// Bytes consumed from this phase's logical input stream.
    pub processed_bytes: u64,
    pub total_bytes: Option<u64>,
}

pub struct OperationControl<'a> {
    cancellation: &'a CancellationToken,
    on_progress: &'a mut dyn FnMut(ByteProgress),
}

impl<'a> OperationControl<'a> {
    pub fn new(
        cancellation: &'a CancellationToken,
        on_progress: &'a mut dyn FnMut(ByteProgress),
    ) -> Self {
        Self {
            cancellation,
            on_progress,
        }
    }
}

#[derive(Default)]
pub(crate) struct Tracker<'a> {
    callback: Option<&'a mut dyn FnMut(ByteProgress)>,
    current: ByteProgress,
    cancellation: Option<CancellationToken>,
}

impl Tracker<'_> {
    pub fn begin(&mut self, phase: ProgressPhase, total_bytes: Option<u64>) -> Result<()> {
        self.current = ByteProgress {
            phase,
            processed_bytes: 0,
            total_bytes,
        };
        self.emit();
        self.checkpoint()
    }

    pub fn advance(&mut self, bytes: u64) -> Result<()> {
        if bytes == 0 {
            return self.checkpoint();
        }
        self.current.processed_bytes = self.current.processed_bytes.saturating_add(bytes);
        self.emit();
        self.checkpoint()
    }

    pub fn checkpoint(&self) -> Result<()> {
        match &self.cancellation {
            Some(token) => token.check(),
            None => Ok(()),
        }
    }

    pub fn checkpoint_io(&self) -> std::io::Result<()> {
        match &self.cancellation {
            Some(token) => token.check_io(),
            None => Ok(()),
        }
    }

    pub fn cancellation_token(&self) -> Option<CancellationToken> {
        self.cancellation.clone()
    }

    fn emit(&mut self) {
        if let Some(callback) = &mut self.callback {
            callback(self.current);
        }
    }
}

pub(crate) fn observe<T>(
    callback: &mut dyn FnMut(ByteProgress),
    operation: impl FnOnce(&mut Tracker<'_>) -> Result<T>,
) -> Result<T> {
    observe_inner(callback, None, operation)
}

pub(crate) fn observe_control<T>(
    control: &mut OperationControl<'_>,
    operation: impl FnOnce(&mut Tracker<'_>) -> Result<T>,
) -> Result<T> {
    observe_inner(
        control.on_progress,
        Some(control.cancellation.clone()),
        operation,
    )
}

fn observe_inner<T>(
    callback: &mut dyn FnMut(ByteProgress),
    cancellation: Option<CancellationToken>,
    operation: impl FnOnce(&mut Tracker<'_>) -> Result<T>,
) -> Result<T> {
    let mut tracker = Tracker {
        callback: Some(callback),
        current: ByteProgress::default(),
        cancellation,
    };
    let result = tracker
        .begin(ProgressPhase::Preparing, None)
        .and_then(|_| operation(&mut tracker));
    // Publication is the commit point. A late request must not turn a fully
    // committed result into an error, nor cause that result to be deleted.
    tracker.current = ByteProgress {
        phase: match &result {
            Ok(_) => ProgressPhase::Complete,
            Err(Error::Cancelled) => ProgressPhase::Cancelled,
            Err(_) => ProgressPhase::Failed,
        },
        ..ByteProgress::default()
    };
    tracker.emit();
    result
}

#[cfg(test)]
mod tests;
