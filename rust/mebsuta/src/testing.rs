//! Shared test utilities for handler implementations.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::error::Error;
use crate::handler::Handler;
use crate::record::Context;
use crate::value::{Key, Value};

/// A minimal handler for testing that counts `handle()` calls and captures
/// the attributes of the last record.
#[derive(Clone)]
pub struct Mock {
    count: Arc<AtomicUsize>,
    last_attrs: Arc<Mutex<Vec<(Key, Value)>>>,
}

impl Mock {
    pub fn new() -> Self {
        Mock {
            count: Arc::new(AtomicUsize::new(0)),
            last_attrs: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn count(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    pub fn last_attrs(&self) -> Vec<(Key, Value)> {
        self.last_attrs.lock().unwrap().clone()
    }
}

impl Handler for Mock {
    fn enabled(&self, _ctx: &Context<'_>) -> bool {
        true
    }

    fn handle(&self, record: &std::sync::Arc<crate::record::OwnedRecord>) -> Result<(), Error> {
        self.count.fetch_add(1, Ordering::Relaxed);
        *self.last_attrs.lock().unwrap() = record.attrs.clone();
        Ok(())
    }

    fn clone_box(&self) -> Box<dyn Handler> {
        Box::new(self.clone())
    }

    fn set_error_handler(&self, _: Option<Box<dyn Fn(&str, &Error) + Send + Sync>>) {}
}
