//! Shared state and store for the iroh-dns-server

use std::sync::Arc;

use crate::{dns::DnsHandler, lookup::Backend, metrics::Metrics};

/// The shared app state.
#[derive(Clone)]
pub(crate) struct AppState {
    /// The pkarr DNS store
    pub backend: Backend,
    /// Handler for DNS requests
    pub dns_handler: DnsHandler,
    /// Metrics collector.
    pub metrics: Arc<Metrics>,
}
