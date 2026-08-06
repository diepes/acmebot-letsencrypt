//! Internal support types mirroring the C# `Acmebot.Acme.Internal` namespace.
//! Not part of the public API surface, but exposed at `crate::internal` for tests.

pub mod header_parser;
pub mod nonce_store;
pub mod protocol_types;

pub use header_parser::parse_link_headers;
pub use nonce_store::AcmeNonceStore;
pub use protocol_types::*;
