//! The Promptwall policy engine: the policy format and the checks it
//! configures, with no async runtime or network I/O. The proxy (crate
//! `promptwall`) serves it over HTTP; `promptwall-wasm` compiles it to
//! WebAssembly for the npm package, so both apply the same rules.

pub mod attachments;
pub mod inspect;
pub mod limits;
pub mod moderation;
pub mod ner;
pub mod policy;
pub mod text;
pub mod tools;

pub use policy::{Action, Policy};
pub use text::{Sample, Verdict};
