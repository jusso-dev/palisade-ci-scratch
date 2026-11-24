#![doc = include_str!("../README.md")]
// This crate parses untrusted files, so unchecked indexing is flagged in
// library code. Unit tests index fixtures they built themselves.
#![warn(clippy::indexing_slicing)]
#![cfg_attr(test, allow(clippy::indexing_slicing))]

pub mod authenticode;
pub mod catalog;
pub mod fsctx;
pub mod hash;
pub mod pe;
pub mod script;
#[cfg(all(windows, feature = "os-trust"))]
pub mod win;
