// Copyright (C) Internet Systems Consortium, Inc. ("ISC")
// SPDX-License-Identifier: MPL-2.0

// Keep a single Rust staticlib so the runtime is linked exactly once.
#[path = "rust-hashmap.rs"]
mod rust_hashmap;
