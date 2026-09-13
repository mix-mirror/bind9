// Copyright (C) Internet Systems Consortium, Inc. ("ISC")
// SPDX-License-Identifier: MPL-2.0

use std::collections::HashMap;
use std::ffi::{c_char, c_uint, c_void, CStr};

pub struct IscRustHashmap {
    inner: HashMap<(Vec<u8>, c_uint), *mut c_void>,
    case_sensitive: bool,
}

impl IscRustHashmap {
    unsafe fn key(&self, key: *const c_char, kind: c_uint) -> (Vec<u8>, c_uint) {
        let mut bytes = unsafe { CStr::from_ptr(key) }.to_bytes().to_vec();
        if !self.case_sensitive {
            bytes.make_ascii_lowercase();
        }
        (bytes, kind)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn isc_rust_hashmap_new(case_sensitive: bool) -> *mut IscRustHashmap {
    Box::into_raw(Box::new(IscRustHashmap {
        inner: HashMap::with_capacity(16),
        case_sensitive,
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn isc_rust_hashmap_free(map: *mut IscRustHashmap) {
    unsafe { drop(Box::from_raw(map)) };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn isc_rust_hashmap_get(
    map: *const IscRustHashmap,
    key: *const c_char,
    kind: c_uint,
) -> *mut c_void {
    let map = unsafe { &*map };
    map.inner.get(&unsafe { map.key(key, kind) }).copied().unwrap_or(std::ptr::null_mut())
}

// Insert only if absent; return the existing value, or NULL on insertion.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn isc_rust_hashmap_insert(
    map: *mut IscRustHashmap,
    key: *const c_char,
    kind: c_uint,
    value: *mut c_void,
) -> *mut c_void {
    let map = unsafe { &mut *map };
    let key = unsafe { map.key(key, kind) };
    match map.inner.entry(key) {
        std::collections::hash_map::Entry::Occupied(entry) => *entry.get(),
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert(value);
            std::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn isc_rust_hashmap_remove(
    map: *mut IscRustHashmap,
    key: *const c_char,
    kind: c_uint,
) -> *mut c_void {
    let map = unsafe { &mut *map };
    let key = unsafe { map.key(key, kind) };
    map.inner.remove(&key).unwrap_or(std::ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn isc_rust_hashmap_len(map: *const IscRustHashmap) -> usize {
    unsafe { &*map }.inner.len()
}

// The callback returns true to remove an entry and may free its value.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn isc_rust_hashmap_foreach(
    map: *mut IscRustHashmap,
    action: unsafe extern "C" fn(*mut c_void, *mut c_void) -> bool,
    arg: *mut c_void,
) {
    unsafe { &mut *map }.inner.retain(|_, value| !unsafe { action(*value, arg) });
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn remove(value: *mut c_void, arg: *mut c_void) -> bool {
        value == arg
    }

    #[test]
    fn map_contract() {
        unsafe {
            for sensitive in [false, true] {
                let map = isc_rust_hashmap_new(sensitive);
                let mut a = 1u8;
                let mut b = 2u8;
                let a = (&mut a as *mut u8).cast();
                let b = (&mut b as *mut u8).cast();
                let upper = c"Key".as_ptr();
                let lower = c"key".as_ptr();
                assert!(isc_rust_hashmap_insert(map, upper, 1, a).is_null());
                assert_eq!(isc_rust_hashmap_insert(map, upper, 1, b), a);
                assert_eq!(isc_rust_hashmap_get(map, upper, 1), a);
                assert_eq!(isc_rust_hashmap_get(map, lower, 1).is_null(), sensitive);
                assert!(isc_rust_hashmap_insert(map, upper, 2, b).is_null());
                assert_eq!(isc_rust_hashmap_len(map), 2);
                isc_rust_hashmap_foreach(map, remove, a);
                assert_eq!(isc_rust_hashmap_len(map), 1);
                assert_eq!(isc_rust_hashmap_remove(map, upper, 2), b);
                assert!(isc_rust_hashmap_remove(map, upper, 2).is_null());
                isc_rust_hashmap_free(map);
            }
        }
    }
}
