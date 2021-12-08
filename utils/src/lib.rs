// This file and its contents are supplied under the terms of the
// Common Development and Distribution License ("CDDL"), version 1.0.
// You may only use this file in accordance with the terms of version
// 1.0 of the CDDL.
//
// A full copy of the text of the CDDL should have accompanied this
// source.  A copy of the CDDL is also available via the Internet at
// http://www.illumos.org/license/CDDL.

//
// Copyright 2021 Oxide Computer Company
//

use std::io::{Error, Result};
use std::os::unix::io::RawFd;
use std::ptr::{null_mut, NonNull};

use libc::{mmap, munmap, MAP_SHARED, PROT_READ};

pub struct RoMMap {
    ptr: NonNull<u8>,
    size: usize,
}

impl RoMMap {
    pub fn new(fd: RawFd, len: usize) -> Result<Self> {
        let res =
            unsafe { mmap(null_mut(), len, PROT_READ, MAP_SHARED, fd, 0) };
        if let Some(ptr) = NonNull::new(res as *mut u8) {
            Ok(Self { ptr, size: len })
        } else {
            Err(Error::last_os_error())
        }
    }

    pub fn take(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ref(), self.size) }
    }
}

impl Drop for RoMMap {
    fn drop(&mut self) {
        unsafe {
            munmap(self.ptr.as_ptr() as *mut core::ffi::c_void, self.size);
        }
    }
}
