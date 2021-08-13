use std::ffi::c_void;
use std::mem;
use std::path::Path;

use nix::errno;

use crate::*;

pub fn bpf_obj_get<P: AsRef<Path>>(path: P) -> Result<i32> {
    let path = util::path_to_cstring(path)?;
    let fd = unsafe { libbpf_sys::bpf_obj_get(path.as_ptr()) };
    if fd < 0 {
        return Err(Error::System(errno::errno()));
    }
    Ok(fd)
}

pub fn bpf_obj_get_info_by_fd<T>(fd: i32) -> Result<T> {
    // We need to use std::mem::zeroed() instead of just using
    // ::default() because padding bytes need to be zero as well.
    // Old kernels which know about fewer fields than we do will
    // check to make sure every byte past what they know is zero
    // and will return E2BIG otherwise.
    let mut info: T = unsafe { std::mem::zeroed() };
    let info_ptr = &mut info as *mut T;
    let mut len = mem::size_of::<T>() as u32;
    let rc = unsafe { libbpf_sys::bpf_obj_get_info_by_fd(fd, info_ptr as *mut c_void, &mut len) };
    if rc != 0 {
        return Err(Error::System(-rc));
    }
    Ok(info)
}
