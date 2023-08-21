//! Defines ioctl commands used in this library

// Note: RS stands for raminspect here
const RS_MAGIC: u8 = 123;
use crate::ffi::SearchOperation;
use crate::ffi::InspectorRequest;

use nix::ioctl_write_ptr;
use nix::ioctl_readwrite;
ioctl_readwrite!(conduct_search, RS_MAGIC, 1, SearchOperation);
ioctl_write_ptr!(send_inspector_request, RS_MAGIC, 0, InspectorRequest);