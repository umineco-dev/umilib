//! The C ABI of [`crate::service`].
//!
//! C has no futures, so a service is a callback that answers at once:
//! `call(context, request, length, response)` writes the answer with
//! `umilib_service_response_write` and returns true, or returns false if it
//! failed; `drop(context)` (may be null) is called once when the service is
//! dropped. A router of [`Pattern`] rules to such services is called with
//! `umilib_service_router_call`, on the calling thread. As every object of
//! the C ABI, a router is used by one thread at a time, and a service must
//! not change or release the router that calls it.

use alloc::vec::Vec;
use core::ffi::c_void;
use core::future::Future;

use crate::ffi::{Buffer, Definition, Module, Parameter, Pointer, Status, ToStatus, Type, Value};
use crate::service::{Pattern, PatternError, Router, Service};

/// The statuses of this module.
pub struct ServiceStatus;

impl ServiceStatus {
    pub const MISPLACED_WILDCARD: Status =
        Status::new(c"service", c"MisplacedWildcard", c"a `*` is only allowed as the first or the last byte");
    pub const UNFINISHED_ESCAPE: Status =
        Status::new(c"service", c"UnfinishedEscape", c"a `\\` at the end escapes nothing");
    pub const UNROUTED: Status = Status::new(c"service", c"Unrouted", c"no route matches the request");
    pub const FAILED: Status = Status::new(c"service", c"Failed", c"the service of the route failed");
}

impl ToStatus for PatternError {
    fn to_status(&self) -> &'static Status {
        match *self {
            PatternError::MisplacedWildcard => &ServiceStatus::MISPLACED_WILDCARD,
            PatternError::UnfinishedEscape => &ServiceStatus::UNFINISHED_ESCAPE,
        }
    }
}

/// The answer a service callback writes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Response {
    pub bytes: Vec<u8>,
}

/// The call callback of a service:
/// `bool call(void* context, const uint8_t* request, size_t length, umilib_service_Response* response)`.
pub type ServiceCall = Option<
    unsafe extern "C" fn(context: *mut c_void, request: *const u8, length: usize, response: *mut Response) -> bool,
>;

/// The drop callback of a service: `void drop(void* context)`.
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct ServiceDrop(pub Option<unsafe extern "C" fn(context: *mut c_void)>);

/// A service of C callbacks.
pub struct CallbackService {
    call:
        unsafe extern "C" fn(context: *mut c_void, request: *const u8, length: usize, response: *mut Response) -> bool,
    drop: ServiceDrop,
    context: *mut c_void,
}

// SAFETY: the caller of `CallbackService::new` promises that the context may
// be used from the threads that use the service, one at a time.
unsafe impl Send for CallbackService {}
// SAFETY: as above.
unsafe impl Sync for CallbackService {}

impl CallbackService {
    /// The service of `call`, `drop` and `context`.
    ///
    /// # Safety
    /// `call` and `drop` may be called with `context` (from the threads that
    /// use the router or the service, one at a time) until the drop
    /// callback is called, once; the caller keeps them valid until then.
    pub unsafe fn new(
        call: unsafe extern "C" fn(
            context: *mut c_void,
            request: *const u8,
            length: usize,
            response: *mut Response,
        ) -> bool,
        drop: ServiceDrop,
        context: *mut c_void,
    ) -> CallbackService {
        CallbackService { call, drop, context }
    }

    /// Calls the callback with `request`; its answer, or `None` if it failed.
    pub fn answer(&self, request: &[u8]) -> Option<Vec<u8>> {
        let mut response = Response::default();
        // SAFETY: the callback and its context are the caller's, valid until the drop callback;
        // the request and the response live during the call.
        let succeeded = unsafe { (self.call)(self.context, request.as_ptr(), request.len(), &mut response) };
        succeeded.then_some(response.bytes)
    }
}

impl Service<Vec<u8>> for CallbackService {
    type Response = Vec<u8>;
    type Error = ();

    fn call(&self, request: Vec<u8>) -> impl Future<Output = Result<Vec<u8>, ()>> + Send {
        core::future::ready(self.answer(&request).ok_or(()))
    }
}

impl Drop for CallbackService {
    fn drop(&mut self) {
        if let ServiceDrop(Some(drop)) = self.drop {
            // SAFETY: as above; the drop callback is called once.
            unsafe { drop(self.context) }
        }
    }
}

/// The router of the C ABI: patterns of the request's bytes to callback services.
pub type CallbackRouter = Router<Pattern, CallbackService>;

impl Value for Pattern {
    const TYPE: Type = Type::Named("umilib_service_Pattern");
}

impl Value for CallbackRouter {
    const TYPE: Type = Type::Named("umilib_service_Router");
}

impl Value for Response {
    const TYPE: Type = Type::Named("umilib_service_Response");
}

impl Value for ServiceCall {
    const TYPE: Type = Type::Named("umilib_service_ServiceCall");
}

impl Value for ServiceDrop {
    const TYPE: Type = Type::Named("umilib_service_ServiceDrop");
}

crate::ffi_functions! {
    const FUNCTIONS;

    /// Writes the pattern of the `length` bytes of text at `text` into `out` (case not ignored);
    /// fails with `MisplacedWildcard` or `UnfinishedEscape`.
    pub unsafe extern "C" fn umilib_service_pattern_parse(text: *const u8, length: usize, out: *mut *mut Pattern) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let text = unsafe { Pointer::slice(text, length) }?;
            Pointer::check_range(out, 1)?;
            let pattern = Pattern::parse(text).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, pattern) }
        })())
    }

    /// Releases a pattern. Does nothing if `pattern` is null.
    pub unsafe extern "C" fn umilib_service_pattern_free(pattern: *mut Pattern) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(pattern) }
    }

    /// Writes the text of the pattern into `out`.
    pub unsafe extern "C" fn umilib_service_pattern_format(pattern: *const Pattern, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let pattern = unsafe { Pointer::reference(pattern) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(pattern.format())) }
        })())
    }

    /// Writes a copy of the pattern that ignores the case of ASCII letters if `ignore` is true into `out`.
    pub unsafe extern "C" fn umilib_service_pattern_ignoring_ascii_case(pattern: *const Pattern, ignore: bool, out: *mut *mut Pattern) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let pattern = unsafe { Pointer::reference(pattern) }?;
            unsafe { Pointer::write_handle(out, pattern.clone().ignoring_ascii_case(ignore)) }
        })())
    }

    /// Writes whether the pattern ignores the case of ASCII letters into `out`.
    pub unsafe extern "C" fn umilib_service_pattern_ignores_ascii_case(pattern: *const Pattern, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let pattern = unsafe { Pointer::reference(pattern) }?;
            unsafe { Pointer::write(out, pattern.ignores_ascii_case()) }
        })())
    }

    /// Writes whether the `length` bytes at `data` match the pattern into `out`.
    pub unsafe extern "C" fn umilib_service_pattern_matches_bytes(pattern: *const Pattern, data: *const u8, length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and a writable pointer.
            let pattern = unsafe { Pointer::reference(pattern) }?;
            let data = unsafe { Pointer::slice(data, length) }?;
            unsafe { Pointer::write(out, pattern.matches_bytes(data)) }
        })())
    }

    /// Appends the `length` bytes at `data` to the answer of a service callback.
    pub unsafe extern "C" fn umilib_service_response_write(response: *mut Response, data: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes the response given to its callback and readable bytes.
            let response = unsafe { Pointer::reference_mut(response) }?;
            let data = unsafe { Pointer::slice(data, length) }?;
            response.bytes.extend_from_slice(data);
            Ok(())
        })())
    }

    /// Writes a new router without routes into `out`.
    pub unsafe extern "C" fn umilib_service_router_new(out: *mut *mut CallbackRouter) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, CallbackRouter::new()) })
    }

    /// Releases a router; the drop callbacks of its services are called. Does nothing if `router`
    /// is null. Not during a call of the router (from one of its services).
    pub unsafe extern "C" fn umilib_service_router_free(router: *mut CallbackRouter) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(router) }
    }

    /// Adds a route of (a copy of) `pattern` to the service of `call`, `drop` (may be null) and
    /// `context` after the routes. The router owns the service from then on; if this function
    /// fails, the service is not added and the caller keeps its context (`drop` is not called).
    /// Not during a call of the router (from one of its services).
    pub unsafe extern "C" fn umilib_service_router_push(router: *mut CallbackRouter, pattern: *const Pattern, call: ServiceCall, drop: ServiceDrop, context: *mut c_void) -> *const Status {
        Status::from_result((|| {
            let call = call.ok_or(&Status::INVALID_ARGUMENT)?;
            // SAFETY: the caller passes valid handles.
            let pattern = unsafe { Pointer::reference(pattern) }?.clone();
            let router = unsafe { Pointer::reference_mut(router) }?;
            // SAFETY: the caller of this function promises what `CallbackService::new` requires.
            router.push(pattern, unsafe { CallbackService::new(call, drop, context) });
            Ok(())
        })())
    }

    /// Sets the service of the requests no route matches to that of `call`, `drop` and `context`;
    /// with a null `call`, removes it (`drop` and `context` are then ignored). The drop callback of
    /// a service replaced is called. If this function fails, nothing changes and the caller keeps
    /// its context. Not during a call of the router (from one of its services).
    pub unsafe extern "C" fn umilib_service_router_set_fallback(router: *mut CallbackRouter, call: ServiceCall, drop: ServiceDrop, context: *mut c_void) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let router = unsafe { Pointer::reference_mut(router) }?;
            // SAFETY: the caller of this function promises what `CallbackService::new` requires.
            router.set_fallback(call.map(|call| unsafe { CallbackService::new(call, drop, context) }));
            Ok(())
        })())
    }

    /// Writes the routes of the router into `out`.
    pub unsafe extern "C" fn umilib_service_router_len(router: *const CallbackRouter, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let router = unsafe { Pointer::reference(router) }?;
            unsafe { Pointer::write(out, router.routes().len()) }
        })())
    }

    /// Gives the `length` bytes at `data` to the service of the first route whose pattern matches
    /// them (or the fallback) and writes its answer into `out`; fails with `Unrouted` if there is
    /// none, and `Failed` if the service failed. The router must not be changed or released
    /// until the call returns, by its services either.
    pub unsafe extern "C" fn umilib_service_router_call(router: *const CallbackRouter, data: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and a writable buffer.
            let router = unsafe { Pointer::reference(router) }?;
            let request = unsafe { Pointer::slice(data, length) }?;
            Pointer::check_range(out, 1)?;
            let service = router.find(&request).ok_or(&ServiceStatus::UNROUTED)?;
            let answer = service.answer(request).ok_or(&ServiceStatus::FAILED)?;
            unsafe { Pointer::write(out, Buffer::from_vec(answer)) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "service",
    definitions: &[
        Definition::Opaque {
            name: "umilib_service_Pattern",
            documentation: " A pattern of bytes: any, exact, prefix or suffix.",
        },
        Definition::Opaque {
            name: "umilib_service_Response",
            documentation: " The answer a service callback writes with `umilib_service_response_write`.",
        },
        Definition::Callback {
            name: "umilib_service_ServiceCall",
            documentation: " The call callback of a service: writes the answer to the request and returns true, or false if it failed.",
            parameters: &[
                Parameter { name: "context", value: <*mut c_void as Value>::TYPE },
                Parameter { name: "request", value: <*const u8 as Value>::TYPE },
                Parameter { name: "length", value: <usize as Value>::TYPE },
                Parameter { name: "response", value: <*mut Response as Value>::TYPE },
            ],
            returns: Type::Bool,
        },
        Definition::Callback {
            name: "umilib_service_ServiceDrop",
            documentation: " The drop callback of a service, called once when it is dropped.",
            parameters: &[Parameter { name: "context", value: <*mut c_void as Value>::TYPE }],
            returns: Type::Void,
        },
        Definition::Opaque {
            name: "umilib_service_Router",
            documentation: " A router of patterns of the request's bytes to callback services.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
