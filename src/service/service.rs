use alloc::boxed::Box;
use alloc::sync::Arc;
use core::future::Future;

/// Something that answers requests of type `Request`.
///
/// A service is shared (`&self`) by the connections that call it, and its
/// futures are `Send`, so that servers may run calls on a thread pool. An
/// implementation may write `async fn call`.
pub trait Service<Request> {
    type Response;
    type Error;

    /// Answers `request`.
    fn call(&self, request: Request) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send;
}

impl<Request, S: Service<Request> + ?Sized> Service<Request> for &S {
    type Response = S::Response;
    type Error = S::Error;

    fn call(&self, request: Request) -> impl Future<Output = Result<S::Response, S::Error>> + Send {
        (**self).call(request)
    }
}

impl<Request, S: Service<Request> + ?Sized> Service<Request> for Box<S> {
    type Response = S::Response;
    type Error = S::Error;

    fn call(&self, request: Request) -> impl Future<Output = Result<S::Response, S::Error>> + Send {
        (**self).call(request)
    }
}

impl<Request, S: Service<Request> + ?Sized> Service<Request> for Arc<S> {
    type Response = S::Response;
    type Error = S::Error;

    fn call(&self, request: Request) -> impl Future<Output = Result<S::Response, S::Error>> + Send {
        (**self).call(request)
    }
}
