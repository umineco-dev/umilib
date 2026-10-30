use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;

use super::Service;

/// The boxed future of a [`DynService`].
pub type ServiceFuture<'a, Response, Error> = Pin<Box<dyn Future<Output = Result<Response, Error>> + Send + 'a>>;

/// A [`Service`] whose type is hidden behind `dyn`: every service that is
/// `Send` and `Sync` is one, and its futures are boxed.
pub trait DynService<Request>: Send + Sync {
    type Response;
    type Error;

    fn call_boxed<'a>(&'a self, request: Request) -> ServiceFuture<'a, Self::Response, Self::Error>
    where
        Request: 'a;
}

impl<Request, S> DynService<Request> for S
where
    S: Service<Request> + Send + Sync,
{
    type Response = S::Response;
    type Error = S::Error;

    fn call_boxed<'a>(&'a self, request: Request) -> ServiceFuture<'a, S::Response, S::Error>
    where
        Request: 'a,
    {
        Box::pin(self.call(request))
    }
}

/// A service of any type that answers `Request` with `Response` or `Error`,
/// for routes whose services differ.
pub struct BoxService<Request, Response, Error> {
    service: Box<dyn DynService<Request, Response = Response, Error = Error>>,
}

impl<Request, Response, Error> BoxService<Request, Response, Error> {
    pub fn new<S>(service: S) -> BoxService<Request, Response, Error>
    where
        S: Service<Request, Response = Response, Error = Error> + Send + Sync + 'static,
    {
        BoxService { service: Box::new(service) }
    }
}

impl<Request, Response, Error> Service<Request> for BoxService<Request, Response, Error> {
    type Response = Response;
    type Error = Error;

    fn call(&self, request: Request) -> impl Future<Output = Result<Response, Error>> + Send {
        self.service.call_boxed(request)
    }
}

impl<Request, Response, Error> core::fmt::Debug for BoxService<Request, Response, Error> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BoxService")
    }
}
