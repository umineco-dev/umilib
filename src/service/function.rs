use core::future::Future;

use super::Service;

/// A service of a function from a request to a future of the result.
#[derive(Clone, Copy, Debug)]
pub struct FunctionService<F> {
    function: F,
}

impl<F> FunctionService<F> {
    pub const fn new(function: F) -> FunctionService<F> {
        FunctionService { function }
    }

    pub fn function(&self) -> &F {
        &self.function
    }
}

impl<Request, Response, Error, F, Fut> Service<Request> for FunctionService<F>
where
    F: Fn(Request) -> Fut,
    Fut: Future<Output = Result<Response, Error>> + Send,
{
    type Response = Response;
    type Error = Error;

    fn call(&self, request: Request) -> impl Future<Output = Result<Response, Error>> + Send {
        (self.function)(request)
    }
}
