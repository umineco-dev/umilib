use alloc::vec::Vec;
use core::future::Future;

use super::{Rule, Service};

/// A route of a [`Router`]: the requests its rule matches go to its service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route<R, S> {
    pub rule: R,
    pub service: S,
}

/// The error of a [`Router`]: no route matched (the request is given
/// back), or the service of the route failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteError<Request, E> {
    Unrouted(Request),
    Service(E),
}

impl<Request, E: core::fmt::Display> core::fmt::Display for RouteError<Request, E> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RouteError::Unrouted(_) => formatter.write_str("no route matches the request"),
            RouteError::Service(error) => write!(formatter, "the service of the route failed: {error}"),
        }
    }
}

impl<Request: core::fmt::Debug, E: core::error::Error + 'static> core::error::Error for RouteError<Request, E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            RouteError::Unrouted(_) => None,
            RouteError::Service(error) => Some(error),
        }
    }
}

/// A service that gives each request to the service of the first route
/// (in the order they were added) whose rule matches it, or to its
/// fallback if none does; without a fallback, the request is given back in
/// [`RouteError::Unrouted`]. Routes of different services use a
/// [`BoxService`](super::BoxService) or an enum; routes of different rules,
/// a `Box<dyn Rule>` or an enum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Router<R, S> {
    routes: Vec<Route<R, S>>,
    fallback: Option<S>,
}

impl<R, S> Router<R, S> {
    pub const fn new() -> Router<R, S> {
        Router { routes: Vec::new(), fallback: None }
    }

    /// The router with a route of `rule` to `service` after its routes.
    pub fn route(mut self, rule: R, service: S) -> Router<R, S> {
        self.push(rule, service);
        self
    }

    /// Adds a route of `rule` to `service` after the routes.
    pub fn push(&mut self, rule: R, service: S) {
        self.routes.push(Route { rule, service });
    }

    /// The router with `service` for the requests no route matches.
    pub fn with_fallback(mut self, service: S) -> Router<R, S> {
        self.fallback = Some(service);
        self
    }

    pub fn set_fallback(&mut self, service: Option<S>) {
        self.fallback = service;
    }

    pub fn routes(&self) -> &[Route<R, S>] {
        &self.routes
    }

    pub fn routes_mut(&mut self) -> &mut Vec<Route<R, S>> {
        &mut self.routes
    }

    pub fn fallback(&self) -> Option<&S> {
        self.fallback.as_ref()
    }

    /// The service `request` goes to: that of the first route whose rule matches, or the fallback.
    pub fn find<Request>(&self, request: &Request) -> Option<&S>
    where
        R: Rule<Request>,
    {
        let route = self.routes.iter().find(|route| route.rule.matches(request));
        route.map(|route| &route.service).or(self.fallback.as_ref())
    }
}

impl<R, S> Default for Router<R, S> {
    fn default() -> Router<R, S> {
        Router::new()
    }
}

impl<Request, R, S> Service<Request> for Router<R, S>
where
    Request: Send,
    R: Rule<Request>,
    S: Service<Request> + Sync,
{
    type Response = S::Response;
    type Error = RouteError<Request, S::Error>;

    fn call(
        &self,
        request: Request,
    ) -> impl Future<Output = Result<S::Response, RouteError<Request, S::Error>>> + Send {
        let service = self.find(&request);
        async move {
            match service {
                Some(service) => service.call(request).await.map_err(RouteError::Service),
                None => Err(RouteError::Unrouted(request)),
            }
        }
    }
}
