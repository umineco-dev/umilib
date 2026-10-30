//! Services and routers, without `std`.
//!
//! - A [`Service`] answers requests: `call(request)` is a future of
//!   `Result<Response, Error>`. [`FunctionService`] makes one of a closure;
//!   [`BoxService`] hides the type of one.
//! - A [`Rule`] says whether a request is for a route: [`Pattern`] matches
//!   bytes (exactly, by prefix or by suffix), and [`AndRule`], [`OrRule`],
//!   [`NotRule`], [`AnyRule`] and [`FunctionRule`] combine and make rules.
//! - A [`Router`] is a service that gives each request to the service of
//!   the first route whose rule matches it, or to its fallback.
//!
//! The protocols define their own rules (a host, a path, a server name)
//! and routers are services, so routers nest: a TLS router by server name
//! to an HTTP router by path to the services.

mod boxed;
mod function;
mod pattern;
mod router;
mod rule;
#[allow(clippy::module_inception)]
mod service;

pub use boxed::{BoxService, DynService, ServiceFuture};
pub use function::FunctionService;
pub use pattern::{Pattern, PatternError, PatternKind};
pub use router::{Route, RouteError, Router};
pub use rule::{AndRule, AnyRule, FunctionRule, NotRule, OrRule, Rule};
pub use service::Service;
