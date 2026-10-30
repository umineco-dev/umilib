use std::convert::Infallible;
use std::sync::Arc;

use umilib::service::{AnyRule, BoxService, FunctionRule, FunctionService, Pattern, RouteError, Router, Rule, Service};

use crate::{YieldOnce, block_on};

/// A service that answers with its name and the request.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Named(&'static str);

impl Service<String> for Named {
    type Response = String;
    type Error = Infallible;

    async fn call(&self, request: String) -> Result<String, Infallible> {
        YieldOnce::new().await;
        Ok(format!("{}:{request}", self.0))
    }
}

#[test]
fn the_first_matching_route_answers() {
    let router = Router::new()
        .route(Pattern::prefix(b"/oauth/"), Named("oauth"))
        .route(Pattern::prefix(b"/api/"), Named("api"))
        .route(Pattern::prefix(b"/api/admin/"), Named("never: an earlier route matches"));
    assert_eq!(router.routes().len(), 3);
    assert_eq!(block_on(router.call(String::from("/oauth/token"))), Ok(String::from("oauth:/oauth/token")));
    assert_eq!(block_on(router.call(String::from("/api/admin/x"))), Ok(String::from("api:/api/admin/x")));
    assert_eq!(router.find(&String::from("/api/v1")), Some(&Named("api")));
}

#[test]
fn unrouted_requests_are_given_back_or_go_to_the_fallback() {
    let mut router = Router::new().route(Pattern::exact(b"/"), Named("root"));
    assert_eq!(block_on(router.call(String::from("/missing"))), Err(RouteError::Unrouted(String::from("/missing"))));
    assert_eq!(router.find(&String::from("/missing")), None);
    router.set_fallback(Some(Named("fallback")));
    assert_eq!(router.find(&String::from("/missing")), Some(&Named("fallback")));
    assert_eq!(router.fallback(), Some(&Named("fallback")));
    assert_eq!(block_on(router.call(String::from("/missing"))), Ok(String::from("fallback:/missing")));
    // A matching route still comes before the fallback.
    assert_eq!(block_on(router.call(String::from("/"))), Ok(String::from("root:/")));
    let empty: Router<Pattern, Named> = Router::default().with_fallback(Named("all"));
    assert!(empty.routes().is_empty());
    assert_eq!(block_on(empty.call(String::from("x"))), Ok(String::from("all:x")));
}

#[test]
fn errors_of_services_are_those_of_their_route() {
    let failing =
        FunctionService::new(|request: String| async move { Err::<String, String>(format!("failed {request}")) });
    let router = Router::new().route(AnyRule, failing);
    let error = block_on(router.call(String::from("x"))).unwrap_err();
    assert_eq!(error, RouteError::Service(String::from("failed x")));
    assert_eq!(error.to_string(), "the service of the route failed: failed x");
    let unrouted: RouteError<String, String> = RouteError::Unrouted(String::from("y"));
    assert_eq!(unrouted.to_string(), "no route matches the request");
    // The error of the service is the source of the router's.
    use std::error::Error;
    let failed: RouteError<String, umilib::service::PatternError> =
        RouteError::Service(umilib::service::PatternError::UnfinishedEscape);
    assert_eq!(
        failed.source().map(ToString::to_string),
        Some(umilib::service::PatternError::UnfinishedEscape.to_string())
    );
    let unrouted: RouteError<String, umilib::service::PatternError> = RouteError::Unrouted(String::new());
    assert!(unrouted.source().is_none());
}

#[test]
fn routers_of_different_services_and_rules() {
    type Answer = BoxService<String, String, Infallible>;
    let echo: Answer = BoxService::new(FunctionService::new(|request: String| async move { Ok(request) }));
    let length: Answer =
        BoxService::new(FunctionService::new(|request: String| async move { Ok(request.len().to_string()) }));
    let rules: Vec<Box<dyn Rule<String> + Send + Sync>> =
        vec![Box::new(Pattern::prefix(b"echo ")), Box::new(FunctionRule::new(|request: &String| request.len() > 10))];
    let mut router = Router::new();
    for (rule, service) in rules.into_iter().zip([echo, length]) {
        router.push(rule, service);
    }
    assert_eq!(block_on(router.call(String::from("echo a"))), Ok(String::from("echo a")));
    assert_eq!(block_on(router.call(String::from("a long request"))), Ok(String::from("14")));
    assert!(matches!(block_on(router.call(String::from("short"))), Err(RouteError::Unrouted(_))));
}

#[test]
fn routers_nest() {
    // By host, then by path: the request is (host, path).
    let host = |pattern: Pattern| {
        FunctionRule::new(move |request: &(String, String)| pattern.matches_bytes(request.0.as_bytes()))
    };
    let path = |pattern: Pattern| {
        FunctionRule::new(move |request: &(String, String)| pattern.matches_bytes(request.1.as_bytes()))
    };
    let answer = |name: &'static str| {
        BoxService::new(FunctionService::new(move |request: (String, String)| async move {
            Ok::<String, Infallible>(format!("{name} {}{}", request.0, request.1))
        }))
    };
    let auth = Router::new().route(path(Pattern::prefix(b"/oauth/")), answer("oauth")).with_fallback(answer("auth"));
    let site = Router::new().route(path(Pattern::any()), answer("site"));
    let auth_rule = host(Pattern::exact(b"auth.example.com").ignoring_ascii_case(true));
    let any_rule = FunctionRule::new(|_: &(String, String)| true);
    let hosts = Router::new()
        .route(Box::new(auth_rule) as Box<dyn Rule<(String, String)> + Send + Sync>, Arc::new(auth))
        .route(Box::new(any_rule), Arc::new(site));
    let call = |host: &str, path: &str| block_on(hosts.call((host.to_string(), path.to_string())));
    assert_eq!(call("AUTH.example.com", "/oauth/token"), Ok(String::from("oauth AUTH.example.com/oauth/token")));
    assert_eq!(call("auth.example.com", "/login"), Ok(String::from("auth auth.example.com/login")));
    assert_eq!(call("www.example.com", "/oauth/token"), Ok(String::from("site www.example.com/oauth/token")));
}
