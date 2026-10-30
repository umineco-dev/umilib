# Services and routers: `umilib::service`

`service` (no `std`) is how protocols hand requests to the code that answers
them, and how one server routes requests to several such pieces of code.

```rust
use std::convert::Infallible;
use umilib::service::{BoxService, FunctionService, Pattern, RouteError, Router, Service};

let api = FunctionService::new(|path: String| async move { Ok::<_, Infallible>(format!("api {path}")) });
let oauth = FunctionService::new(|path: String| async move { Ok::<_, Infallible>(format!("oauth {path}")) });
let router = Router::new()
    .route(Pattern::prefix(b"/oauth/"), BoxService::new(oauth))
    .route(Pattern::prefix(b"/api/"), BoxService::new(api));
let answer = router.call(String::from("/api/users")).await;      // Ok("api /api/users")
let missing = router.call(String::from("/other")).await;         // Err(RouteError::Unrouted("/other"))
```

## Services

A `Service<Request>` answers requests: `call(&self, request)` returns a
future of `Result<Self::Response, Self::Error>`.

- A service is shared (`&self`) by the connections that call it, and its
  futures are `Send`, so that servers may run calls on a thread pool
  ([platform-runtime.md](platform-runtime.md)). An implementation may write
  `async fn call(&self, request: Request) -> Result<...>`.
- `&S`, `Box<S>` and `Arc<S>` are services when `S` is.
- `FunctionService::new(function)` makes a service of a function from the
  request to a future of the result.
- `BoxService<Request, Response, Error>::new(service)` hides the type of a
  service (one that is `Send + Sync + 'static`), for routes whose services
  differ. `DynService` is the object-safe form behind it, whose
  `call_boxed` boxes the future.

## Rules

A `Rule<Request>` says whether a request is for a route:
`matches(&self, &request)`.

- `rule.and(other)` (`AndRule`) matches what both match; `rule.or(other)`
  (`OrRule`) what either matches; `rule.not()` (`NotRule`) what the rule
  does not. `and` does not ask its second rule if the first does not
  match, and `or` does not if the first matches.
- `AnyRule` matches every request; `FunctionRule::new(function)` is the
  rule of a function `&Request -> bool`.
- `&R`, `Box<R>` (`Box<dyn Rule<Request> + Send + Sync>` for rules of
  different types) and `Arc<R>` are rules when `R` is.
- The protocols define their own rules: a host, a path, a server name, an
  ALPN protocol.

### Patterns

`Pattern` matches bytes. It is a rule of every request that is
`AsRef<[u8]>` (`String`, `&str`, `Vec<u8>`), and the protocols' rules use it
for host names, paths and names.

- `Pattern::any()`, `exact(bytes)`, `prefix(bytes)` and `suffix(bytes)`
  (`Pattern::new(kind, bytes)` with `PatternKind`). A prefix or suffix of
  nothing is `Any`.
- `ignoring_ascii_case(true)` folds the ASCII letters, as host names need;
  other bytes are compared as they are.
- `matches_bytes(input)` says whether `input` matches.
- `Pattern::parse(text)` and `format()` convert to and from its text:
  - `*` is any input;
  - `bytes*` is a prefix;
  - `*bytes` is a suffix;
  - `bytes` is the exact bytes;
  - `\*` and `\\` stand for a `*` and a `\` of the bytes (`\` before any
    other byte stands for that byte).

  Whether case is ignored is not part of the text. A `*` elsewhere than at
  one end, or at both ends, is `PatternError::MisplacedWildcard`: such
  patterns are reserved. A `\` at the end is
  `PatternError::UnfinishedEscape`.

## Routers

`Router<R, S>` is a service that gives each request to the service of the
first route whose rule matches it, in the order the routes were added:

- `Router::new().route(rule, service)` adds routes (`push(rule, service)`
  on a router you hold).
- `with_fallback(service)` (or `set_fallback`) sets the service of the
  requests no route matches. Without one, the router fails with
  `RouteError::Unrouted(request)`, giving the request back.
- A failing service gives `RouteError::Service(error)`.
- `find(&request)` is the service the request would go to.
- Its routes have one rule type and one service type: use `BoxService` and
  `Box<dyn Rule>` (or enums of your own) for different ones.
- A router is a service, so routers nest: by host, then by path.

## C and Python

The C ABI (`include/umilib/service.h`) and the Python package
`umilib.service` provide routers of patterns of the request's bytes to
services of callbacks.

- **Patterns:** `parse`, `format`, `ignoring_ascii_case`,
  `ignores_ascii_case`, `matches_bytes`.
- **Routers:** `new`, `push`, `set_fallback`, `len`, `call`. A call fails
  with `Unrouted` if no route matches the request, and with `Failed` if
  the service fails.
- **Services:** in C, a service is
  `bool call(void* context, const uint8_t* request, size_t length, umilib_service_Response* response)`.
  It writes its answer with `umilib_service_response_write` and returns
  false if it failed.
  - Its `drop` callback is called once, when the router drops the
    service (when it is replaced, or when the router is released).
  - If `push` or `set_fallback` fails, the service is not added, and the
    caller keeps the context.
  - A call runs on the calling thread. As every object of the C ABI, a
    router is used by one thread at a time; the context must be usable
    from each thread that uses it.
  - A service must not change or release the router that calls it.
- **Python:** a service is a function from bytes to a bytes-like answer,
  and an exception it raises is raised again by the `Router.call` that ran
  it. A service that uses its own router raises `Reentrant`.
