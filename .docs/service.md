# Services and routers

How `umilib::service` is designed. The user-facing description is in
[docs/service.md](../docs/service.md).

## `Service`

- `call` takes `&self`, not `&mut self`. A server calls one service from
  many connections at once; a service that needs mutable state keeps it
  behind its own lock. There is no `poll_ready` (as tower has): back
  pressure belongs to the protocols, which see their connections.
- The returned future is `impl Future + Send`. Servers spawn calls on the
  platform's `ThreadPool`, which needs `Send`. Callers cannot add `Send`
  to the future of an `async fn` in a trait without return type notation,
  which the minimum Rust version (1.88) does not have. An impl may still
  write `async fn call`: the compiler checks that its future is `Send`.
- `async fn` in traits is not object-safe, so `DynService` boxes the
  future (`call_boxed`) for `BoxService`; the `where Request: 'a` bound
  lets a boxed future own the request.

## `Router`

- Routes are tried in order and the first match wins. That is simple to
  predict and enough for the tens of routes of a server; a protocol that
  needs more (a trie of paths, a table of exact names) defines its own
  router and stays a `Service`.
- `RouteError::Unrouted` gives the request back, so a caller can try
  something else with it (another router, an error answer that quotes it)
  without cloning it first.
- One rule type and one service type per router keep the router free of
  allocation per route; heterogeneous routes opt in to `Box`.

## `Pattern`

- `Pattern::matches_bytes` is not called `matches`, so that it does not
  shadow `Rule::matches` (whose argument is the request, not its bytes).
- A prefix or suffix of nothing is normalized to `Any` in the
  constructors (the fields are private), so a pattern formats to a text
  that parses back to it. Text to pattern to text gives the canonical text:
  a needless escape (`\a`) is dropped. The fuzz target `service-patterns`
  checks both, and checks matching against `starts_with` and `ends_with`.
- A `*` that is not at one end, or a `*` at both ends, is an error rather
  than a literal. That leaves room for richer patterns later (`*` in the
  middle, labels of host names) without changing what existing text means.

## C ABI

- `umilib_service_router_call` finds the route of the borrowed bytes
  (`Router::find` with a `&[u8]` request) and calls the callback directly.
  It neither copies the request nor polls a future; the `Service` impl
  of `CallbackService` is for Rust code that holds one.
- `CallbackService::new` (like `CallbackTask::new` of the runtime) is
  `unsafe`: it stores a function and a context that it later calls, and
  that is sent between threads. Safe code must not be able to make one.
- A service called by `umilib_service_router_call` must not change or
  release its router: the call holds a shared reference to the router,
  and `push`, `set_fallback` or `free` would alias it. The Python binding
  refuses that (`Reentrant`); C callers are told so in the header.
- If `push` or `set_fallback` fails, the service is not taken: its drop
  callback is not called, and the caller keeps the context.

## Python

- The exceptions of the services are kept per router and taken while the
  router's lock is held, so concurrent calls do not take each other's.
- An entry made for a push that fails is removed: the router never calls
  its drop callback.
- A drop callback releases its own ctypes function object while it runs.
  With CPython and libffi nothing reads that object after the Python
  function returns, so this is safe today; keep it in mind if a binding is
  ported to another runtime.
