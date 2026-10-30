//! An authorization server, an API and SMTP, IMAP and POP3 servers that take its tokens, run
//! together: the integration of umilib's OAuth with its HTTP and mail protocols
//! (`examples/integrated.sh` runs it against curl, Python's standard library and Keycloak).
//!
//! ```text
//! integrated serve [--auth PORT] [--api PORT] [--smtp PORT] [--imap PORT] [--pop PORT]
//!                  [--workers N] [--state DIR] [--user NAME:PASSWORD]...
//! integrated client-credentials METADATA CLIENT SECRET [--resource URI] [--dpop]
//! integrated device METADATA CLIENT [--scope SCOPE]
//! integrated introspect METADATA CLIENT SECRET TOKEN
//! ```
//!
//! `serve` runs the authorization server (`http://127.0.0.1:AUTH`, 9080 by default) in this
//! process, as it keeps its grants in memory, and the API (9081) and the mail servers (2525,
//! 1143, 1110) in `--workers` processes of the platform runtime's supervisor sharing their
//! listeners (or in this process with `--workers 0`). The JWT access tokens of the server are
//! checked by the workers with its public key alone, so any worker takes any token; mailboxes
//! are files under `--state`, so every worker sees every message. Each worker keeps its own
//! store of DPoP proof identifiers, so a proof replayed to another worker is not caught
//! (RFC 9449 §11.1): a deployment that needs the replay check across processes shares that
//! store, or runs one process (`--workers 0`).
//!
//! The authorization server: its metadata at `/.well-known/oauth-authorization-server`, its
//! keys at `/jwks`, a login and consent page at `/authorize`, the endpoints `/token`,
//! `/introspect`, `/revoke`, `/par` and `/device`, the device verification page at
//! `/device/verify`, and a console at `/` that signs in with the code flow and shows the
//! tokens. Its clients: `console` (the console), `cli` (public: code with a loopback redirect,
//! device, refresh), `service` (client credentials, secret `service-secret`) and `api`
//! (introspection, secret `api-secret`). Users are `--user NAME:PASSWORD`
//! (`alice:wonderland` and `bob:builder` without one); scopes are `api` and `mail`.
//!
//! The API: its metadata at `/.well-known/oauth-protected-resource`, `/api/whoami` (scope `api`)
//! and `/api/mail` (the user's messages, scope `mail`, only for a token of a user), Bearer or
//! DPoP. A request with more than one `Authorization` or `DPoP` field is refused. The mail servers take `AUTH
//! OAUTHBEARER` (RFC 7628) with a token of the scope `mail`; SMTP delivers to local
//! mailboxes, POP3 and IMAP read them. Everything is plain TCP on 127.0.0.1: this is a test
//! tool, and a deployment puts TLS in front (bearer tokens are secrets).
//!
//! The client commands run this crate's OAuth client against any authorization server whose
//! RFC 8414 metadata is at `METADATA` (over `http://`): client credentials (with a DPoP proof
//! if `--dpop`), the device grant (it prints the user code and polls), and introspection.
#![cfg_attr(
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)),
    allow(unused_imports, dead_code)
)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant as Clock, SystemTime, UNIX_EPOCH};

use umilib::auth::cert::key::{KeyAlgorithm, NamedCurve, PrivateKey};
use umilib::auth::oauth::{
    DPoPConfig, DPoPProof, DPoPTarget, OAuthAccessTokenFormat, OAuthAuthorization, OAuthAuthorizationFailure,
    OAuthClient, OAuthClientAuthentication, OAuthClientConfig, OAuthClientMethod, OAuthClientRegistration,
    OAuthDeviceAuthorizationResponse, OAuthEndpointRequest, OAuthError, OAuthGrant, OAuthGrantRecord, OAuthHTTPRequest,
    OAuthHTTPResponse, OAuthMetadata, OAuthMetadataKind, OAuthParameters, OAuthResourceConfig, OAuthResourceServer,
    OAuthScope, OAuthServer, OAuthServerConfig, OAuthTokenInfo, OAuthTokenRequest, OAuthTokenResponse,
    OAuthTokenScheme, OAuthTokenValidation,
};
use umilib::auth::sasl::oauthbearer::{OAUTHBEARERErrorResult, OAUTHBEARERMessage};
use umilib::codec::json::{JSONEncoder, JSONObject, JSONValue};
use umilib::codec::mail::{MIMEEntity, MailConfig};
use umilib::codec::uri::URIReference;
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
use umilib::platform::native::Random;
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
use umilib::platform::runtime::{Conversion, ListenerConfig, Supervisor, SupervisorConfig, Worker};
use umilib::protocol::http::v1::{H1Config, H1Connection};
use umilib::protocol::http::{HTTPConnection, HTTPEvent, HTTPMethod, HTTPRequest, HTTPResponse, HTTPRule, HTTPStatus};
use umilib::protocol::imap::v4::{
    IMAPCommandBody, IMAPCondition, IMAPConfig, IMAPFetchAttribute, IMAPFetchItem, IMAPMailbox, IMAPResponse,
    IMAPResponseCode, IMAPServer, IMAPServerConfig, IMAPServerEvent,
};
use umilib::protocol::jwt::{JWK, JWKSet, JWSAlgorithm};
use umilib::protocol::pop::v3::{
    POP3Command, POP3Config, POP3MultiLineWriter, POP3Response, POP3Server, POP3ServerConfig, POP3ServerEvent,
};
use umilib::protocol::smtp::{SMTPCommand, SMTPConfig, SMTPReply, SMTPServer, SMTPServerConfig, SMTPServerEvent};
use umilib::runtime::Instant;
use umilib::secret::ConstantTimeEq;
use umilib::service::{Pattern, Router};

/// The command line: positional arguments and `--name value` options.
pub struct Arguments {
    pub positional: Vec<String>,
    pub options: Vec<(String, Option<String>)>,
}

impl Arguments {
    /// The options that take no value.
    pub const FLAGS: &'static [&'static str] = &["--dpop"];

    pub fn parse() -> Arguments {
        let mut arguments = Arguments { positional: Vec::new(), options: Vec::new() };
        let mut words = std::env::args().skip(1);
        while let Some(word) = words.next() {
            if word.starts_with("--") {
                let value = if Arguments::FLAGS.contains(&word.as_str()) { None } else { words.next() };
                arguments.options.push((word, value));
            } else {
                arguments.positional.push(word);
            }
        }
        arguments
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.options.iter().find(|(key, _)| key == name).and_then(|(_, value)| value.as_deref())
    }

    pub fn all(&self, name: &str) -> Vec<&str> {
        self.options.iter().filter(|(key, _)| key == name).filter_map(|(_, value)| value.as_deref()).collect()
    }

    pub fn has(&self, name: &str) -> bool {
        self.options.iter().any(|(key, _)| key == name)
    }

    pub fn port(&self, name: &str, default: u16) -> u16 {
        self.get(name).map_or(default, |port| port.parse().unwrap_or_else(|_| Tool::fail(&format!("{name} PORT"))))
    }

    pub fn position(&self, index: usize, what: &str) -> &str {
        self.positional.get(index).map(String::as_str).unwrap_or_else(|| Tool::fail(what))
    }
}

/// Helpers of the whole program.
pub struct Tool;

impl Tool {
    pub fn fail(message: &str) -> ! {
        eprintln!("error: {message}");
        std::process::exit(1)
    }

    /// The time in seconds since 1970, as OAuth takes it.
    pub fn time() -> i64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs() as i64)
    }

    /// The time of a protocol state machine, since `start`.
    pub fn now(start: Clock) -> Instant {
        Instant::from_nanos(start.elapsed().as_nanos() as u64)
    }

    /// Writes `out`, then reads what arrives within `wait`; `None` once the peer closed.
    pub fn exchange(stream: &mut TcpStream, out: &[u8], wait: Duration) -> Option<Vec<u8>> {
        if !out.is_empty() && stream.write_all(out).is_err() {
            return None;
        }
        let _ = stream.set_read_timeout(Some(wait.max(Duration::from_millis(1))));
        let mut buffer = vec![0u8; 1 << 16];
        match stream.read(&mut buffer) {
            Ok(0) => None,
            Ok(count) => Some(buffer[..count].to_vec()),
            Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                Some(Vec::new())
            }
            Err(_) => None,
        }
    }

    /// The time until `deadline`, at most a second.
    pub fn wait(deadline: Option<Instant>, now: Instant) -> Duration {
        deadline.map_or(Duration::from_secs(1), |deadline| {
            Duration::from_nanos(deadline.as_nanos().saturating_sub(now.as_nanos())).min(Duration::from_secs(1))
        })
    }

    /// `text` with the characters of HTML markup escaped.
    pub fn escape(text: &str) -> String {
        text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
    }

    /// A page of `title` and `body`.
    pub fn page(title: &str, body: &str) -> Vec<u8> {
        format!(
            "<!doctype html><meta charset=utf-8><title>{}</title><h1>{}</h1>\n{body}\n",
            Tool::escape(title),
            Tool::escape(title)
        )
        .into_bytes()
    }
}

/// A request one of the HTTP servers received, whole.
pub struct Exchange {
    pub request: HTTPRequest,
    pub body: Vec<u8>,
}

impl Exchange {
    /// Whether the request has more than one of the fields OAuth reads, which it then refuses
    /// (RFC 9449 §4.3: one `DPoP` field).
    pub fn has_repeated_fields(&self) -> bool {
        [&b"authorization"[..], b"dpop", b"content-type"]
            .iter()
            .any(|name| self.request.fields.get_all(name).count() > 1)
    }

    /// The request as OAuth reads it, with `origin` (`http://host:port`) for its absolute URI.
    pub fn endpoint(&self, origin: &str) -> OAuthEndpointRequest {
        let field =
            |name: &[u8]| self.request.fields.get(name).map(|value| String::from_utf8_lossy(value).into_owned());
        OAuthEndpointRequest {
            method: String::from_utf8_lossy(self.request.method.as_bytes()).into_owned(),
            uri: format!("{origin}{}", String::from_utf8_lossy(&self.request.path)),
            authorization: field(b"authorization"),
            dpop: field(b"dpop"),
            content_type: field(b"content-type"),
            body: self.body.clone(),
        }
    }

    /// The parameters of the query of the request.
    pub fn query(&self) -> OAuthParameters {
        let path = String::from_utf8_lossy(&self.request.path).into_owned();
        URIReference::parse(&path).ok().and_then(|uri| OAuthParameters::from_query(&uri).ok()).unwrap_or_default()
    }
}

/// A minimal HTTP/1.1 server and client over blocking sockets, one thread per connection.
pub struct HTTP;

impl HTTP {
    /// Serves `listener`, answering each request with `handle`.
    pub fn serve(listener: TcpListener, handle: Arc<dyn Fn(&Exchange) -> OAuthHTTPResponse + Send + Sync>) {
        for stream in listener.incoming().flatten() {
            let handle = handle.clone();
            std::thread::spawn(move || HTTP::connection(stream, handle));
        }
    }

    /// One connection: requests read whole, answered in order.
    pub fn connection(mut stream: TcpStream, handle: Arc<dyn Fn(&Exchange) -> OAuthHTTPResponse + Send + Sync>) {
        let start = Clock::now();
        let mut connection = H1Connection::server(H1Config::default(), Tool::now(start));
        let mut requests: BTreeMap<u64, Exchange> = BTreeMap::new();
        let mut out = Vec::new();
        loop {
            let mut buffer = vec![0u8; 1 << 16];
            while let Some(event) = connection.poll_event() {
                match event {
                    HTTPEvent::Request { stream, request, end } => {
                        requests.insert(stream.0, Exchange { request, body: Vec::new() });
                        if end {
                            HTTP::answer(&mut connection, stream, requests.remove(&stream.0), &handle);
                        }
                    }
                    HTTPEvent::Data { stream } => {
                        while let Ok(count) = connection.read_data(stream, &mut buffer) {
                            if count == 0 {
                                break;
                            }
                            if let Some(exchange) = requests.get_mut(&stream.0) {
                                exchange.body.extend_from_slice(&buffer[..count]);
                            }
                        }
                    }
                    HTTPEvent::End { stream } => {
                        while let Ok(count) = connection.read_data(stream, &mut buffer) {
                            if count == 0 {
                                break;
                            }
                            if let Some(exchange) = requests.get_mut(&stream.0) {
                                exchange.body.extend_from_slice(&buffer[..count]);
                            }
                        }
                        HTTP::answer(&mut connection, stream, requests.remove(&stream.0), &handle);
                    }
                    _ => {}
                }
            }
            out.clear();
            connection.transmit(&mut out);
            if connection.wants_close() {
                let _ = stream.write_all(&out);
                break;
            }
            match Tool::exchange(&mut stream, &out, Duration::from_millis(50)) {
                Some(input) => connection.receive(&input, Tool::now(start)),
                None => connection.receive_close(Tool::now(start)),
            }
            connection.expire(Tool::now(start));
            if start.elapsed() > Duration::from_secs(120) {
                break;
            }
        }
    }

    fn answer(
        connection: &mut H1Connection,
        stream: umilib::protocol::http::HTTPStreamID,
        exchange: Option<Exchange>,
        handle: &Arc<dyn Fn(&Exchange) -> OAuthHTTPResponse + Send + Sync>,
    ) {
        let Some(exchange) = exchange else { return };
        let reply = match exchange.has_repeated_fields() {
            true => HTTP::reply(400, "text/plain", b"a repeated Authorization, DPoP or Content-Type field\n".to_vec()),
            false => handle(&exchange),
        };
        println!(
            "http: {} {} {}",
            String::from_utf8_lossy(exchange.request.method.as_bytes()),
            String::from_utf8_lossy(&exchange.request.path).split('?').next().unwrap_or_default(),
            reply.status
        );
        let mut response = HTTPResponse::new(HTTPStatus(reply.status));
        for (name, value) in &reply.headers {
            let _ = response.fields.append(name.as_bytes(), value.as_bytes());
        }
        let _ = response.fields.append(b"content-length", reply.body.len().to_string().as_bytes());
        let _ = connection.send_response(stream, &response, reply.body.is_empty());
        if !reply.body.is_empty() {
            let _ = connection.send_data(stream, &reply.body, true);
        }
    }

    /// A response of `status`, the content type `kind` and `body`, never cached.
    pub fn reply(status: u16, kind: &str, body: Vec<u8>) -> OAuthHTTPResponse {
        OAuthHTTPResponse {
            status,
            headers: vec![("content-type".into(), kind.into()), ("cache-control".into(), "no-store".into())],
            body,
        }
    }

    /// A redirect to `location`.
    pub fn redirect(location: &str) -> OAuthHTTPResponse {
        OAuthHTTPResponse {
            status: 302,
            headers: vec![("location".into(), location.into()), ("cache-control".into(), "no-store".into())],
            body: Vec::new(),
        }
    }

    /// Sends the request a client made (to an `http://` URI) and returns the response.
    pub fn send(request: &OAuthHTTPRequest) -> OAuthHTTPResponse {
        HTTP::fetch(&request.method, &request.uri, &request.headers, &request.body)
    }

    /// Sends a request of `method` to the `http://` URI `uri` and returns the response.
    pub fn fetch(method: &str, uri: &str, headers: &[(String, String)], body: &[u8]) -> OAuthHTTPResponse {
        let target = URIReference::parse(uri).unwrap_or_else(|error| Tool::fail(&format!("{uri}: {error}")));
        if target.scheme.as_deref() != Some("http") {
            Tool::fail("only http:// URIs: this is a test tool");
        }
        let authority = target.authority.clone().unwrap_or_else(|| Tool::fail("a URI with a host"));
        let address =
            format!("{}:{}", authority.host.trim_matches(['[', ']']), authority.port.as_deref().unwrap_or("80"));
        let mut stream =
            TcpStream::connect(&address).unwrap_or_else(|error| Tool::fail(&format!("{address}: {error}")));
        let start = Clock::now();
        let mut connection = H1Connection::client(H1Config::default(), Tool::now(start));
        let path = format!(
            "{}{}",
            if target.path.is_empty() { "/" } else { &target.path },
            target.query.as_ref().map_or(String::new(), |query| format!("?{query}"))
        );
        let method = HTTPMethod::parse(method.as_bytes()).unwrap_or_else(|_| Tool::fail("a method"));
        let mut request = HTTPRequest::new(method, b"http", authority.to_string().as_bytes(), path.as_bytes());
        for (name, value) in headers {
            let _ = request.fields.append(name.as_bytes(), value.as_bytes());
        }
        if !body.is_empty() {
            let _ = request.fields.append(b"content-length", body.len().to_string().as_bytes());
        }
        let stream_id =
            connection.send_request(&request, body.is_empty()).unwrap_or_else(|error| Tool::fail(&format!("{error}")));
        if !body.is_empty() {
            let _ = connection.send_data(stream_id, body, true);
        }
        let mut response = OAuthHTTPResponse::default();
        let mut buffer = vec![0u8; 1 << 16];
        let mut out = Vec::new();
        loop {
            out.clear();
            connection.transmit(&mut out);
            let Some(input) = Tool::exchange(&mut stream, &out, Duration::from_millis(50)) else {
                connection.receive_close(Tool::now(start));
                break;
            };
            connection.receive(&input, Tool::now(start));
            let mut done = false;
            while let Some(event) = connection.poll_event() {
                match event {
                    HTTPEvent::Response { response: head, end, .. } if !head.status.is_informational() => {
                        response.status = head.status.0;
                        response.headers = head
                            .fields
                            .iter()
                            .map(|field| {
                                (
                                    String::from_utf8_lossy(&field.name).into_owned(),
                                    String::from_utf8_lossy(&field.value).into_owned(),
                                )
                            })
                            .collect();
                        done |= end;
                    }
                    HTTPEvent::Data { stream } | HTTPEvent::End { stream } => {
                        while let Ok(count) = connection.read_data(stream, &mut buffer) {
                            if count == 0 {
                                break;
                            }
                            response.body.extend_from_slice(&buffer[..count]);
                        }
                        done |= matches!(event, HTTPEvent::End { .. });
                    }
                    HTTPEvent::Closed { .. } => done = true,
                    _ => {}
                }
            }
            if done || start.elapsed() > Duration::from_secs(30) {
                break;
            }
        }
        response
    }
}

/// The authorization server's process: the server, the console's client, the users, and the
/// authorization requests waiting for the user's login.
pub struct Authority {
    pub server: OAuthServer,
    pub console: OAuthClient,
    pub users: BTreeMap<String, String>,
    pub consents: BTreeMap<String, (OAuthAuthorization, i64)>,
    pub origin: String,
    pub random: Random,
}

/// The pages and endpoints of the authorization server, routed by `HTTPRule`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityRoute {
    Console,
    ConsoleStart,
    ConsoleCallback,
    Metadata,
    Keys,
    Authorize,
    Decide,
    Token,
    Introspect,
    Revoke,
    Push,
    Device,
    Verify,
    Verified,
}

impl Authority {
    /// The seconds a login page waits for its form.
    pub const CONSENT_LIFETIME: i64 = 600;

    pub fn new(origin: &str, resource: &str, key: JWK, users: BTreeMap<String, String>) -> Authority {
        let mut config = OAuthServerConfig::new(origin);
        config.jwks_uri = Some(format!("{origin}/jwks"));
        config.access_token_format = OAuthAccessTokenFormat::JWT {
            key: Box::new(key),
            algorithm: JWSAlgorithm::ES256,
            default_audience: resource.into(),
        };
        let mut server = OAuthServer::new(config);
        let scope = OAuthScope::parse("api mail").expect("a scope");
        let callback = format!("{origin}/console/callback");
        server
            .register(OAuthClientRegistration::public("console", &[&callback], scope.clone()))
            .expect("a registration");
        let mut cli = OAuthClientRegistration::public("cli", &["http://127.0.0.1/cb"], scope.clone());
        cli.grant_types.push(OAuthGrant::DEVICE_CODE.into());
        server.register(cli).expect("a registration");
        let service = OAuthClientRegistration::confidential(
            "service",
            OAuthClientMethod::SecretBasic,
            "service-secret",
            &[OAuthGrant::CLIENT_CREDENTIALS],
            OAuthScope::parse("api").expect("a scope"),
        );
        server.register(service).expect("a registration");
        let mut api = OAuthClientRegistration::confidential(
            "api",
            OAuthClientMethod::SecretBasic,
            "api-secret",
            &[],
            OAuthScope::default(),
        );
        api.introspection = true;
        server.register(api).expect("a registration");
        let config = OAuthClientConfig::from_metadata(
            &server.metadata(),
            OAuthClientAuthentication::None { client_id: "console".into() },
            &callback,
        )
        .expect("the console's configuration");
        Authority {
            server,
            console: OAuthClient::new(config),
            users,
            consents: BTreeMap::new(),
            origin: origin.into(),
            random: Random,
        }
    }

    pub fn router() -> Router<HTTPRule, AuthorityRoute> {
        let any = Pattern::any;
        let get = |path: &[u8], route| (HTTPRule::new(any(), Pattern::exact(path)).with_method(HTTPMethod::GET), route);
        let post =
            |path: &[u8], route| (HTTPRule::new(any(), Pattern::exact(path)).with_method(HTTPMethod::POST), route);
        // The endpoints take every method: the server answers what is not a POST (RFC 6749 §3.2).
        let endpoint = |path: &[u8], route| (HTTPRule::new(any(), Pattern::exact(path)), route);
        let query =
            |path: &[u8], route| (HTTPRule::new(any(), Pattern::prefix(path)).with_method(HTTPMethod::GET), route);
        let routes = [
            get(b"/", AuthorityRoute::Console),
            get(b"/console/start", AuthorityRoute::ConsoleStart),
            query(b"/console/callback?", AuthorityRoute::ConsoleCallback),
            get(b"/.well-known/oauth-authorization-server", AuthorityRoute::Metadata),
            get(b"/jwks", AuthorityRoute::Keys),
            query(b"/authorize?", AuthorityRoute::Authorize),
            post(b"/authorize", AuthorityRoute::Decide),
            endpoint(b"/token", AuthorityRoute::Token),
            endpoint(b"/introspect", AuthorityRoute::Introspect),
            endpoint(b"/revoke", AuthorityRoute::Revoke),
            endpoint(b"/par", AuthorityRoute::Push),
            endpoint(b"/device", AuthorityRoute::Device),
            get(b"/device/verify", AuthorityRoute::Verify),
            query(b"/device/verify?", AuthorityRoute::Verify),
            post(b"/device/verify", AuthorityRoute::Verified),
        ];
        routes.into_iter().fold(Router::new(), |router, (rule, route)| router.route(rule, route))
    }

    /// Whether `password` is that of `user`, compared in constant time.
    pub fn verify(&self, user: &str, password: &str) -> bool {
        self.users.get(user).is_some_and(|own| own.as_bytes().ct_eq(password.as_bytes()).into_bool())
    }

    pub fn handle(&mut self, router: &Router<HTTPRule, AuthorityRoute>, exchange: &Exchange) -> OAuthHTTPResponse {
        let now = Tool::time();
        let endpoint = exchange.endpoint(&self.origin);
        let html =
            |status, title: &str, body: &str| HTTP::reply(status, "text/html; charset=utf-8", Tool::page(title, body));
        let form = || OAuthParameters::parse(&exchange.body).unwrap_or_default();
        let Some(route) = router.find(&exchange.request) else {
            return html(404, "Not found", "");
        };
        match route {
            AuthorityRoute::Metadata => {
                HTTP::reply(200, OAuthHTTPRequest::JSON, self.server.metadata().encode().into_bytes())
            }
            AuthorityRoute::Keys => HTTP::reply(
                200,
                "application/jwk-set+json",
                self.server.jwks().map(|keys| keys.to_json()).unwrap_or_default().into_bytes(),
            ),
            AuthorityRoute::Token => self.server.token(&endpoint, now, &mut self.random),
            AuthorityRoute::Introspect => self.server.introspect(&endpoint, now),
            AuthorityRoute::Revoke => self.server.revoke(&endpoint, now),
            AuthorityRoute::Push => self.server.push(&endpoint, now, &mut self.random),
            AuthorityRoute::Device => self.server.device_authorize(&endpoint, now, &mut self.random),
            AuthorityRoute::Authorize => match self.server.authorize(&exchange.query(), now) {
                Ok(authorization) => {
                    self.consents.retain(|_, (_, created)| now - *created <= Authority::CONSENT_LIFETIME);
                    let identifier = self.server.random_token(&mut self.random).expect("random");
                    let body = format!(
                        "<p>{} asks for <b>{}</b>.</p><form method=post action=/authorize><input type=hidden name=consent value=\"{identifier}\">\
                         <label>User <input name=user></label> <label>Password <input name=password type=password></label>\
                         <button name=decision value=allow>Allow</button> <button name=decision value=deny>Deny</button></form>",
                        Tool::escape(&authorization.client_id),
                        Tool::escape(&authorization.scope.to_string()),
                    );
                    self.consents.insert(identifier, (authorization, now));
                    html(200, "Sign in", &body)
                }
                Err(OAuthAuthorizationFailure::Local(error)) => html(400, "Error", &Tool::escape(&error.encode())),
                Err(OAuthAuthorizationFailure::Redirect(uri)) => HTTP::redirect(&uri.to_string()),
            },
            AuthorityRoute::Decide => {
                let form = form();
                let Some((authorization, _)) = form.get("consent").and_then(|consent| self.consents.remove(consent))
                else {
                    return html(400, "Error", "this sign-in has expired");
                };
                if form.get("decision") != Some("allow") {
                    return HTTP::redirect(
                        &self.server.deny(&authorization).map(|uri| uri.to_string()).unwrap_or_default(),
                    );
                }
                let user = form.get("user").unwrap_or_default().to_string();
                if !self.verify(&user, form.get("password").unwrap_or_default()) {
                    return html(403, "Error", "wrong user or password");
                }
                println!("login: {user} for {}", authorization.client_id);
                let grant = OAuthGrantRecord {
                    client_id: authorization.client_id.clone(),
                    subject: Some(user),
                    scope: authorization.scope.clone(),
                    resources: authorization.resources.clone(),
                    authentication_time: Some(now),
                    ..OAuthGrantRecord::default()
                };
                match self.server.approve(&authorization, grant, now, &mut self.random) {
                    Ok(uri) => HTTP::redirect(&uri.to_string()),
                    Err(error) => html(500, "Error", &Tool::escape(&error.to_string())),
                }
            }
            AuthorityRoute::Verify => {
                let code = exchange.query().get("user_code").map(Tool::escape).unwrap_or_default();
                let body = format!(
                    "<form method=post action=/device/verify><label>Code <input name=user_code value=\"{code}\"></label> \
                     <label>User <input name=user></label> <label>Password <input name=password type=password></label> <button>Allow</button></form>"
                );
                html(200, "Connect a device", &body)
            }
            AuthorityRoute::Verified => {
                let form = form();
                let code = form.get("user_code").unwrap_or_default().to_string();
                let user = form.get("user").unwrap_or_default().to_string();
                let Some(device) = self.server.device(&code, now).cloned() else {
                    return html(400, "Error", "no such code");
                };
                if !self.verify(&user, form.get("password").unwrap_or_default()) {
                    return html(403, "Error", "wrong user or password");
                }
                let grant = OAuthGrantRecord {
                    client_id: device.client_id.clone(),
                    subject: Some(user.clone()),
                    scope: device.scope.clone(),
                    resources: device.resources.clone(),
                    authentication_time: Some(now),
                    ..OAuthGrantRecord::default()
                };
                match self.server.device_approve(&code, grant, now) {
                    Ok(()) => {
                        println!("device: {user} for {}", device.client_id);
                        html(200, "Connected", "<p>The device is connected.</p>")
                    }
                    Err(error) => html(400, "Error", &Tool::escape(&error.to_string())),
                }
            }
            AuthorityRoute::Console => html(200, "umilib console", "<p><a href=/console/start>Sign in</a></p>"),
            AuthorityRoute::ConsoleStart => {
                let scope = OAuthScope::parse("api mail").expect("a scope");
                match self.console.authorize(Some(&scope), &[], now, &mut self.random) {
                    Ok(url) => HTTP::redirect(&url.to_string()),
                    Err(error) => html(500, "Error", &Tool::escape(&error.to_string())),
                }
            }
            AuthorityRoute::ConsoleCallback => {
                let redirect = format!("{}{}", self.origin, String::from_utf8_lossy(&exchange.request.path));
                let request = match URIReference::parse(&redirect)
                    .map_err(OAuthError::from)
                    .and_then(|uri| self.console.callback(&uri, now))
                {
                    Ok(request) => request,
                    Err(error) => return html(400, "Error", &Tool::escape(&error.to_string())),
                };
                // The console is a client of this server: its token request goes straight to it.
                let http = self.console.token_request(&request, now, &mut self.random).expect("a token request");
                let received = OAuthEndpointRequest {
                    method: http.method.clone(),
                    uri: http.uri.clone(),
                    authorization: http.header("authorization").map(str::to_string),
                    content_type: http.header("content-type").map(str::to_string),
                    body: http.body.clone(),
                    ..OAuthEndpointRequest::default()
                };
                let response = self.server.token(&received, now, &mut self.random);
                match OAuthTokenResponse::decode(response.status, &response.body) {
                    Ok(tokens) => {
                        let body = format!(
                            "<p>Access token ({} s, scope {}):</p><pre id=access_token>{}</pre><p>Refresh token:</p><pre id=refresh_token>{}</pre>",
                            tokens.expires_in.unwrap_or_default(),
                            Tool::escape(&tokens.scope.map(|scope| scope.to_string()).unwrap_or_default()),
                            Tool::escape(&tokens.access_token),
                            Tool::escape(tokens.refresh_token.as_deref().unwrap_or_default()),
                        );
                        html(200, "Signed in", &body)
                    }
                    Err(error) => html(400, "Error", &Tool::escape(&error.to_string())),
                }
            }
        }
    }
}

/// The resource side, in each worker: the checks of tokens, and the mailboxes on disk.
pub struct Resource {
    pub checks: Mutex<OAuthResourceServer>,
    pub origin: String,
    pub issuer: String,
    pub state: PathBuf,
}

/// The routes of the API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceRoute {
    Metadata,
    WhoAmI,
    Mail,
}

impl Resource {
    pub fn new(origin: &str, issuer: &str, keys: JWKSet, state: &Path) -> Resource {
        let config = OAuthResourceConfig {
            resource: origin.into(),
            realm: Some("umilib".into()),
            resource_metadata: OAuthMetadata::location(OAuthMetadataKind::Resource, origin).ok(),
            validation: OAuthTokenValidation::JWT {
                issuer: issuer.into(),
                keys,
                algorithms: vec![JWSAlgorithm::ES256],
            },
            require_dpop: false,
            dpop: DPoPConfig::default(),
            leeway: 5,
        };
        let checks = OAuthResourceServer::new(config).expect("a resource server");
        Resource { checks: Mutex::new(checks), origin: origin.into(), issuer: issuer.into(), state: state.into() }
    }

    pub fn router() -> Router<HTTPRule, ResourceRoute> {
        let get = |path: &[u8], route| {
            (HTTPRule::new(Pattern::any(), Pattern::exact(path)).with_method(HTTPMethod::GET), route)
        };
        [
            get(b"/.well-known/oauth-protected-resource", ResourceRoute::Metadata),
            get(b"/api/whoami", ResourceRoute::WhoAmI),
            get(b"/api/mail", ResourceRoute::Mail),
        ]
        .into_iter()
        .fold(Router::new(), |router, (rule, route)| router.route(rule, route))
    }

    /// The token of `request`, taken, with the scope `scope`.
    pub fn take(&self, request: &OAuthEndpointRequest, scope: &str) -> Result<OAuthTokenInfo, OAuthHTTPResponse> {
        let mut checks = self.checks.lock().expect("the checks");
        let info = checks.accept_jwt(request, Tool::time()).map_err(|refusal| refusal.to_response())?;
        let scheme = if info.confirmation.is_some() { OAuthTokenScheme::DPoP } else { OAuthTokenScheme::Bearer };
        checks
            .require_scope(&info, &OAuthScope::parse(scope).expect("a scope"), scheme)
            .map_err(|refusal| refusal.to_response())?;
        Ok(info)
    }

    pub fn handle(&self, router: &Router<HTTPRule, ResourceRoute>, exchange: &Exchange) -> OAuthHTTPResponse {
        let endpoint = exchange.endpoint(&self.origin);
        let json = |object: JSONObject| {
            HTTP::reply(
                200,
                OAuthHTTPRequest::JSON,
                JSONEncoder::COMPACT.encode(&JSONValue::Object(object)).into_bytes(),
            )
        };
        let text = |value: &str| JSONValue::String(value.into());
        match router.find(&exchange.request) {
            None => HTTP::reply(404, "text/plain", b"not found\n".to_vec()),
            Some(ResourceRoute::Metadata) => {
                let metadata = self.checks.lock().expect("the checks").metadata(&[&self.issuer], &["api", "mail"]);
                HTTP::reply(200, OAuthHTTPRequest::JSON, metadata.encode().into_bytes())
            }
            Some(ResourceRoute::WhoAmI) => match self.take(&endpoint, "api") {
                Ok(info) => {
                    let mut object = JSONObject::new();
                    object.insert("subject".into(), text(info.subject.as_deref().unwrap_or_default()));
                    object.insert("client_id".into(), text(info.client_id.as_deref().unwrap_or_default()));
                    object.insert("scope".into(), text(&info.scope.to_string()));
                    object.insert("bound".into(), JSONValue::Bool(info.confirmation.is_some()));
                    object.insert("process".into(), JSONValue::Number(u64::from(std::process::id()).into()));
                    json(object)
                }
                Err(refusal) => refusal,
            },
            Some(ResourceRoute::Mail) => match self.take(&endpoint, "mail") {
                // RFC 9068 §5: a token without a resource owner has the client as its subject;
                // only a user's token reads a mailbox.
                Ok(info) if info.subject.is_none() || info.subject == info.client_id => {
                    HTTP::reply(403, "text/plain", b"a token of a user is required\n".to_vec())
                }
                Ok(info) => {
                    let user = info.subject.unwrap_or_default();
                    let subjects =
                        self.mailbox(&user).iter().map(|message| text(&Resource::subject(message))).collect();
                    let mut object = JSONObject::new();
                    object.insert("user".into(), text(&user));
                    object.insert("messages".into(), JSONValue::Array(subjects));
                    json(object)
                }
                Err(refusal) => refusal,
            },
        }
    }

    /// The `Subject` of a message.
    pub fn subject(message: &[u8]) -> String {
        String::from_utf8_lossy(message)
            .lines()
            .take_while(|line| !line.is_empty())
            .find_map(|line| line.strip_prefix("Subject: ").map(str::to_string))
            .unwrap_or_default()
    }

    /// The user of the OAUTHBEARER response `response` whose token has the scope `mail`, or the
    /// error result to send (RFC 7628 §3.2.2).
    pub fn mail_user(&self, response: &[u8]) -> Result<String, Vec<u8>> {
        let refused = |status: &str| {
            OAUTHBEARERErrorResult { status: status.into(), scope: Some("mail".into()), openid_configuration: None }
                .encode()
        };
        let message = OAUTHBEARERMessage::decode(response).map_err(|_| refused("invalid_request"))?;
        let token = message.bearer_token().ok_or_else(|| refused("invalid_request"))?;
        let request = OAuthEndpointRequest {
            method: "AUTH".into(),
            uri: self.origin.clone(),
            authorization: Some(format!("Bearer {token}")),
            ..OAuthEndpointRequest::default()
        };
        let info = self.take(&request, "mail").map_err(|response| match response.status {
            403 => refused("insufficient_scope"),
            _ => refused("invalid_token"),
        })?;
        Ok(info.subject.unwrap_or_default())
    }

    /// The directory of the mailbox of `user`, a name of letters and digits only, if the user
    /// has one: mailboxes are made when the server starts, never by a message.
    pub fn directory(&self, user: &str) -> Option<PathBuf> {
        let valid = !user.is_empty() && user.bytes().all(|byte| byte.is_ascii_alphanumeric());
        let directory = self.state.join("mail").join(user);
        (valid && directory.is_dir()).then_some(directory)
    }

    /// The messages of `user`, oldest first.
    pub fn mailbox(&self, user: &str) -> Vec<Vec<u8>> {
        let Some(directory) = self.directory(user) else { return Vec::new() };
        let mut names: Vec<PathBuf> = std::fs::read_dir(directory)
            .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
            .unwrap_or_default();
        names.sort();
        names.iter().filter_map(|path| std::fs::read(path).ok()).collect()
    }

    /// Delivers `message` to the mailbox of `user`; `false` for an unknown user.
    pub fn deliver(&self, user: &str, message: &[u8]) -> bool {
        let Some(directory) = self.directory(user) else { return false };
        let name = format!(
            "{:020}-{}-{:?}.eml",
            SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |time| time.as_nanos()),
            std::process::id(),
            std::thread::current().id()
        );
        std::fs::write(directory.join(name.replace(['(', ')'], "")), message).is_ok()
    }

    /// One SMTP connection: submission after `AUTH OAUTHBEARER`, to local mailboxes.
    pub fn smtp(&self, mut stream: TcpStream) {
        let start = Clock::now();
        let settings = SMTPServerConfig {
            domain: "umilib.test".into(),
            auth_mechanisms: vec!["OAUTHBEARER".into()],
            passwords_require_tls: false,
            requires_auth: true,
            ..SMTPServerConfig::default()
        };
        let Ok(mut server) = SMTPServer::new(SMTPConfig::default(), settings, false) else { return };
        server.greet(server.greeting(), Tool::now(start)).expect("a greeting");
        let (mut user, mut failed, mut recipients, mut message) =
            (None::<String>, false, Vec::<String>::new(), Vec::new());
        let mut out = Vec::new();
        while server.is_open() {
            out.clear();
            server.transmit(&mut out);
            let now = Tool::now(start);
            let Some(input) = Tool::exchange(&mut stream, &out, Tool::wait(server.poll_timeout(), now)) else { break };
            let now = Tool::now(start);
            server.receive(&input, now);
            if server.poll_timeout().is_some_and(|deadline| deadline <= now) {
                server.expire(now);
            }
            while let Some(event) = server.poll_event() {
                let authenticate = |response: &[u8],
                                    server: &mut SMTPServer,
                                    failed: &mut bool,
                                    user: &mut Option<String>|
                 -> Option<SMTPReply> {
                    if *failed {
                        // RFC 7628 §3.2.3: the client's dummy response ends a failed exchange.
                        *failed = false;
                        return Some(SMTPReply::new(535, "5.7.8 Authentication credentials invalid"));
                    }
                    match self.mail_user(response) {
                        Ok(name) => {
                            println!("smtp: {name} authenticated");
                            *user = Some(name);
                            Some(SMTPReply::new(235, "2.7.0 Authentication successful"))
                        }
                        Err(error) => {
                            *failed = true;
                            server.auth_challenge(&error, now).expect("a challenge");
                            None
                        }
                    }
                };
                let reply = match event {
                    SMTPServerEvent::Command(SMTPCommand::Auth { initial: Some(response), .. }) => {
                        failed = false;
                        authenticate(&response, &mut server, &mut failed, &mut user)
                    }
                    SMTPServerEvent::Command(SMTPCommand::Auth { initial: None, .. }) => {
                        failed = false;
                        server.auth_challenge(b"", now).expect("a challenge");
                        None
                    }
                    // RFC 4954 §4: a cancelled exchange starts over.
                    SMTPServerEvent::AuthCancelled => {
                        failed = false;
                        None
                    }
                    SMTPServerEvent::AuthResponse(response) => {
                        authenticate(&response, &mut server, &mut failed, &mut user)
                    }
                    SMTPServerEvent::Command(SMTPCommand::Ehlo(name) | SMTPCommand::Helo(name)) => {
                        Some(SMTPReply::new(250, &format!("umilib.test greets {name}")))
                    }
                    SMTPServerEvent::Command(SMTPCommand::Mail { path, .. }) => {
                        recipients.clear();
                        // The sender is the authenticated user (RFC 6409 §6.1).
                        let local =
                            path.to_string().trim_matches(['<', '>']).split('@').next().unwrap_or_default().to_string();
                        match user.as_deref() == Some(local.as_str()) {
                            true => Some(SMTPReply::new(250, "OK")),
                            false => Some(SMTPReply::new(550, "5.7.1 The sender is not the authenticated user")),
                        }
                    }
                    SMTPServerEvent::Command(SMTPCommand::Rcpt { path, .. }) => {
                        let local =
                            path.to_string().trim_matches(['<', '>']).split('@').next().unwrap_or_default().to_string();
                        match self.directory(&local) {
                            Some(_) => {
                                recipients.push(local);
                                Some(SMTPReply::new(250, "OK"))
                            }
                            None => Some(SMTPReply::new(550, "5.1.1 No such mailbox")),
                        }
                    }
                    SMTPServerEvent::Command(SMTPCommand::Data) => {
                        Some(SMTPReply::new(354, "End data with <CR><LF>.<CR><LF>"))
                    }
                    SMTPServerEvent::Command(_) => Some(SMTPReply::new(250, "OK")),
                    SMTPServerEvent::Data(data) => {
                        message.extend_from_slice(&data);
                        None
                    }
                    SMTPServerEvent::DataEnd { last } => {
                        if !last {
                            Some(SMTPReply::new(250, "OK"))
                        } else {
                            let from = user.clone().unwrap_or_default();
                            let delivered =
                                recipients.iter().filter(|recipient| self.deliver(recipient, &message)).count();
                            println!("smtp: {from} sent \"{}\" to {delivered}", Resource::subject(&message));
                            message.clear();
                            Some(SMTPReply::new(250, "Queued"))
                        }
                    }
                    SMTPServerEvent::DataRejected(_) => {
                        message.clear();
                        None
                    }
                    _ => None,
                };
                if let Some(reply) = reply {
                    server.reply(reply, now).expect("a reply");
                }
            }
        }
        out.clear();
        server.transmit(&mut out);
        let _ = stream.write_all(&out);
    }

    /// One POP3 connection: `AUTH OAUTHBEARER`, then the user's maildrop.
    pub fn pop3(&self, mut stream: TcpStream) {
        let start = Clock::now();
        let settings = POP3ServerConfig {
            sasl_mechanisms: vec!["OAUTHBEARER".into()],
            passwords_require_tls: false,
            ..POP3ServerConfig::default()
        };
        let Ok(mut server) = POP3Server::new(POP3Config::default(), settings, false) else { return };
        server.greet(POP3Response::ok("umilib POP3 server ready"), Tool::now(start)).expect("a greeting");
        let (mut messages, mut failed) = (Vec::<Vec<u8>>::new(), false);
        let mut out = Vec::new();
        while server.is_open() {
            out.clear();
            server.transmit(&mut out);
            let now = Tool::now(start);
            let Some(input) = Tool::exchange(&mut stream, &out, Tool::wait(server.poll_timeout(), now)) else { break };
            let now = Tool::now(start);
            server.receive(&input, now);
            if server.poll_timeout().is_some_and(|deadline| deadline <= now) {
                server.expire(now);
            }
            while let Some(event) = server.poll_event() {
                let authenticate =
                    |response: &[u8], server: &mut POP3Server, failed: &mut bool, messages: &mut Vec<Vec<u8>>| {
                        if *failed {
                            *failed = false;
                            server.reply(POP3Response::error("authentication failed"), now).expect("a reply");
                            return;
                        }
                        match self.mail_user(response) {
                            Ok(user) => {
                                println!("pop3: {user} authenticated");
                                *messages = self.mailbox(&user);
                                server.reply(POP3Response::ok("maildrop locked and ready"), now).expect("a reply");
                            }
                            Err(error) => {
                                *failed = true;
                                server.auth_challenge(&error, now).expect("a challenge");
                            }
                        }
                    };
                match event {
                    POP3ServerEvent::Command(POP3Command::Auth { initial: Some(response), .. }) => {
                        failed = false;
                        authenticate(&response, &mut server, &mut failed, &mut messages)
                    }
                    POP3ServerEvent::Command(POP3Command::Auth { initial: None, .. }) => {
                        failed = false;
                        server.auth_challenge(b"", now).expect("a challenge")
                    }
                    POP3ServerEvent::AuthCancelled => failed = false,
                    POP3ServerEvent::AuthResponse(response) => {
                        authenticate(&response, &mut server, &mut failed, &mut messages)
                    }
                    POP3ServerEvent::Command(command) => {
                        let size = |message: &Vec<u8>| POP3MultiLineWriter::canonical_length(message);
                        let message =
                            |number: u32| (number as usize).checked_sub(1).and_then(|index| messages.get(index));
                        let (response, data) = match &command {
                            POP3Command::Stat => (
                                POP3Response::ok(&format!(
                                    "{} {}",
                                    messages.len(),
                                    messages.iter().map(size).sum::<u64>()
                                )),
                                None,
                            ),
                            POP3Command::List(None) => {
                                let lines: String = messages
                                    .iter()
                                    .enumerate()
                                    .map(|(index, message)| format!("{} {}\r\n", index + 1, size(message)))
                                    .collect();
                                (POP3Response::ok(&format!("{} messages", messages.len())), Some(lines.into_bytes()))
                            }
                            POP3Command::Retr(number) => match message(*number) {
                                Some(message) => {
                                    (POP3Response::ok(&format!("{} octets", size(message))), Some(message.clone()))
                                }
                                None => (POP3Response::error("no such message"), None),
                            },
                            POP3Command::Noop | POP3Command::Rset => (POP3Response::ok(""), None),
                            POP3Command::Quit => (POP3Response::ok("umilib POP3 server signing off"), None),
                            _ => (POP3Response::error("not implemented"), None),
                        };
                        let multi = response.ok && command.is_multi_line();
                        server.reply(response, now).expect("a reply");
                        if multi {
                            server.send_data(&data.unwrap_or_default()).expect("the lines");
                            server.end_data(now).expect("the end");
                        }
                    }
                    _ => {}
                }
            }
        }
        out.clear();
        server.transmit(&mut out);
        let _ = stream.write_all(&out);
    }

    /// One IMAP connection: `AUTHENTICATE OAUTHBEARER`, then INBOX read-only.
    pub fn imap(&self, mut stream: TcpStream) {
        let start = Clock::now();
        let settings = IMAPServerConfig {
            auth_mechanisms: vec!["OAUTHBEARER".into()],
            passwords_require_tls: false,
            ..IMAPServerConfig::default()
        };
        let Ok(mut server) = IMAPServer::new(IMAPConfig::default(), settings, false) else { return };
        server.greet(IMAPCondition::OK, "umilib IMAP4rev2 server ready", Tool::now(start)).expect("a greeting");
        let (mut messages, mut failed) = (Vec::<Vec<u8>>::new(), false);
        let mut out = Vec::new();
        while server.is_open() {
            out.clear();
            server.transmit(&mut out);
            let now = Tool::now(start);
            let Some(input) = Tool::exchange(&mut stream, &out, Tool::wait(server.poll_timeout(), now)) else { break };
            let now = Tool::now(start);
            server.receive(&input, now);
            if server.poll_timeout().is_some_and(|deadline| deadline <= now) {
                server.expire(now);
            }
            while let Some(event) = server.poll_event() {
                let authenticate =
                    |data: &[u8], server: &mut IMAPServer, failed: &mut bool, messages: &mut Vec<Vec<u8>>| {
                        if *failed {
                            *failed = false;
                            server
                                .complete(
                                    IMAPCondition::NO,
                                    Some(IMAPResponseCode::Other { name: "AUTHENTICATIONFAILED".into(), text: None }),
                                    "AUTHENTICATE failed",
                                    now,
                                )
                                .expect("a completion");
                            return;
                        }
                        match self.mail_user(data) {
                            Ok(user) => {
                                println!("imap: {user} authenticated");
                                *messages = self.mailbox(&user);
                                server
                                    .complete(IMAPCondition::OK, None, "AUTHENTICATE completed", now)
                                    .expect("a completion");
                            }
                            Err(error) => {
                                *failed = true;
                                server.authenticate_challenge(&error, now).expect("a challenge");
                            }
                        }
                    };
                match event {
                    IMAPServerEvent::Command(command) => match &command.body {
                        IMAPCommandBody::Authenticate { initial: Some(data), .. } => {
                            failed = false;
                            authenticate(data, &mut server, &mut failed, &mut messages)
                        }
                        IMAPCommandBody::Authenticate { initial: None, .. } => {
                            failed = false;
                            server.authenticate_challenge(b"", now).expect("a challenge")
                        }
                        body => Resource::answer(&mut server, body, &messages, now),
                    },
                    IMAPServerEvent::AuthenticateResponse { data, .. } => {
                        authenticate(&data, &mut server, &mut failed, &mut messages)
                    }
                    IMAPServerEvent::AuthenticateCancelled { .. } => failed = false,
                    _ => {}
                }
            }
        }
        out.clear();
        server.transmit(&mut out);
        let _ = stream.write_all(&out);
    }

    /// Answers a command of the read-only INBOX of `messages`.
    pub fn answer(server: &mut IMAPServer, body: &IMAPCommandBody, messages: &[Vec<u8>], now: Instant) {
        let ok = |server: &mut IMAPServer, code: Option<IMAPResponseCode>, text: &str| {
            server.complete(IMAPCondition::OK, code, text, now).expect("a completion");
        };
        match body {
            IMAPCommandBody::Select(mailbox) | IMAPCommandBody::Examine(mailbox) if mailbox.is_inbox() => {
                server.respond(&IMAPResponse::Exists(messages.len() as u32)).expect("EXISTS");
                server.respond(&IMAPResponse::Flags(vec!["\\Seen".into()])).expect("FLAGS");
                server
                    .respond(&IMAPResponse::untagged(IMAPCondition::OK, Some(IMAPResponseCode::UIDValidity(1)), ""))
                    .expect("OK");
                ok(server, Some(IMAPResponseCode::ReadOnly), "SELECT completed")
            }
            IMAPCommandBody::Select(_) | IMAPCommandBody::Examine(_) => {
                server.complete(IMAPCondition::NO, None, "no such mailbox", now).expect("NO")
            }
            IMAPCommandBody::List { .. } => {
                let response = IMAPResponse::List {
                    lsub: false,
                    attributes: vec!["\\HasNoChildren".into()],
                    delimiter: Some('/'),
                    mailbox: IMAPMailbox::inbox(),
                    extended: Vec::new(),
                };
                server.respond(&response).expect("LIST");
                ok(server, None, "LIST completed")
            }
            IMAPCommandBody::Fetch { uid, set, attributes } => {
                let last = messages.len() as u32;
                for (index, message) in messages.iter().enumerate() {
                    let number = index as u32 + 1;
                    if !set.contains(number, last) {
                        continue;
                    }
                    let entity = MIMEEntity::decode(message, &MailConfig::default()).ok();
                    let mut items: Vec<IMAPFetchItem> = attributes
                        .iter()
                        .filter_map(|attribute| match attribute {
                            IMAPFetchAttribute::UID => Some(IMAPFetchItem::UID(number)),
                            IMAPFetchAttribute::Flags => Some(IMAPFetchItem::Flags(Vec::new())),
                            IMAPFetchAttribute::RFC822Size => Some(IMAPFetchItem::RFC822Size(message.len() as u64)),
                            IMAPFetchAttribute::RFC822 => Some(IMAPFetchItem::RFC822(Some(message.clone()))),
                            IMAPFetchAttribute::BodySection { section, .. } => {
                                let data = entity.as_ref().and_then(|entity| section.extract(entity, message));
                                Some(IMAPFetchItem::BodySection { section: section.clone(), origin: None, data })
                            }
                            _ => None,
                        })
                        .collect();
                    if *uid && !attributes.contains(&IMAPFetchAttribute::UID) {
                        items.insert(0, IMAPFetchItem::UID(number));
                    }
                    server.respond(&IMAPResponse::Fetch { number, items }).expect("FETCH");
                }
                ok(server, None, "FETCH completed")
            }
            _ => ok(server, None, "completed"),
        }
    }
}

/// `serve`: the processes and their listeners.
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
pub struct Serve;

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
impl Serve {
    /// The environment variable that gives the workers the public keys of the server.
    pub const KEYS: &'static str = "UMILIB_INTEGRATED_KEYS";

    pub fn run(arguments: &Arguments) {
        let ports = [
            arguments.port("--auth", 9080),
            arguments.port("--api", 9081),
            arguments.port("--smtp", 2525),
            arguments.port("--imap", 1143),
            arguments.port("--pop", 1110),
        ];
        let issuer = format!("http://127.0.0.1:{}", ports[0]);
        let origin = format!("http://127.0.0.1:{}", ports[1]);
        let state = PathBuf::from(arguments.get("--state").unwrap_or("integrated-state"));
        if let Some(mut worker) = Worker::current().unwrap_or_else(|error| Tool::fail(&error.to_string())) {
            let keys = std::env::var(Serve::KEYS).unwrap_or_else(|_| Tool::fail("the keys of the server"));
            let keys = JWKSet::from_json(keys.as_bytes()).unwrap_or_else(|error| Tool::fail(&error.to_string()));
            let listeners: Vec<TcpListener> =
                worker.take_listeners().into_iter().map(|socket| socket.into_tcp_listener()).collect();
            let resource = Arc::new(Resource::new(&origin, &issuer, keys, &state));
            Worker::watch(|| std::process::exit(0)).unwrap_or_else(|error| Tool::fail(&error.to_string()));
            println!("worker {} (process {})", worker.index(), std::process::id());
            Serve::resources(listeners, resource);
            return;
        }
        let users: BTreeMap<String, String> = match arguments.all("--user") {
            users if users.is_empty() => [("alice", "wonderland"), ("bob", "builder")]
                .iter()
                .map(|(user, password)| (user.to_string(), password.to_string()))
                .collect(),
            users => users
                .iter()
                .filter_map(|user| user.split_once(':'))
                .map(|(user, password)| (user.into(), password.into()))
                .collect(),
        };
        // RFC 9068 §5: a user named as a client would be taken for its tokens.
        if let Some(user) = users.keys().find(|user| ["console", "cli", "service", "api"].contains(&user.as_str())) {
            Tool::fail(&format!("the user {user} has the name of a client"));
        }
        for user in users.keys() {
            std::fs::create_dir_all(state.join("mail").join(user))
                .unwrap_or_else(|error| Tool::fail(&error.to_string()));
        }
        let key = JWK::from_private_key(
            &PrivateKey::generate(KeyAlgorithm::EC(NamedCurve::P256), &mut Random).expect("a key"),
        )
        .expect("a JWK");
        let keys = JWKSet { keys: vec![key.to_public().expect("a public key")], other: JSONObject::new() };
        let bind = |port: u16| {
            ListenerConfig::default()
                .bind(Conversion::address(std::net::SocketAddr::from(([127, 0, 0, 1], port))))
                .unwrap_or_else(|error| Tool::fail(&format!("port {port}: {error:?}")))
        };
        let authority_listener = bind(ports[0]).into_tcp_listener();
        let shared: Vec<_> = ports[1..].iter().map(|port| bind(*port)).collect();
        let authority = Arc::new(Mutex::new(Authority::new(&issuer, &origin, key, users)));
        let router = Arc::new(Authority::router());
        println!("authorization server: {issuer}");
        println!("api: {origin}, smtp: {}, imap: {}, pop3: {}", ports[2], ports[3], ports[4]);
        let _ = std::io::stdout().flush();
        let handle: Arc<dyn Fn(&Exchange) -> OAuthHTTPResponse + Send + Sync> =
            Arc::new(move |exchange| authority.lock().expect("the authority").handle(&router, exchange));
        let workers: usize = arguments.get("--workers").map_or(2, |count| count.parse().unwrap_or(2));
        if workers == 0 {
            let resource = Arc::new(Resource::new(&origin, &issuer, keys, &state));
            let listeners = shared.into_iter().map(|socket| socket.into_tcp_listener()).collect();
            std::thread::spawn(move || Serve::resources(listeners, resource));
            HTTP::serve(authority_listener, handle);
            return;
        }
        std::thread::spawn(move || HTTP::serve(authority_listener, handle));
        let config = SupervisorConfig {
            workers,
            environment: vec![(Serve::KEYS.into(), keys.to_json().into())],
            ..SupervisorConfig::default()
        };
        let mut supervisor = Supervisor::new(config, shared);
        supervisor.run(|| false).unwrap_or_else(|error| Tool::fail(&error.to_string()));
    }

    /// Serves the API, SMTP, IMAP and POP3 on `listeners`, in this order.
    pub fn resources(listeners: Vec<TcpListener>, resource: Arc<Resource>) {
        let mut listeners = listeners.into_iter();
        let (api, smtp, imap, pop) = match (listeners.next(), listeners.next(), listeners.next(), listeners.next()) {
            (Some(api), Some(smtp), Some(imap), Some(pop)) => (api, smtp, imap, pop),
            _ => Tool::fail("four listeners"),
        };
        type Session = fn(&Resource, TcpStream);
        for (listener, session) in [(smtp, Resource::smtp as Session), (imap, Resource::imap), (pop, Resource::pop3)] {
            let resource = resource.clone();
            std::thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    let resource = resource.clone();
                    std::thread::spawn(move || session(&resource, stream));
                }
            });
        }
        let router = Arc::new(Resource::router());
        HTTP::serve(api, Arc::new(move |exchange| resource.handle(&router, exchange)));
    }
}

/// The client commands, against any authorization server.
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
pub struct Client;

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
impl Client {
    /// The metadata at `location`, checked against its issuer (RFC 8414 §3.3).
    pub fn metadata(location: &str) -> OAuthMetadata {
        let response = HTTP::fetch("GET", location, &[("accept".into(), OAuthHTTPRequest::JSON.into())], &[]);
        if response.status != 200 {
            Tool::fail(&format!("metadata: status {}", response.status));
        }
        let metadata = OAuthMetadata::decode(OAuthMetadataKind::Server, &response.body)
            .unwrap_or_else(|error| Tool::fail(&format!("metadata: {error}")));
        let issuer = metadata.identifier().expect("an issuer").to_string();
        // The location of an issuer is fixed by RFC 8414 §3.1; a server that serves its metadata
        // elsewhere (OpenID Connect discovery) is taken as it is named on the command line.
        if OAuthMetadata::location(OAuthMetadataKind::Server, &issuer).ok().as_deref() == Some(location) {
            metadata.check(&issuer).unwrap_or_else(|error| Tool::fail(&error.to_string()));
        }
        println!("issuer: {issuer}");
        metadata
    }

    pub fn client(metadata: &OAuthMetadata, authentication: OAuthClientAuthentication) -> OAuthClient {
        let config = OAuthClientConfig::from_metadata(metadata, authentication, "http://127.0.0.1/cb")
            .unwrap_or_else(|error| Tool::fail(&error.to_string()));
        OAuthClient::new(config)
    }

    /// Prints the token response of `response`, or fails with its error.
    pub fn tokens(response: &OAuthHTTPResponse) -> OAuthTokenResponse {
        match OAuthTokenResponse::decode(response.status, &response.body) {
            Ok(tokens) => {
                println!("token_type: {}", tokens.token_type);
                println!("access_token: {}", tokens.access_token);
                if let Some(scope) = &tokens.scope {
                    println!("scope: {scope}");
                }
                tokens
            }
            Err(error) => Tool::fail(&format!("token: {error}")),
        }
    }

    pub fn client_credentials(arguments: &Arguments) {
        let metadata = Client::metadata(arguments.position(1, "METADATA"));
        let authentication = OAuthClientAuthentication::SecretBasic {
            client_id: arguments.position(2, "CLIENT").into(),
            secret: umilib::secret::Secret::new(arguments.position(3, "SECRET").into()),
        };
        let client = Client::client(&metadata, authentication);
        let mut request = OAuthTokenRequest::new(OAuthGrant::ClientCredentials);
        request.resources = arguments.all("--resource").iter().map(|resource| resource.to_string()).collect();
        let mut http = client
            .token_request(&request, Tool::time(), &mut Random)
            .unwrap_or_else(|error| Tool::fail(&error.to_string()));
        let key = arguments.has("--dpop").then(|| {
            JWK::from_private_key(
                &PrivateKey::generate(KeyAlgorithm::EC(NamedCurve::P256), &mut Random).expect("a key"),
            )
            .expect("a JWK")
        });
        if let Some(key) = &key {
            let target = DPoPTarget { method: "POST", uri: &client.config().token_endpoint, access_token: None };
            let proof =
                DPoPProof::create(key, JWSAlgorithm::ES256, &target, Tool::time(), None, &mut Random).expect("a proof");
            http.headers.push(("dpop".into(), proof));
        }
        let tokens = Client::tokens(&HTTP::send(&http));
        if let (Some(key), Some(api)) = (&key, arguments.get("--api")) {
            let target = DPoPTarget { method: "GET", uri: api, access_token: Some(&tokens.access_token) };
            let proof =
                DPoPProof::create(key, JWSAlgorithm::ES256, &target, Tool::time(), None, &mut Random).expect("a proof");
            let headers =
                vec![("authorization".into(), format!("DPoP {}", tokens.access_token)), ("dpop".into(), proof)];
            let response = HTTP::fetch("GET", api, &headers, &[]);
            println!("api: {} {}", response.status, String::from_utf8_lossy(&response.body));
        }
    }

    pub fn device(arguments: &Arguments) {
        let metadata = Client::metadata(arguments.position(1, "METADATA"));
        let client_id = arguments.position(2, "CLIENT").to_string();
        let client = Client::client(&metadata, OAuthClientAuthentication::None { client_id });
        let endpoint = metadata
            .string(OAuthMetadata::DEVICE_AUTHORIZATION_ENDPOINT)
            .ok()
            .flatten()
            .unwrap_or_else(|| Tool::fail("no device authorization endpoint"))
            .to_string();
        let mut parameters = OAuthParameters::new();
        parameters.push_optional("scope", arguments.get("--scope"));
        let http = client.endpoint_request(&endpoint, parameters, Tool::time(), &mut Random).expect("a request");
        let response = HTTP::send(&http);
        let answer = OAuthDeviceAuthorizationResponse::decode(response.status, &response.body)
            .unwrap_or_else(|error| Tool::fail(&format!("device: {error}")));
        println!("user_code: {}", answer.user_code);
        println!("verification_uri: {}", answer.verification_uri);
        if let Some(complete) = &answer.verification_uri_complete {
            println!("verification_uri_complete: {complete}");
        }
        let _ = std::io::stdout().flush();
        let mut interval = answer.interval.unwrap_or(5);
        let deadline = Clock::now() + Duration::from_secs(answer.expires_in);
        let request = OAuthTokenRequest::new(OAuthGrant::DeviceCode { device_code: answer.device_code.clone() });
        while Clock::now() < deadline {
            std::thread::sleep(Duration::from_secs(interval));
            let http = client.token_request(&request, Tool::time(), &mut Random).expect("a request");
            let response = HTTP::send(&http);
            match OAuthTokenResponse::decode(response.status, &response.body) {
                Err(OAuthError::Response(error)) if error.code.as_str() == "authorization_pending" => continue,
                Err(OAuthError::Response(error)) if error.code.as_str() == "slow_down" => interval += 5,
                _ => {
                    Client::tokens(&response);
                    return;
                }
            }
        }
        Tool::fail("the device code expired");
    }

    pub fn introspect(arguments: &Arguments) {
        let metadata = Client::metadata(arguments.position(1, "METADATA"));
        let authentication = OAuthClientAuthentication::SecretBasic {
            client_id: arguments.position(2, "CLIENT").into(),
            secret: umilib::secret::Secret::new(arguments.position(3, "SECRET").into()),
        };
        let client = Client::client(&metadata, authentication);
        let endpoint = metadata
            .string(OAuthMetadata::INTROSPECTION_ENDPOINT)
            .ok()
            .flatten()
            .unwrap_or_else(|| Tool::fail("no introspection endpoint"))
            .to_string();
        let mut parameters = OAuthParameters::new();
        parameters.push("token", arguments.position(4, "TOKEN"));
        let http = client.endpoint_request(&endpoint, parameters, Tool::time(), &mut Random).expect("a request");
        let response = HTTP::send(&http);
        match umilib::auth::oauth::OAuthIntrospectionResponse::decode(response.status, &response.body) {
            Ok(answer) => println!(
                "active: {}{}",
                answer.active,
                answer.subject.map(|subject| format!(", sub: {subject}")).unwrap_or_default()
            ),
            Err(error) => Tool::fail(&format!("introspection: {error}")),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
fn main() {
    let arguments = Arguments::parse();
    match arguments.positional.first().map(String::as_str) {
        Some("serve") => Serve::run(&arguments),
        Some("client-credentials") => Client::client_credentials(&arguments),
        Some("device") => Client::device(&arguments),
        Some("introspect") => Client::introspect(&arguments),
        _ => Tool::fail("a command: serve, client-credentials, device or introspect"),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)))]
fn main() {
    eprintln!("this example needs the operating system's random source");
}
