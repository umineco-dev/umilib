//! SCRAM against RFC 5802 (SCRAM-SHA-1) and RFC 7677 (SCRAM-SHA-256).

use umilib::auth::sasl::scram::{
    SCRAMClient, SCRAMClientFirst, SCRAMConfig, SCRAMCredentials, SCRAMError, SCRAMHash, SCRAMKeys, SCRAMNonce,
    SCRAMSecret, SCRAMServer, SCRAMServerError, SCRAMServerFinal, SCRAMServerFirst,
};
use umilib::auth::sasl::{GS2ChannelBinding, SASLMechanism};
use umilib::codec::base::Encoding;
use umilib::codec::base::base64::Base64;
use umilib::hash::sha::v1::SHA1;
use umilib::hash::sha::v2::SHA256;
use umilib::secret::Secret;

use super::random;

const RFC5802: &str = include_str!("../../vectors/auth/sasl/rfc5802.txt");
const RFC7677: &str = include_str!("../../vectors/auth/sasl/rfc7677.txt");

fn password(text: &str) -> SCRAMSecret {
    SCRAMSecret::Password(Secret::new(String::from(text)))
}

/// Runs the example exchange `messages` (client-first, server-first,
/// client-final, server-final) of user "user" and password "pencil" with
/// both sides of this module, checking that each message is the example's.
fn check_example<H: SCRAMHash>(messages: &[(char, String)]) {
    let [(client, c1), (server, s1), (_, c2), (_, s2)] = messages else { panic!("{messages:?}") };
    assert_eq!((*client, *server), ('C', 'S'));
    let client_nonce = c1.rsplit_once("r=").unwrap().1;
    let mut client = SCRAMClient::<H>::new("user", password("pencil"), client_nonce);
    assert_eq!(client.client_first().unwrap(), c1.as_bytes());
    let mut server = SCRAMServer::<H>::new(false);
    let first = server.receive_client_first(c1.as_bytes()).unwrap().clone();
    assert_eq!((first.username.as_str(), first.nonce.as_str()), ("user", client_nonce));
    assert_eq!(server.username(), Some("user"));
    let server_first = SCRAMServerFirst::decode(s1.as_bytes()).unwrap();
    assert_eq!(server_first.encode().unwrap(), s1.as_bytes());
    let credentials = SCRAMCredentials::<H>::new("pencil", &server_first.salt, server_first.iterations).unwrap();
    let server_nonce = &server_first.nonce[client_nonce.len()..];
    assert_eq!(server.server_first(&credentials, server_nonce).unwrap(), s1.as_bytes());
    assert_eq!(client.receive_server_first(s1.as_bytes()).unwrap(), c2.as_bytes());
    assert_eq!(server.receive_client_final(c2.as_bytes()).unwrap(), s2.as_bytes());
    // RFC 5802 §5: the server then checks the authorization identity against the authenticated one.
    assert_eq!((server.username(), server.authzid()), (Some("user"), None));
    client.receive_server_final(s2.as_bytes()).unwrap();
    // RFC 5802 §5.1: the SaltedPassword can be kept to log in again without Hi.
    let SCRAMSecret::SaltedPassword { salt, iterations, .. } = client.salted_secret().unwrap() else { panic!() };
    assert_eq!((salt, iterations), (server_first.salt.clone(), server_first.iterations));
    let mut again = SCRAMClient::<H>::new("user", client.salted_secret().unwrap(), client_nonce);
    again.client_first().unwrap();
    assert_eq!(again.receive_server_first(s1.as_bytes()).unwrap(), c2.as_bytes());
    let mut other_salt = SCRAMClient::<H>::new("user", client.salted_secret().unwrap(), client_nonce);
    other_salt.client_first().unwrap();
    let moved = SCRAMServerFirst { salt: vec![1; 16], ..server_first };
    assert_eq!(other_salt.receive_server_first(&moved.encode().unwrap()), Err(SCRAMError::Salt));
}

#[test]
fn rfc_5802_section_5() {
    check_example::<SHA1>(&super::exchange(RFC5802, "password 'pencil' are used):"));
    assert_eq!(SCRAMClient::<SHA1>::new("u", password("p"), "n").mechanism(), SASLMechanism::SCRAMSHA1);
}

#[test]
fn rfc_7677_section_3() {
    check_example::<SHA256>(&super::exchange(RFC7677, "'user' and password 'pencil' are being used."));
    assert_eq!(SCRAMServer::<SHA256>::new(true).mechanism(), SASLMechanism::SCRAMSHA256PLUS);
}

#[test]
fn server_errors_are_those_of_rfc_5802_section_7() {
    let grammar =
        RFC5802.split("server-error-value = ").nth(1).unwrap().split("server-error-value-ext").next().unwrap();
    let names: Vec<&str> = grammar.split('"').skip(1).step_by(2).collect();
    assert_eq!(names, SCRAMServerError::ALL.map(SCRAMServerError::name));
    for error in SCRAMServerError::ALL {
        assert_eq!(SCRAMServerError::from_name(error.name()), error);
        assert_eq!(
            SCRAMServerFinal::decode(&SCRAMServerFinal::Error(error).encode()).unwrap(),
            SCRAMServerFinal::Error(error)
        );
    }
    // Unrecognized errors are treated as other-error.
    assert_eq!(
        SCRAMServerFinal::decode(b"e=some-new-error").unwrap(),
        SCRAMServerFinal::Error(SCRAMServerError::OtherError)
    );
}

/// A client and a server of SCRAM-SHA-256 for "user" and "pencil", the
/// server holding `channel_bindings`, after the client-first-message; the
/// message is returned too.
fn started(
    binding: GS2ChannelBinding,
    data: &[u8],
    plus: bool,
    channel_bindings: &[(&str, &[u8])],
) -> (SCRAMClient<SHA256>, SCRAMServer<SHA256>, Result<Vec<u8>, SCRAMError>) {
    let mut client =
        SCRAMClient::<SHA256>::new("user", password("pencil"), &SCRAMNonce::random(&mut random()).unwrap());
    client.channel_binding = binding;
    client.channel_binding_data = data.to_vec();
    let mut server = SCRAMServer::<SHA256>::new(plus);
    for (name, data) in channel_bindings {
        server.add_channel_binding(name, data);
    }
    let message = client.client_first();
    (client, server, message)
}

fn credentials() -> SCRAMCredentials<SHA256> {
    SCRAMCredentials::new("pencil", &[7; 16], 4096).unwrap()
}

#[test]
fn channel_binding_follows_rfc_5802_section_6() {
    let exporter = GS2ChannelBinding::Required(String::from(GS2ChannelBinding::TLS_EXPORTER));
    // p= with the data of the channel: SCRAM-SHA-256-PLUS succeeds.
    let (mut client, mut server, first) =
        started(exporter.clone(), b"exporter value", true, &[("tls-exporter", b"exporter value")]);
    assert_eq!(client.mechanism(), SASLMechanism::SCRAMSHA256PLUS);
    server.receive_client_first(&first.unwrap()).unwrap();
    let server_first = server.server_first(&credentials(), "server").unwrap();
    let client_final = client.receive_server_first(&server_first).unwrap();
    // c= is the base64 of the GS2 header and the channel binding data (RFC 5802 §7, cbind-input).
    let text = String::from_utf8(client_final.clone()).unwrap();
    assert!(text.starts_with(&format!("c={},", Base64::STANDARD.encode(b"p=tls-exporter,,exporter value"))));
    client.receive_server_final(&server.receive_client_final(&client_final).unwrap()).unwrap();
    // The data of another channel does not match.
    let (mut client, mut server, first) =
        started(exporter.clone(), b"another channel", true, &[("tls-exporter", b"exporter value")]);
    server.receive_client_first(&first.unwrap()).unwrap();
    let client_final = client.receive_server_first(&server.server_first(&credentials(), "server").unwrap()).unwrap();
    assert_eq!(
        server.receive_client_final(&client_final),
        Err(SCRAMError::Server(SCRAMServerError::ChannelBindingsDontMatch))
    );
    // y from a client of a server that supports channel binding: a downgrade.
    let (_, mut server, first) = started(GS2ChannelBinding::NotOffered, b"", false, &[("tls-exporter", b"x")]);
    assert_eq!(
        server.receive_client_first(&first.unwrap()).map(|_| ()),
        Err(SCRAMError::Server(SCRAMServerError::ServerDoesSupportChannelBinding))
    );
    // y is fine for a server without channel binding, n always on a non-PLUS mechanism.
    let (_, mut server, first) = started(GS2ChannelBinding::NotOffered, b"", false, &[]);
    server.receive_client_first(&first.unwrap()).unwrap();
    let (_, mut server, first) = started(GS2ChannelBinding::Unsupported, b"", false, &[("tls-exporter", b"x")]);
    server.receive_client_first(&first.unwrap()).unwrap();
    // p with a type the server does not support, or with none.
    let unique = GS2ChannelBinding::Required(String::from(GS2ChannelBinding::TLS_UNIQUE));
    let (_, mut server, first) = started(unique.clone(), b"x", true, &[("tls-exporter", b"x")]);
    assert_eq!(
        server.receive_client_first(&first.unwrap()).map(|_| ()),
        Err(SCRAMError::Server(SCRAMServerError::UnsupportedChannelBindingType))
    );
    let (_, mut server, first) = started(unique, b"x", true, &[]);
    assert_eq!(
        server.receive_client_first(&first.unwrap()).map(|_| ()),
        Err(SCRAMError::Server(SCRAMServerError::ChannelBindingNotSupported))
    );
    // cbind-data is present exactly for p.
    assert_eq!(started(exporter, b"", true, &[]).2, Err(SCRAMError::Format));
    assert_eq!(started(GS2ChannelBinding::Unsupported, b"x", false, &[]).2, Err(SCRAMError::Format));
}

#[test]
fn servers_follow_rfc_5802_section_5() {
    let mut server = SCRAMServer::<SHA256>::new(false);
    let invalid =
        |message: &[u8]| SCRAMServer::<SHA256>::new(false).receive_client_first(message).map(|_| ()).unwrap_err();
    // The first message starts with n, y or p.
    assert_eq!(invalid(b"F,n,,n=user,r=abc"), SCRAMError::Server(SCRAMServerError::InvalidEncoding));
    assert_eq!(invalid(b"x,,n=user,r=abc"), SCRAMError::Server(SCRAMServerError::InvalidEncoding));
    // '=' in a username not followed by 2C or 3D fails the authentication.
    assert_eq!(invalid(b"n,,n=us=2Der,r=abc"), SCRAMError::Server(SCRAMServerError::InvalidUsernameEncoding));
    // m= is a mandatory extension, not supported.
    assert_eq!(invalid(b"n,,m=ext,n=user,r=abc"), SCRAMError::Server(SCRAMServerError::ExtensionsNotSupported));
    // The nonce is printable without ','; the username is required.
    assert_eq!(invalid(b"n,,n=user,r=a b"), SCRAMError::Server(SCRAMServerError::InvalidEncoding));
    assert_eq!(invalid(b"n,,r=abc"), SCRAMError::Server(SCRAMServerError::InvalidEncoding));
    // A username that SASLprep refuses (U+0007, a control character).
    assert_eq!(
        invalid("n,,n=a\u{0007},r=abc".as_bytes()),
        SCRAMError::Server(SCRAMServerError::InvalidUsernameEncoding)
    );
    // Unknown optional extensions are ignored; escapes are undone; the username is prepared.
    let first = server.receive_client_first("n,a=ad=2Cmin,n=U\u{0301}=2Cx,r=abc,x=ext".as_bytes()).unwrap().clone();
    assert_eq!(first.username, "U\u{0301},x");
    assert_eq!(first.header.authzid.as_deref(), Some("ad,min"));
    assert_eq!(first.extensions, vec![('x', String::from("ext"))]);
    assert_eq!(server.username(), Some("\u{00DA},x"));
    assert_eq!(server.authzid(), Some("ad,min"));
    // A wrong password gives an invalid proof; the nonce of the client-final-message is the full one.
    let mut client = SCRAMClient::<SHA256>::new("user", password("wrong"), "abc");
    let mut server = SCRAMServer::<SHA256>::new(false);
    server.receive_client_first(&client.client_first().unwrap()).unwrap();
    let client_final = client.receive_server_first(&server.server_first(&credentials(), "def").unwrap()).unwrap();
    assert_eq!(server.receive_client_final(&client_final), Err(SCRAMError::Server(SCRAMServerError::InvalidProof)));
    assert_eq!(server.reject(SCRAMServerError::InvalidProof), b"e=invalid-proof");
    assert_eq!(
        client.receive_server_final(b"e=invalid-proof"),
        Err(SCRAMError::Server(SCRAMServerError::InvalidProof))
    );
    // Steps out of order.
    assert_eq!(server.receive_client_final(&client_final), Err(SCRAMError::State));
    let mut fresh = SCRAMServer::<SHA256>::new(false);
    assert_eq!(fresh.server_first(&credentials(), "x"), Err(SCRAMError::State));
    // A replaced nonce or a changed message is refused.
    let mut client = SCRAMClient::<SHA256>::new("user", password("pencil"), "abc");
    let mut server = SCRAMServer::<SHA256>::new(false);
    server.receive_client_first(&client.client_first().unwrap()).unwrap();
    let client_final =
        String::from_utf8(client.receive_server_first(&server.server_first(&credentials(), "def").unwrap()).unwrap())
            .unwrap();
    let replaced = client_final.replace("r=abcdef", "r=abcdeg");
    assert_eq!(
        server.clone().receive_client_final(replaced.as_bytes()),
        Err(SCRAMError::Server(SCRAMServerError::OtherError))
    );
    let extended = client_final.replace(",p=", ",x=1,p=");
    assert_eq!(
        server.clone().receive_client_final(extended.as_bytes()),
        Err(SCRAMError::Server(SCRAMServerError::InvalidProof))
    );
    let mandatory = client_final.replace(",p=", ",m=1,p=");
    assert_eq!(
        server.receive_client_final(mandatory.as_bytes()),
        Err(SCRAMError::Server(SCRAMServerError::ExtensionsNotSupported))
    );
}

#[test]
fn clients_follow_rfc_5802_section_5() {
    let first = |config: SCRAMConfig| {
        let mut client = SCRAMClient::<SHA256>::new("user", password("pencil"), "abc");
        client.config = config;
        client.client_first().unwrap();
        client
    };
    let server_first = |nonce: &str, iterations: u32| {
        SCRAMServerFirst { nonce: nonce.into(), salt: vec![1; 16], iterations, extensions: vec![] }.encode().unwrap()
    };
    // The client nonce must begin the server's, and the server adds to it.
    for nonce in ["abd123", "abc", "xabc123"] {
        assert_eq!(
            first(SCRAMConfig::default()).receive_server_first(&server_first(nonce, 4096)),
            Err(SCRAMError::Nonce),
            "{nonce}"
        );
    }
    // The iteration count is within the configuration (RFC 7677 §3: at least 4096).
    assert_eq!(
        first(SCRAMConfig::default()).receive_server_first(&server_first("abc1", 4095)),
        Err(SCRAMError::Iterations)
    );
    let bounded = SCRAMConfig { maximum_iterations: 5000, ..SCRAMConfig::default() };
    assert_eq!(first(bounded).receive_server_first(&server_first("abc1", 5001)), Err(SCRAMError::Iterations));
    // m= in a server message fails; i= is a positive number.
    assert_eq!(
        first(SCRAMConfig::default()).receive_server_first(b"m=x,r=abc1,s=AQID,i=4096"),
        Err(SCRAMError::Extension)
    );
    for message in [
        &b"r=abc1,s=AQID,i=0"[..],
        b"r=abc1,s=AQID,i=04096",
        b"r=abc1,s=AQID",
        b"r=abc1,i=4096,s=AQID",
        b"r=abc1,s=!!,i=4096",
    ] {
        assert_eq!(first(SCRAMConfig::default()).receive_server_first(message), Err(SCRAMError::Format), "{message:?}");
    }
    assert_eq!(
        first(SCRAMConfig::default()).receive_server_first(b"r=abc1,s=AQID,i=99999999999"),
        Err(SCRAMError::Iterations)
    );
    // A ServerSignature that does not verify fails the exchange (RFC 5802 §5).
    let mut client = first(SCRAMConfig::default());
    client.receive_server_first(&server_first("abc1", 4096)).unwrap();
    assert_eq!(
        client.receive_server_final(&SCRAMServerFinal::Verifier(vec![0; 32]).encode()),
        Err(SCRAMError::ServerSignature)
    );
    assert_eq!(client.receive_server_final(b"v=AAAA"), Err(SCRAMError::State), "the exchange has failed");
    assert!(client.salted_secret().is_none());
}

#[test]
fn usernames_and_passwords_are_prepared() {
    // RFC 5802 §5.1: ',' and '=' in usernames are sent as =2C and =3D.
    let mut client = SCRAMClient::<SHA256>::new("a,b=c", password("p"), "abc");
    assert_eq!(client.client_first().unwrap(), b"n,,n=a=2Cb=3Dc,r=abc");
    // Usernames are SASLprep'ed as queries; passwords as stored strings (RFC 5802 §2.2).
    let mut client = SCRAMClient::<SHA256>::new("\u{2168}", password("p"), "abc");
    assert_eq!(client.client_first().unwrap(), b"n,,n=IX,r=abc");
    let soft = SCRAMKeys::<SHA256>::from_password("I\u{00AD}X", &[1; 8], 4096).unwrap();
    let plain = SCRAMKeys::<SHA256>::from_password("IX", &[1; 8], 4096).unwrap();
    assert_eq!(soft.stored_key.expose(), plain.stored_key.expose());
    assert!(SCRAMKeys::<SHA256>::from_password("\u{0221}", &[1; 8], 4096).is_err(), "unassigned in a stored string");
    let mut refused = SCRAMClient::<SHA256>::new("a\u{0007}", password("p"), "abc");
    assert!(matches!(refused.client_first(), Err(SCRAMError::Prepare(_))));
    assert_eq!(refused.client_first(), Err(SCRAMError::State), "a failed exchange takes no further step");
    // The keys of RFC 5802 §3: StoredKey = H(ClientKey).
    assert_eq!(plain.stored_key.expose(), <SHA256 as umilib::hash::Digest>::digest(plain.client_key.expose()).as_ref());
    // Credentials keep only StoredKey and ServerKey; their parts are checked against the hash.
    let credentials = SCRAMCredentials::<SHA256>::from_keys(&plain, &[1; 8], 4096);
    assert!(
        SCRAMCredentials::<SHA256>::from_parts(
            &[1; 8],
            4096,
            credentials.stored_key.expose(),
            credentials.server_key.expose()
        )
        .is_ok()
    );
    assert!(SCRAMCredentials::<SHA256>::from_parts(&[1; 8], 4096, &[0; 20], &[0; 32]).is_err());
    // RFC 5802 §7: s= holds a value of one character or more, so a salt is not empty.
    assert_eq!(SCRAMCredentials::<SHA256>::new("p", &[], 4096).map(|_| ()), Err(SCRAMError::Format));
    let stored = credentials.stored_key.expose();
    assert!(SCRAMCredentials::<SHA256>::from_parts(&[], 4096, stored, credentials.server_key.expose()).is_err());
    let empty = SCRAMServerFirst { nonce: String::from("abc"), salt: vec![], iterations: 4096, extensions: vec![] };
    assert_eq!(empty.encode(), Err(SCRAMError::Format));
}

#[test]
fn messages_read_back() {
    let first = SCRAMClientFirst::decode(b"y,a=admin,n=user,r=nonce,z=1").unwrap();
    assert_eq!(first.encode().unwrap(), b"y,a=admin,n=user,r=nonce,z=1");
    assert_eq!(first.bare().unwrap(), "n=user,r=nonce,z=1");
    let final_message = umilib::auth::sasl::scram::SCRAMClientFinal::decode(b"c=biws,r=nonce,p=AQID").unwrap();
    assert_eq!(final_message.channel_binding, b"n,,");
    assert_eq!(final_message.encode().unwrap(), b"c=biws,r=nonce,p=AQID");
    assert_eq!(SCRAMNonce::random(&mut random()).unwrap().len(), 32);
}
