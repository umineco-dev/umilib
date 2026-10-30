use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;

use crate::crypto::random::Random;
use crate::protocol::ip::IPEndpoint;
use crate::runtime::Instant;

use super::{CoAPCode, CoAPEndpoint, CoAPError, CoAPEvent, CoAPMessage, CoAPOptionNumber, CoAPType};

/// A client observing a resource (RFC 7641 §4.1): where it is, its
/// token, the resource's path, and the notifications in flight.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CoAPObserver {
    pub peer: IPEndpoint,
    pub token: Vec<u8>,
    pub path: Vec<String>,
    pub notifications: Vec<u64>,
    /// When it was last sent a Confirmable notification.
    pub confirmed: Instant,
}

/// The observers of a server's resources (RFC 7641 §4): they register
/// with GET and Observe 0, deregister with Observe 1 (§3.6) or by
/// rejecting a notification (RST), and are dropped when a Confirmable
/// notification times out (§4.5) or after a notification of an error (§4.2).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CoAPObservers {
    pub observers: Vec<CoAPObserver>,
    /// The sequence of Observe values, of 24 bits, strictly increasing (§4.4).
    pub sequence: u32,
    /// A notification at least this often is Confirmable (§4.5: 24 hours).
    pub confirm_interval: Duration,
    /// The most observers kept.
    pub maximum: usize,
}

impl Default for CoAPObservers {
    fn default() -> CoAPObservers {
        CoAPObservers {
            observers: Vec::new(),
            sequence: 0,
            confirm_interval: Duration::from_secs(86_400),
            maximum: 1024,
        }
    }
}

impl CoAPObservers {
    /// Takes the GET or FETCH `request` of `peer` at `now`: with Observe 0
    /// the client observes the resource (an entry of the same peer and
    /// token replaced, §4.1); with Observe 1 it stops. Whether the response
    /// is to carry Observe ([`CoAPObservers::next_value`]).
    pub fn register(&mut self, peer: IPEndpoint, request: &CoAPMessage, now: Instant) -> bool {
        let observable = request.code == CoAPCode::GET || request.code == CoAPCode::FETCH;
        let path = request.options.path();
        self.observers.retain(|observer| !(observer.peer == peer && observer.token == request.token));
        match request.options.observe() {
            Some(0) if observable && self.observers.len() < self.maximum => {
                self.observers.push(CoAPObserver {
                    peer,
                    token: request.token.clone(),
                    path,
                    notifications: Vec::new(),
                    confirmed: now,
                });
                true
            }
            _ => false,
        }
    }

    /// The next Observe value (§4.4).
    pub fn next_value(&mut self) -> u32 {
        self.sequence = (self.sequence + 1) & 0xFF_FFFF;
        self.sequence
    }

    /// Sends the state of the resource at `path` to its observers (§4.2):
    /// `response` with each one's token and the next Observe value,
    /// Confirmable if `confirmable` or if the observer has not had a
    /// Confirmable one for the interval. A response of another class than
    /// 2 has no Observe, and ends the observations.
    pub fn notify<R: Random>(
        &mut self,
        endpoint: &mut CoAPEndpoint,
        path: &[String],
        response: &CoAPMessage,
        confirmable: bool,
        now: Instant,
        random: &mut R,
    ) -> Result<(), CoAPError> {
        let success = response.code.class() == 2;
        let value = if success { Some(self.next_value()) } else { None };
        let interval = self.confirm_interval;
        for observer in self.observers.iter_mut().filter(|observer| observer.path == path) {
            // The notifications the endpoint has forgotten, and has told nothing of, are done.
            observer.notifications.retain(|handle| CoAPObservers::is_live(endpoint, *handle));
            let mut message = response.clone();
            message.token = observer.token.clone();
            let confirm = confirmable || now.saturating_duration_since(observer.confirmed) >= interval;
            message.kind = if confirm { CoAPType::Confirmable } else { CoAPType::NonConfirmable };
            if confirm {
                observer.confirmed = now;
            }
            match value {
                Some(value) => {
                    message.options.set_uint(CoAPOptionNumber::OBSERVE, value);
                    observer.notifications.push(endpoint.notify(observer.peer, message, now, random)?);
                }
                None => {
                    message.options.remove(CoAPOptionNumber::OBSERVE);
                    endpoint.send_message(observer.peer, message, false, false, now, random)?;
                }
            }
        }
        if !success {
            self.observers.retain(|observer| observer.path != path);
        }
        Ok(())
    }

    /// Whether the endpoint keeps the message `handle` (sent, or waiting for
    /// NSTART), or has an event of it not yet taken: a notification that may
    /// still end its observation.
    pub fn is_live(endpoint: &CoAPEndpoint, handle: u64) -> bool {
        endpoint.outgoing.contains_key(&handle)
            || endpoint.waiting.iter().any(|(waiting, _)| *waiting == handle)
            || endpoint.events.iter().any(|event| {
                matches!(event, CoAPEvent::Timeout { message } | CoAPEvent::Reset { message } if *message == handle)
            })
    }

    /// Takes an event of the endpoint: a notification rejected or not
    /// acknowledged ends its observation (§3.6, §4.5). Whether it was one.
    pub fn handle(&mut self, event: &CoAPEvent) -> bool {
        let (CoAPEvent::Reset { message } | CoAPEvent::Timeout { message }) = event else { return false };
        let before = self.observers.len();
        self.observers.retain(|observer| !observer.notifications.contains(message));
        before != self.observers.len()
    }
}
