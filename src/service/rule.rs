use alloc::boxed::Box;
use alloc::sync::Arc;

/// Whether a request is for a route of a [`Router`](super::Router).
pub trait Rule<Request> {
    fn matches(&self, request: &Request) -> bool;

    /// The rule that matches what both this one and `other` match.
    fn and<O: Rule<Request>>(self, other: O) -> AndRule<Self, O>
    where
        Self: Sized,
    {
        AndRule::new(self, other)
    }

    /// The rule that matches what this one or `other` matches.
    fn or<O: Rule<Request>>(self, other: O) -> OrRule<Self, O>
    where
        Self: Sized,
    {
        OrRule::new(self, other)
    }

    /// The rule that matches what this one does not.
    fn not(self) -> NotRule<Self>
    where
        Self: Sized,
    {
        NotRule::new(self)
    }
}

impl<Request, R: Rule<Request> + ?Sized> Rule<Request> for &R {
    fn matches(&self, request: &Request) -> bool {
        (**self).matches(request)
    }
}

impl<Request, R: Rule<Request> + ?Sized> Rule<Request> for Box<R> {
    fn matches(&self, request: &Request) -> bool {
        (**self).matches(request)
    }
}

impl<Request, R: Rule<Request> + ?Sized> Rule<Request> for Arc<R> {
    fn matches(&self, request: &Request) -> bool {
        (**self).matches(request)
    }
}

/// The rule that matches every request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AnyRule;

impl<Request> Rule<Request> for AnyRule {
    fn matches(&self, _request: &Request) -> bool {
        true
    }
}

/// The rule that matches what both of its rules match (the second is not
/// asked if the first does not match).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AndRule<A, B> {
    pub first: A,
    pub second: B,
}

impl<A, B> AndRule<A, B> {
    pub const fn new(first: A, second: B) -> AndRule<A, B> {
        AndRule { first, second }
    }
}

impl<Request, A: Rule<Request>, B: Rule<Request>> Rule<Request> for AndRule<A, B> {
    fn matches(&self, request: &Request) -> bool {
        self.first.matches(request) && self.second.matches(request)
    }
}

/// The rule that matches what either of its rules matches (the second is
/// not asked if the first matches).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrRule<A, B> {
    pub first: A,
    pub second: B,
}

impl<A, B> OrRule<A, B> {
    pub const fn new(first: A, second: B) -> OrRule<A, B> {
        OrRule { first, second }
    }
}

impl<Request, A: Rule<Request>, B: Rule<Request>> Rule<Request> for OrRule<A, B> {
    fn matches(&self, request: &Request) -> bool {
        self.first.matches(request) || self.second.matches(request)
    }
}

/// The rule that matches what its rule does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotRule<A> {
    pub rule: A,
}

impl<A> NotRule<A> {
    pub const fn new(rule: A) -> NotRule<A> {
        NotRule { rule }
    }
}

impl<Request, A: Rule<Request>> Rule<Request> for NotRule<A> {
    fn matches(&self, request: &Request) -> bool {
        !self.rule.matches(request)
    }
}

/// The rule of a function of the request.
#[derive(Clone, Copy, Debug)]
pub struct FunctionRule<F> {
    function: F,
}

impl<F> FunctionRule<F> {
    pub const fn new(function: F) -> FunctionRule<F> {
        FunctionRule { function }
    }

    pub fn function(&self) -> &F {
        &self.function
    }
}

impl<Request, F: Fn(&Request) -> bool> Rule<Request> for FunctionRule<F> {
    fn matches(&self, request: &Request) -> bool {
        (self.function)(request)
    }
}
