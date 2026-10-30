"""Tests of umilib.service: patterns of bytes and routers of services."""

import pytest

from umilib.service import Pattern, Router, ServiceStatusError


def test_patterns_match_as_their_text_says():
    host = Pattern.parse("*.example.com")
    assert host.matches_bytes(b"auth.example.com")
    assert not host.matches_bytes(b"example.com")
    assert not host.matches_bytes(b"auth.EXAMPLE.com")
    folded = host.ignoring_ascii_case()
    assert folded.ignores_ascii_case and not host.ignores_ascii_case
    assert folded.matches_bytes(b"auth.EXAMPLE.com")
    assert Pattern.parse(b"/oauth/*").matches_bytes(b"/oauth/token")
    assert Pattern.parse("*").matches_bytes(b"")
    assert Pattern.parse("h3").matches_bytes(b"h3") and not Pattern.parse("h3").matches_bytes(b"h3-29")
    for text in [b"*", b"", b"exact", b"*suffix", b"prefix*", b"\\*", b"\\**", b"*\\*", b"a\\\\b"]:
        assert Pattern.parse(Pattern.parse(text).format()).format() == Pattern.parse(text).format()
    assert Pattern.parse("\\a").format() == b"a"


def test_text_that_is_not_a_pattern_is_rejected():
    for text, name in [("a*b", "MisplacedWildcard"), ("*a*", "MisplacedWildcard"), ("a\\", "UnfinishedEscape")]:
        with pytest.raises(ServiceStatusError) as error:
            Pattern.parse(text)
        assert error.value.name == name


def test_routers_give_requests_to_the_first_matching_route():
    router = Router().route(Pattern.parse("/oauth/*"), lambda request: b"oauth " + request)
    router.push(Pattern.parse("/api/*"), lambda request: b"api " + request)
    router.push(Pattern.parse("/api/admin/*"), lambda request: b"never")
    assert len(router) == 3
    assert router.call(b"/oauth/token") == b"oauth /oauth/token"
    assert router.call(b"/api/admin/x") == b"api /api/admin/x"
    with pytest.raises(ServiceStatusError) as error:
        router.call(b"/missing")
    assert error.value.name == "Unrouted"
    router.set_fallback(lambda request: b"fallback")
    assert router.call(b"/missing") == b"fallback"
    router.set_fallback(None)
    with pytest.raises(ServiceStatusError):
        router.call(b"/missing")


def test_exceptions_of_services_are_raised_by_the_call():
    def fail(request):
        raise ValueError("the service fails")

    router = Router().route(Pattern.parse("*"), fail)
    with pytest.raises(ValueError, match="the service fails"):
        router.call(b"x")
    # A service that answers what is not bytes fails too.
    router = Router().route(Pattern.parse("*"), lambda request: 42)
    with pytest.raises(TypeError):
        router.call(b"x")


def test_fallbacks_replaced_and_routers_closed_release_their_services():
    router = Router().route(Pattern.parse("/a"), lambda request: b"a")
    router.set_fallback(lambda request: b"first")
    assert len(router.callbacks) == 2
    router.set_fallback(lambda request: b"second")
    assert len(router.callbacks) == 2
    assert router.call(b"/other") == b"second"
    router.close()
    assert router.callbacks == {}


def test_a_failed_push_keeps_nothing():
    router = Router()
    pattern = Pattern.parse("*")
    pattern.close()
    with pytest.raises(Exception):
        router.push(pattern, lambda request: b"")
    assert router.callbacks == {}
    assert len(router) == 0


def test_a_service_cannot_use_its_own_router():
    router = Router()
    router.push(Pattern.parse("*"), lambda request: router.call(b"again"))
    with pytest.raises(Exception) as error:
        router.call(b"x")
    assert getattr(error.value, "name", None) == "Reentrant"


def test_concurrent_calls_raise_their_own_exceptions():
    import sys
    import threading

    def fail(request):
        raise ValueError(request.decode())

    router = Router().route(Pattern.parse("*"), fail)
    mixed = []

    def caller(name):
        for _ in range(500):
            try:
                router.call(name.encode())
            except ValueError as error:
                if str(error) != name:
                    mixed.append((name, str(error)))
            except Exception as error:  # noqa: BLE001 - recorded: the exception was lost
                mixed.append((name, repr(error)))

    interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        threads = [threading.Thread(target=caller, args=(f"thread {index}",)) for index in range(4)]
        [thread.start() for thread in threads]
        [thread.join() for thread in threads]
    finally:
        sys.setswitchinterval(interval)
    assert mixed == []
