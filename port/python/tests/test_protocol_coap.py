"""Tests of umilib.protocol.coap against the rules and examples of RFC 7252 (messages, options, the
message layer, requests and responses), RFC 8974 (extended tokens), RFC 7641 (observation), RFC 7959
(block-wise transfers) and RFC 6690 (the CoRE Link Format): two endpoints driven from Python over a
simulated network."""

import dataclasses
import datetime

import pytest

from umilib.crypto.random import HMACDRBG
from umilib.ffi import FFIError
from umilib.hash.sha.v2 import SHA256
from umilib.protocol.coap import (
    CoAPBlock,
    CoAPBlockwise,
    CoAPCode,
    CoAPConfig,
    CoAPContentFormat,
    CoAPEndpoint,
    CoAPError,
    CoAPEvent,
    CoAPEventKind,
    CoAPLink,
    CoAPMessage,
    CoAPObservers,
    CoAPOptionFormat,
    CoAPOptionNumber,
    CoAPOptions,
    CoAPRule,
    CoAPType,
)
from umilib.protocol.ip import IPAddress, IPEndpoint

CLIENT = IPEndpoint(IPAddress.parse("192.0.2.2"), 40000)
SERVER = IPEndpoint(IPAddress.parse("192.0.2.1"), 5683)
MS = 1_000_000


def random(label: bytes = b"coap") -> HMACDRBG:
    return HMACDRBG[SHA256](b"0123456789abcdef0123456789abcdef", b"nonce of 16 byte", label)


def get(path: str, kind: CoAPType = CoAPType.CONFIRMABLE) -> CoAPMessage:
    message = CoAPMessage.new(kind, CoAPCode.GET, 0)
    options = message.options
    options.set_uri(path)
    message.options = options
    return message


def with_option(message: CoAPMessage, number: int, value: int) -> CoAPMessage:
    options = message.options
    options.set_uint(number, value)
    message.options = options
    return message


class Pair:
    """A client and a server and the datagrams between them."""

    def __init__(self, config: CoAPConfig | None = None) -> None:
        self.random = random(b"pair")
        self.client = CoAPEndpoint.new(config, self.random)
        self.server = CoAPEndpoint.new(config, self.random)

    def run(self, now: int) -> tuple[list[bytes], list[bytes]]:
        """Delivers what each has to send until neither has any; the datagrams, the client's first."""
        moved: tuple[list[bytes], list[bytes]] = ([], [])
        while True:
            before = len(moved[0]) + len(moved[1])
            while (out := self.client.transmit()) is not None:
                assert out.peer == SERVER
                moved[0].append(out.message)
                self.server.receive(CLIENT, out.message, now, self.random)
            while (out := self.server.transmit()) is not None:
                assert out.peer == CLIENT
                moved[1].append(out.message)
                self.client.receive(SERVER, out.message, now, self.random)
            if len(moved[0]) + len(moved[1]) == before:
                return moved

    @staticmethod
    def events(endpoint: CoAPEndpoint) -> list[CoAPEvent]:
        return list(iter(endpoint.poll_event, None))

    def request(self) -> CoAPEvent:
        """The one request the server has to answer."""
        events = Pair.events(self.server)
        assert [event.kind for event in events] == [CoAPEventKind.REQUEST]
        assert events[0].peer == CLIENT
        return events[0]


def header(data: bytes) -> tuple[CoAPType, CoAPCode, int]:
    message = CoAPMessage.decode(data)
    return message.kind, message.code, message.id


def test_codes_and_types_of_rfc_7252():
    # §12.1: c.dd, of a class of 3 bits and a detail of 5.
    assert (int(CoAPCode.GET), int(CoAPCode.CONTENT), int(CoAPCode.NOT_FOUND)) == (0x01, 0x45, 0x84)
    assert str(CoAPCode.CONTENT) == "2.05" and str(CoAPCode.GATEWAY_TIMEOUT) == "5.04"
    assert str(CoAPCode.CONTINUE) == "2.31" and str(CoAPCode.REQUEST_ENTITY_INCOMPLETE) == "4.08"
    assert CoAPCode.GET.is_request() and not CoAPCode.EMPTY.is_request() and CoAPCode.EMPTY.is_empty()
    assert all(CoAPCode.new(class_, 0).is_response() for class_ in (2, 4, 5))
    assert not any(CoAPCode.new(class_, 0).is_response() for class_ in (0, 1, 3, 6, 7))
    # §3: the type's two bits.
    assert [CoAPType.from_bits(bits) for bits in range(4)] == [
        CoAPType.CONFIRMABLE,
        CoAPType.NON_CONFIRMABLE,
        CoAPType.ACKNOWLEDGEMENT,
        CoAPType.RESET,
    ]
    # §12.3: the Content-Formats of the registry.
    assert (CoAPContentFormat.TEXT_PLAIN, CoAPContentFormat.LINK_FORMAT, CoAPContentFormat.JSON) == (0, 40, 50)


def test_the_message_format_of_rfc_7252():
    # §3 and the example of appendix A: a CON GET of /temperature with the token 0x20.
    message = get("/temperature")
    message.id = 0x7D34
    message.token = b"\x20"
    data = message.encode()
    assert data == bytes([0x41, 0x01, 0x7D, 0x34, 0x20, 0xBB]) + b"temperature"
    decoded = CoAPMessage.decode(data)
    assert (decoded.kind, decoded.code, decoded.id, decoded.token) == (CoAPType.CONFIRMABLE, CoAPCode.GET, 0x7D34, b"\x20")
    assert decoded.options.path() == ["temperature"]
    response = CoAPMessage.new(CoAPType.ACKNOWLEDGEMENT, CoAPCode.CONTENT, 0x7D34)
    response.token = b"\x20"
    response.payload = b"22.3 C"
    assert response.encode() == bytes([0x61, 0x45, 0x7D, 0x34, 0x20, 0xFF]) + b"22.3 C"
    # A copy is a message of its own; the options are a copy until assigned.
    copy = message.clone()
    copy.kind = CoAPType.NON_CONFIRMABLE
    options = message.options
    options.set_uri("/other")
    assert message.kind == CoAPType.CONFIRMABLE and message.options.path() == ["temperature"]
    # §3.1: deltas and lengths of 13 to 268 take one more byte (minus 13), from 269 two (minus 269).
    for number, length, expected in [
        (12, 12, b"\xcc"),
        (13, 13, b"\xdd\x00\x00"),
        (268, 268, b"\xdd\xff\xff"),
        (269, 269, b"\xee\x00\x00\x00\x00"),
        (1000, 300, b"\xee\x02\xdb\x00\x1f"),
        (65535, 1034, b"\xee\xfe\xf2\x02\xfd"),
    ]:
        message = CoAPMessage.new(CoAPType.NON_CONFIRMABLE, CoAPCode.POST, 1)
        options = CoAPOptions()
        options.push(number, b"x" * length)
        message.options = options
        data = message.encode()
        assert data[4 : 4 + len(expected)] == expected, (number, length)
        assert CoAPMessage.decode(data).options.entries == [(number, b"x" * length)]
    # §3.1, §5.4.5: options in the order of their numbers, repeated ones in the order given.
    message = CoAPMessage.new(CoAPType.CONFIRMABLE, CoAPCode.GET, 2)
    options = CoAPOptions()
    for number, value in [(CoAPOptionNumber.URI_QUERY, b"q"), (CoAPOptionNumber.URI_PATH, b"a"), (CoAPOptionNumber.URI_PATH, b"b"), (CoAPOptionNumber.URI_HOST, b"h")]:
        options.push(number, value)
    message.options = options
    decoded = CoAPMessage.decode(message.encode()).options
    assert [number for number, _ in decoded.entries] == [3, 11, 11, 15]
    assert decoded.path() == ["a", "b"] and decoded.queries() == ["q"]
    # §4.1: an empty message is its header alone.
    assert CoAPMessage.empty(CoAPType.RESET, 0x1234).encode() == b"\x70\x00\x12\x34"
    assert CoAPMessage.decode(b"\x60\x00\x12\x34").code.is_empty()


def test_extended_tokens_of_rfc_8974():
    # §2.1: lengths up to 12 in the nibble, 13 to 268 in one more byte, then two; 15 is reserved.
    for length, nibble, extension in [(0, 0, b""), (8, 8, b""), (12, 12, b""), (13, 13, b"\x00"), (268, 13, b"\xff"), (269, 14, b"\x00\x00"), (1000, 14, b"\x02\xdb")]:
        message = CoAPMessage.new(CoAPType.NON_CONFIRMABLE, CoAPCode.GET, 1)
        message.token = b"\x07" * length
        data = message.encode()
        assert (data[0] & 15, data[4 : 4 + len(extension)]) == (nibble, extension), length
        assert len(CoAPMessage.decode(data).token) == length
    message = CoAPMessage.new(CoAPType.NON_CONFIRMABLE, CoAPCode.GET, 1)
    message.token = b"\x01" * CoAPMessage.MAXIMUM_TOKEN
    assert message.encode()[:6] == b"\x5e\x01\x00\x01\xff\xff"
    message.token = b"\x01" * (CoAPMessage.MAXIMUM_TOKEN + 1)
    with pytest.raises(CoAPError) as error:
        message.encode()
    assert error.value.name == "TooLarge"


@pytest.mark.parametrize(
    "data",
    [
        b"\x40\x01\x00",  # shorter than the header
        b"\x80\x01\x00\x01",  # version 2
        b"\x4f\x01\x00\x01",  # the reserved token length 15
        b"\x4d\x01\x00\x01",  # a token length cut short
        b"\x41\x01\x00\x01",  # a token cut short
        b"\x40\x01\x00\x01\xf0",  # an option delta of 15
        b"\x40\x01\x00\x01\x1f",  # an option length of 15
        b"\x40\x01\x00\x01\xff",  # a payload marker without payload
        b"\x40\x01\x00\x01\xd0",  # an option header cut short
        b"\x40\x01\x00\x01\x02\x61",  # an option cut short
        b"\x61\x00\x00\x01\x09",  # an empty message with a token
        b"\x60\x00\x00\x01\xff\x01",  # an empty message with a payload
        b"\x60\x00\x00\x01\x10",  # an empty message with an option
    ],
)
def test_message_format_errors(data):
    with pytest.raises(CoAPError) as error:
        CoAPMessage.decode(data)
    assert (error.value.domain, error.value.name) == ("protocol.coap", "Malformed")


def test_the_header_of_a_message_to_reject():
    # §4.2: the type and Message ID of a message that cannot be read otherwise, of version 1 only.
    assert CoAPMessage.header(b"\x40\x01\x00\x0a\xf0") == (CoAPType.CONFIRMABLE, 10)
    assert CoAPMessage.header(b"\x80\x01\x00\x0a") is None
    assert CoAPMessage.header(b"\x40\x01") is None
    with pytest.raises(FFIError) as error:
        CoAPMessage.new(4, CoAPCode.GET, 0)
    assert error.value.name == "InvalidArgument"


def test_the_options_of_rfc_7252():
    # §5.4.6 and table 4: the properties are of the number's bits.
    for number, critical, unsafe, no_cache_key in [
        (CoAPOptionNumber.IF_MATCH, True, False, False),
        (CoAPOptionNumber.URI_HOST, True, True, False),
        (CoAPOptionNumber.ETAG, False, False, False),
        (CoAPOptionNumber.OBSERVE, False, True, False),
        (CoAPOptionNumber.URI_PATH, True, True, False),
        (CoAPOptionNumber.CONTENT_FORMAT, False, False, False),
        (CoAPOptionNumber.MAX_AGE, False, True, False),
        (CoAPOptionNumber.ACCEPT, True, False, False),
        (CoAPOptionNumber.SIZE1, False, False, True),
    ]:
        assert (number.is_critical(), number.is_unsafe(), number.is_no_cache_key()) == (critical, unsafe, no_cache_key), number
    definition = CoAPOptionNumber.URI_HOST.definition()
    assert (definition.format, definition.least, definition.greatest, definition.repeatable) == (CoAPOptionFormat.STRING, 1, 255, False)
    assert CoAPOptionNumber.ETAG.definition().repeatable and CoAPOptionNumber.PROXY_URI.definition().greatest == 1034
    assert CoAPOptionNumber.IF_NONE_MATCH.definition().format == CoAPOptionFormat.EMPTY
    assert CoAPOptionNumber(9).definition() is None
    # §3.2: uints of as few bytes as they need.
    assert (CoAPOptions.uint_bytes(0), CoAPOptions.uint_bytes(0x1234)) == (b"", b"\x12\x34")
    assert (CoAPOptions.uint_of(b"\x00\x00\x01"), CoAPOptions.uint_of(b"\x01\x02\x03\x04\x05")) == (1, None)
    # §6.4: the path and query of a URI.
    options = CoAPOptions()
    options.set_uri("/a/b", "x=1&y")
    assert (options.path(), options.queries(), len(options)) == (["a", "b"], ["x=1", "y"], 4)
    assert options.get(CoAPOptionNumber.URI_PATH) == b"a" and options.get(CoAPOptionNumber.ETAG) is None
    assert options.all(CoAPOptionNumber.URI_QUERY) == [b"x=1", b"y"]
    assert options.check() is None
    # §5.4.1, §5.4.3, §5.4.5: a critical option unknown, of a length out of its definition, or not
    # repeatable and repeated, rejects the message; such elective ones are ignored.
    for number, value, rejects in [
        (CoAPOptionNumber(9), b"\x01", True),
        (CoAPOptionNumber(10), b"\x01", False),
        (CoAPOptionNumber.URI_HOST, b"", True),
        (CoAPOptionNumber.ETAG, b"", False),
        (CoAPOptionNumber.ACCEPT, b"\x01\x02\x03", True),
    ]:
        changed = options.clone()
        changed.push(number, value)
        assert changed.check() == (number if rejects else None), number
        if not rejects:
            assert changed.usable().entries == options.entries
    repeated = CoAPOptions()
    repeated.push(CoAPOptionNumber.URI_HOST, b"a")
    repeated.push(CoAPOptionNumber.URI_HOST, b"b")
    assert repeated.check() == CoAPOptionNumber.URI_HOST
    repeated.set(CoAPOptionNumber.URI_HOST, b"c")
    assert repeated.entries == [(CoAPOptionNumber.URI_HOST, b"c")]
    repeated.remove(CoAPOptionNumber.URI_HOST)
    assert len(repeated) == 0 and not repeated.contains(CoAPOptionNumber.URI_HOST)
    # §5.10.5: Max-Age is 60 seconds without the option; a repeated elective option counts once.
    assert repeated.max_age() == 60
    repeated.push(CoAPOptionNumber.MAX_AGE, b"\x01")
    repeated.push(CoAPOptionNumber.MAX_AGE, b"\x02")
    assert repeated.usable().max_age() == 1
    # §5.10.3, RFC 7641 §2: Content-Format and Observe.
    assert options.content_format() is None
    options.set_uint(CoAPOptionNumber.CONTENT_FORMAT, CoAPContentFormat.JSON)
    assert options.content_format() == CoAPContentFormat.JSON
    options.set_uint(CoAPOptionNumber.OBSERVE, 0x123456)
    assert (options.observe(), options.get(CoAPOptionNumber.OBSERVE)) == (0x123456, b"\x12\x34\x56")
    # RFC 7959 §2.2: a Block2 option, read; SZX 7 is reserved.
    options.set(CoAPOptionNumber.BLOCK2, b"\x3b")
    assert options.block(CoAPOptionNumber.BLOCK2) == CoAPBlock(3, True, 3)
    assert options.block(CoAPOptionNumber.BLOCK1) is None
    options.set(CoAPOptionNumber.BLOCK2, b"\x0f")
    with pytest.raises(CoAPError) as error:
        options.block(CoAPOptionNumber.BLOCK2)
    assert error.value.name == "Option"


def test_blocks_of_rfc_7959():
    # §2.2: NUM, M and SZX; a size of 2^(SZX + 4); the offset NUM × size.
    block = CoAPBlock.new(3, True, 128)
    assert (block, block.encode(), block.size(), block.offset()) == (CoAPBlock(3, True, 3), b"\x3b", 128, 384)
    assert CoAPBlock.decode(b"\x3b") == block
    assert CoAPBlock.decode(b"") == CoAPBlock(0, False, 0)
    assert CoAPBlock.decode(b"\xff\xff\xf6") == CoAPBlock(CoAPBlock.MAXIMUM_NUMBER, False, 6)
    for value in (b"\x07", b"\x01\x02\x03\x04"):
        with pytest.raises(CoAPError):
            CoAPBlock.decode(value)
    for number, size in [(0, 2048), (0, 8), (0, 100), (1 << 20, 16)]:
        with pytest.raises(CoAPError):
            CoAPBlock.new(number, False, size)
    with pytest.raises(CoAPError):
        CoAPBlock(0, False, 7).encode()
    # §2.4: the blocks of a body.
    body = bytes(value % 256 for value in range(300))
    assert CoAPBlock.new(0, False, 128).slice(body) == (body[:128], True)
    assert CoAPBlock.new(2, False, 128).slice(body) == (body[256:], False)
    assert CoAPBlock.new(3, False, 128).slice(body) is None
    # A server's blocks of a body, Size2 if asked (§4); a smaller size keeps the offset (§2.4).
    request = with_option(get("/large"), CoAPOptionNumber.SIZE2, 0)
    response = CoAPMessage.new(CoAPType.ACKNOWLEDGEMENT, CoAPCode.CONTENT, 0)
    CoAPBlockwise.respond(request, body, 128, response)
    assert response.options.block(CoAPOptionNumber.BLOCK2) == CoAPBlock(0, True, 3)
    assert (response.payload, response.options.uint(CoAPOptionNumber.SIZE2)) == (body[:128], 300)
    options = request.options
    options.set(CoAPOptionNumber.BLOCK2, CoAPBlock.new(1, False, 256).encode())
    request.options = options
    CoAPBlockwise.respond(request, body, 64, response)
    assert (response.options.block(CoAPOptionNumber.BLOCK2), response.payload) == (CoAPBlock(4, False, 2), body[256:])
    options.set(CoAPOptionNumber.BLOCK2, CoAPBlock.new(9, False, 64).encode())
    request.options = options
    with pytest.raises(CoAPError) as error:
        CoAPBlockwise.respond(request, body, 64, response)
    assert error.value.name == "Option" and response.payload == body[256:]
    whole = CoAPMessage.new(CoAPType.ACKNOWLEDGEMENT, CoAPCode.CONTENT, 0)
    CoAPBlockwise.respond(get("/small"), body[:100], 128, whole)
    assert whole.payload == body[:100] and not whole.options.contains(CoAPOptionNumber.BLOCK2)
    # §2.4, §2.5: a receiver takes blocks in order, each but the last full, of one ETag.
    receiver = CoAPBlockwise.new(1000)
    assert not receiver.receive(CoAPBlock.new(0, True, 128), body[:128], b"\x01")
    for block, payload, etag, name in [
        (CoAPBlock.new(2, True, 128), body[256:], b"\x01", "State"),
        (CoAPBlock.new(1, True, 128), body[128:256], b"\x02", "State"),
        (CoAPBlock.new(1, True, 128), body[128:256], None, "State"),
        (CoAPBlock.new(1, True, 128), body[128:200], b"\x01", "Malformed"),
    ]:
        with pytest.raises(CoAPError) as error:
            receiver.receive(block, payload, etag)
        assert error.value.name == name
    assert not receiver.receive(CoAPBlock.new(1, True, 128), body[128:256], b"\x01")
    # The next block is at the end of the body so far, numbered at its size (§2.4), without Observe.
    next_options = receiver.next_request(with_option(request, CoAPOptionNumber.OBSERVE, 0).options, 128)
    assert next_options.block(CoAPOptionNumber.BLOCK2) == CoAPBlock(2, False, 3)
    assert not next_options.contains(CoAPOptionNumber.OBSERVE)
    assert receiver.next_request(request.options, 64).block(CoAPOptionNumber.BLOCK2) == CoAPBlock(4, False, 2)
    assert receiver.receive(CoAPBlock.new(2, False, 128), body[256:], b"\x01")
    assert receiver.body == body
    small = CoAPBlockwise.new(100)
    with pytest.raises(CoAPError) as error:
        small.receive(CoAPBlock.new(0, True, 128), body[:128])
    assert error.value.name == "TooLarge"


def test_the_default_configuration_of_rfc_7252():
    # §4.8, §4.8.2: the transmission parameters and the times derived from them.
    config = CoAPConfig.default()
    assert (config.ack_timeout, config.ack_random_factor, config.max_retransmit, config.nstart) == (datetime.timedelta(seconds=2), 1500, 4, 1)
    assert (config.exchange_lifetime, config.non_lifetime) == (datetime.timedelta(seconds=247), datetime.timedelta(seconds=145))
    # RFC 8974 §2.2.1: tokens of up to 8 bytes unless extended.
    assert config.maximum_token == 8
    for change in ({"ack_timeout": datetime.timedelta(0)}, {"ack_random_factor": 999}, {"nstart": 0}):
        with pytest.raises(CoAPError) as error:
            CoAPEndpoint.new(dataclasses.replace(config, **change), random())
        assert error.value.name == "Config"


def test_piggybacked_and_separate_responses():
    pair = Pair()
    generator = random(b"responses")
    # §5.2.1: the response in the ACK of a Confirmable request, of its Message ID and token.
    handle = pair.client.request(SERVER, get("/a"), 0, generator)
    sent, _ = pair.run(0)
    request = pair.request()
    assert request.message.options.path() == ["a"]
    # §5.3.1: a token of at least 32 bits of randomness, of at most 8 bytes.
    token = request.message.token
    assert 4 <= len(token) <= 8 and CoAPMessage.decode(sent[0]).token == token
    response = CoAPMessage.new(CoAPType.ACKNOWLEDGEMENT, CoAPCode.CONTENT, 0)
    response.payload = b"one"
    pair.server.respond(request.exchange, response, 10 * MS, generator)
    _, replies = pair.run(10 * MS)
    assert [header(reply) for reply in replies] == [(CoAPType.ACKNOWLEDGEMENT, CoAPCode.CONTENT, CoAPMessage.decode(sent[0]).id)]
    events = Pair.events(pair.client)
    assert [(event.kind, event.request) for event in events] == [(CoAPEventKind.RESPONSE, handle)]
    assert (events[0].message.payload, events[0].message.token) == (b"one", token)
    # A request is answered once.
    with pytest.raises(CoAPError) as error:
        pair.server.respond(request.exchange, response, 10 * MS, generator)
    assert error.value.name == "State"
    # §5.2.2: unanswered, an empty ACK, then the response Confirmable, acknowledged by the client.
    handle = pair.client.request(SERVER, get("/b"), 100 * MS, generator)
    sent, _ = pair.run(100 * MS)
    request = pair.request()
    deadline = pair.server.poll_timeout()
    pair.server.expire(deadline)
    _, replies = pair.run(deadline)
    assert [header(reply) for reply in replies] == [(CoAPType.ACKNOWLEDGEMENT, CoAPCode.EMPTY, CoAPMessage.decode(sent[0]).id)]
    assert Pair.events(pair.client) == []
    pair.server.respond(request.exchange, response, 5000 * MS, generator)
    acknowledgements, replies = pair.run(5000 * MS)
    kind, code, separate = header(replies[0])
    assert (kind, code) == (CoAPType.CONFIRMABLE, CoAPCode.CONTENT)
    assert [header(ack) for ack in acknowledgements] == [(CoAPType.ACKNOWLEDGEMENT, CoAPCode.EMPTY, separate)]
    events = Pair.events(pair.client)
    assert [(event.kind, event.request, event.message.kind) for event in events] == [(CoAPEventKind.RESPONSE, handle, CoAPType.CONFIRMABLE)]
    # §5.2.3: a Non-confirmable request gets a Non-confirmable response.
    handle = pair.client.request(SERVER, get("/c", CoAPType.NON_CONFIRMABLE), 6000 * MS, generator)
    pair.run(6000 * MS)
    request = pair.request()
    pair.server.respond(request.exchange, response, 6000 * MS, generator)
    pair.run(6000 * MS)
    events = Pair.events(pair.client)
    assert [(event.request, event.message.kind) for event in events] == [(handle, CoAPType.NON_CONFIRMABLE)]
    # A request is a CON or NON message of a method code.
    for kind, code in [(CoAPType.ACKNOWLEDGEMENT, CoAPCode.GET), (CoAPType.CONFIRMABLE, CoAPCode.CONTENT), (CoAPType.CONFIRMABLE, CoAPCode.EMPTY)]:
        with pytest.raises(CoAPError) as error:
            pair.client.request(SERVER, CoAPMessage.new(kind, code, 0), 0, generator)
        assert error.value.name == "State"


def test_retransmissions_and_duplicates_of_rfc_7252():
    generator = random(b"retransmissions")
    client = CoAPEndpoint.new(None, generator)
    handle = client.request(SERVER, get("/a"), 0, generator)
    first = client.transmit().message
    # §4.2, §4.8: a first timeout from ACK_TIMEOUT to ACK_TIMEOUT × ACK_RANDOM_FACTOR (2 to 3 s),
    # doubled at each of MAX_RETRANSMIT (4) retransmissions, then a timeout.
    deadline = client.poll_timeout()
    assert 2000 * MS <= deadline <= 3000 * MS
    initial = deadline
    for retransmission in range(1, 5):
        client.expire(deadline - 1)
        assert client.transmit() is None
        client.expire(deadline)
        out = client.transmit()
        assert (out.peer, out.message) == (SERVER, first)
        next_deadline = client.poll_timeout()
        assert next_deadline - deadline == initial << retransmission
        deadline = next_deadline
    assert Pair.events(client) == []
    client.expire(deadline)
    assert client.transmit() is None
    assert [(event.kind, event.message) for event in Pair.events(client)] == [(CoAPEventKind.TIMEOUT, handle)]
    # §4.5: a duplicate of a Confirmable request gets the same reply, and is not told again.
    server = CoAPEndpoint.new(None, generator)
    server.receive(CLIENT, first, 0, generator)
    request = server.poll_event()
    server.respond(request.exchange, CoAPMessage.new(CoAPType.ACKNOWLEDGEMENT, CoAPCode.CONTENT, 0), 0, generator)
    reply = server.transmit().message
    server.receive(CLIENT, first, 3000 * MS, generator)
    assert server.transmit().message == reply and server.poll_event() is None
    # Remembered for EXCHANGE_LIFETIME (247 s), then a message of its own again.
    server.expire(248_000 * MS)
    server.receive(CLIENT, first, 248_000 * MS, generator)
    assert [event.kind for event in Pair.events(server)] == [CoAPEventKind.REQUEST]
    # §4.2: a RST of the request ends it.
    handle = client.request(SERVER, get("/b"), 0, generator)
    identifier = CoAPMessage.decode(client.transmit().message).id
    client.receive(SERVER, CoAPMessage.empty(CoAPType.RESET, identifier).encode(), 1, generator)
    assert [(event.kind, event.message) for event in Pair.events(client)] == [(CoAPEventKind.RESET, handle)]


def test_each_retransmission_is_the_message_itself():
    generator = random(b"identical")
    client = CoAPEndpoint.new(None, generator)
    client.request(SERVER, get("/a"), 0, generator)
    first = client.transmit()
    for _ in range(4):
        client.expire(client.poll_timeout())
        # §4.2: the same message, of the same Message ID.
        assert client.transmit() == first


def test_rejections_of_rfc_7252():
    generator = random(b"rejections")
    server = CoAPEndpoint.new(None, generator)

    def reply():
        return header(server.transmit().message)

    # §4.3: a ping, an empty Confirmable message, is answered with a RST.
    server.receive(CLIENT, CoAPMessage.empty(CoAPType.CONFIRMABLE, 9).encode(), 0, generator)
    assert reply() == (CoAPType.RESET, CoAPCode.EMPTY, 9)
    # §4.2: a Confirmable message that cannot be read, RST; a Non-confirmable one, nothing (§4.3).
    server.receive(CLIENT, b"\x40\x01\x00\x0a\xf0", 0, generator)
    assert reply() == (CoAPType.RESET, CoAPCode.EMPTY, 10)
    server.receive(CLIENT, b"\x50\x01\x00\x0b\xf0", 0, generator)
    assert server.transmit() is None
    # RFC 8974 §2.2.1: a token longer than the endpoint takes is a message format error.
    long = get("/a")
    long.id, long.token = 12, b"\x01" * 9
    server.receive(CLIENT, long.encode(), 0, generator)
    assert reply() == (CoAPType.RESET, CoAPCode.EMPTY, 12)
    extended = CoAPEndpoint.new(dataclasses.replace(CoAPConfig.default(), maximum_token=16), generator)
    extended.receive(CLIENT, long.encode(), 0, generator)
    assert [event.kind for event in Pair.events(extended)] == [CoAPEventKind.REQUEST]
    # §5.4.1: an unrecognized critical option in a Confirmable request: 4.02 Bad Option, piggybacked.
    unknown = get("/a")
    unknown.id = 13
    options = unknown.options
    options.push(9, b"\x01")
    unknown.options = options
    server.receive(CLIENT, unknown.encode(), 0, generator)
    assert reply() == (CoAPType.ACKNOWLEDGEMENT, CoAPCode.BAD_OPTION, 13)
    assert server.poll_event() is None
    # §5.4.1: an unrecognized elective option is ignored.
    elective = get("/a")
    elective.id = 15
    options = elective.options
    options.push(10, b"\x01")
    elective.options = options
    server.receive(CLIENT, elective.encode(), 0, generator)
    request = server.poll_event()
    assert request.kind == CoAPEventKind.REQUEST and not request.message.options.contains(10)
    # §5.3.2: a Confirmable response that matches no request is rejected.
    client = CoAPEndpoint.new(None, generator)
    stray = CoAPMessage.new(CoAPType.CONFIRMABLE, CoAPCode.CONTENT, 14)
    stray.token = b"\x05"
    client.receive(SERVER, stray.encode(), 0, generator)
    assert header(client.transmit().message) == (CoAPType.RESET, CoAPCode.EMPTY, 14)
    with pytest.raises(CoAPError) as error:
        server.respond(77, CoAPMessage.new(CoAPType.ACKNOWLEDGEMENT, CoAPCode.CONTENT, 0), 0, generator)
    assert error.value.name == "State"


def test_nstart_of_rfc_7252():
    # §4.7: one outstanding interaction with a peer (NSTART 1); the next waits.
    pair = Pair()
    generator = random(b"nstart")
    pair.client.request(SERVER, get("/a"), 0, generator)
    pair.client.request(SERVER, get("/b"), 0, generator)
    sent, _ = pair.run(0)
    assert len(sent) == 1
    request = pair.request()
    assert request.message.options.path() == ["a"]
    pair.server.respond(request.exchange, CoAPMessage.new(CoAPType.ACKNOWLEDGEMENT, CoAPCode.CONTENT, 0), MS, generator)
    pair.run(MS)
    assert pair.request().message.options.path() == ["b"]


def test_requests_left_unanswered():
    generator = random(b"unanswered")
    # RFC 7967 §2: a request the server does not answer; a Confirmable one is acknowledged by an empty
    # ACK, so that its client stops retransmitting it (RFC 7252 §4.2).
    server = CoAPEndpoint.new(None, generator)
    request = get("/a")
    request.id, request.token = 30, b"\x01"
    server.receive(CLIENT, request.encode(), 0, generator)
    exchange = server.poll_event().exchange
    server.ignore(exchange)
    assert header(server.transmit().message) == (CoAPType.ACKNOWLEDGEMENT, CoAPCode.EMPTY, 30)
    assert server.transmit() is None
    with pytest.raises(CoAPError) as error:
        server.ignore(exchange)
    assert error.value.name == "State"
    # Past `maximum_incoming` requests awaiting an answer, a Confirmable request is answered 5.03.
    small = CoAPEndpoint.new(dataclasses.replace(CoAPConfig.default(), maximum_incoming=1), generator)
    for id in (31, 32):
        request.id, request.token = id, bytes([id])
        small.receive(CLIENT, request.encode(), 0, generator)
    assert [event.kind for event in Pair.events(small)] == [CoAPEventKind.REQUEST]
    assert header(small.transmit().message) == (CoAPType.ACKNOWLEDGEMENT, CoAPCode.SERVICE_UNAVAILABLE, 32)


def test_observations_of_rfc_7641():
    pair = Pair()
    generator = random(b"observations")
    observers = CoAPObservers()
    # §4.5: a Confirmable notification at least every 24 hours.
    assert observers.confirm_interval <= datetime.timedelta(hours=24) and observers.maximum > 0
    # §3.1, §4.1: GET with Observe 0 registers; the response carries Observe.
    handle = pair.client.request(SERVER, with_option(get("/temp"), CoAPOptionNumber.OBSERVE, 0), 0, generator)
    pair.run(0)
    request = pair.request()
    assert observers.register(request.peer, request.message, 0)
    token = request.message.token
    assert [(observer.peer, observer.token) for observer in observers.observers] == [(CLIENT, token)]
    value = observers.next_value()
    response = with_option(CoAPMessage.new(CoAPType.ACKNOWLEDGEMENT, CoAPCode.CONTENT, 0), CoAPOptionNumber.OBSERVE, value)
    response.payload = b"20"
    pair.server.respond(request.exchange, response, 0, generator)
    pair.run(0)
    events = Pair.events(pair.client)
    assert [(event.kind, event.request, event.message.options.observe()) for event in events] == [(CoAPEventKind.RESPONSE, handle, value)]
    # §4.2, §4.4: notifications of the observer's token and of Observe values strictly increasing.
    previous = value
    for payload in (b"21", b"22"):
        response.payload = payload
        observers.notify(pair.server, ["temp"], response, False, 1000 * MS, generator)
        _, notifications = pair.run(1000 * MS)
        notification = CoAPMessage.decode(notifications[0])
        assert notification.token == token
        assert previous < notification.options.observe() < 1 << 24
        previous = notification.options.observe()
        events = Pair.events(pair.client)
        assert [(event.request, event.message.payload) for event in events] == [(handle, payload)]
    # §3.4: a notification older than the freshest is dropped.
    stale = with_option(response.clone(), CoAPOptionNumber.OBSERVE, previous - 1)
    stale.kind, stale.id, stale.token = CoAPType.NON_CONFIRMABLE, 999, token
    pair.client.receive(SERVER, stale.encode(), 2000 * MS, generator)
    assert Pair.events(pair.client) == []
    # §3.4: the order of 24-bit serial numbers, or 128 seconds apart.
    assert CoAPEndpoint.is_fresher(1, 0, 2, 0) and not CoAPEndpoint.is_fresher(2, 0, 1, 0)
    assert CoAPEndpoint.is_fresher(0xFFFFFF, 0, 1, 0) and not CoAPEndpoint.is_fresher(1, 0, 1 + (1 << 23), 0)
    assert CoAPEndpoint.is_fresher(2, 0, 1, 128_001 * MS) and not CoAPEndpoint.is_fresher(2, 0, 1, 128_000 * MS)
    # §3.6: a client that forgets the observation rejects the next notification, which ends it.
    pair.client.cancel(handle, 3000 * MS)
    observers.notify(pair.server, ["temp"], response, False, 3000 * MS, generator)
    resets, _ = pair.run(3000 * MS)
    assert header(resets[0])[0] == CoAPType.RESET
    assert Pair.events(pair.client) == []
    assert any(observers.handle(event) for event in Pair.events(pair.server))
    assert len(observers) == 0


def test_the_ends_of_an_observation():
    generator = random(b"ends")
    endpoint = CoAPEndpoint.new(None, generator)
    observers = CoAPObservers()
    request = with_option(get("/temp"), CoAPOptionNumber.OBSERVE, 0)
    request.token = b"\x01"
    content = CoAPMessage.new(CoAPType.NON_CONFIRMABLE, CoAPCode.CONTENT, 0)
    # RFC 7641 §4.5: a Confirmable notification once the interval passed, and its timeout ends it.
    observers.confirm_interval = datetime.timedelta(minutes=1)
    assert observers.confirm_interval == datetime.timedelta(minutes=1)
    assert observers.register(CLIENT, request, 0)
    observers.notify(endpoint, ["temp"], content, False, 1000 * MS, generator)
    assert CoAPMessage.decode(endpoint.transmit().message).kind == CoAPType.NON_CONFIRMABLE
    observers.notify(endpoint, ["temp"], content, False, 60_000 * MS, generator)
    assert CoAPMessage.decode(endpoint.transmit().message).kind == CoAPType.CONFIRMABLE
    now = 60_000 * MS
    for _ in range(6):
        now = max(endpoint.poll_timeout(), now)
        endpoint.expire(now)
    events = Pair.events(endpoint)
    assert any(event.kind == CoAPEventKind.TIMEOUT and observers.handle(event) for event in events)
    assert len(observers) == 0
    # §3.6: GET with Observe 1 deregisters.
    observers.register(CLIENT, request, 0)
    assert not observers.register(CLIENT, with_option(request.clone(), CoAPOptionNumber.OBSERVE, 1), 0)
    assert len(observers) == 0
    # §4.2: a notification of an error has no Observe, and ends the observations.
    observers.register(CLIENT, request, 0)
    while endpoint.transmit() is not None:
        pass
    observers.notify(endpoint, ["temp"], CoAPMessage.new(CoAPType.NON_CONFIRMABLE, CoAPCode.NOT_FOUND, 0), False, 1, generator)
    sent = CoAPMessage.decode(endpoint.transmit().message)
    assert (sent.code, sent.options.observe()) == (CoAPCode.NOT_FOUND, None)
    assert len(observers) == 0
    # Only GET (§2) and FETCH (RFC 8132 §2.4) observe.
    post = request.clone()
    post.code = CoAPCode.POST
    assert not observers.register(CLIENT, post, 0)
    fetch = request.clone()
    fetch.code = CoAPCode.FETCH
    assert observers.register(CLIENT, fetch, 0)
    # A notification is a response with Observe.
    with pytest.raises(CoAPError) as error:
        endpoint.notify(CLIENT, content, 0, generator)
    assert error.value.name == "State"
    observers.maximum = 0
    assert not observers.register(SERVER, request, 0)
    with pytest.raises(FFIError) as error:
        observers.handle(CoAPEvent(4))
    assert error.value.name == "InvalidArgument"


def test_the_link_format_of_rfc_6690():
    # §5: the links of a resource directory, with an anchor and a title.
    text = (
        '</sensors>;ct=40;title="Sensor Index",</sensors/temp>;rt="temperature-c";if="sensor",'
        '</sensors/light>;rt="light-lux";if="sensor",'
        '<http://www.example.com/sensors/t123>;anchor="/sensors/temp";rel="describedby",'
        '</t>;anchor="/sensors/temp";rel="alternate"'
    )
    links = CoAPLink.parse(text)
    assert len(links) == 5
    assert (links[0].target, links[0].attribute("ct"), links[0].attribute("TITLE")) == ("/sensors", "40", "Sensor Index")
    assert links[0].attribute("rt") is None and not links[0].has_attribute("rt")
    assert (links[3].target, links[3].attribute("anchor"), links[3].attribute("rel")) == (
        "http://www.example.com/sensors/t123",
        "/sensors/temp",
        "describedby",
    )
    # The text of the links reads back as the same links.
    formatted = CoAPLink.format(links)
    assert formatted.startswith('</sensors>;ct=40;title="Sensor Index",')
    again = CoAPLink.parse(formatted)
    assert [(link.target, link.attributes) for link in again] == [(link.target, link.attributes) for link in links]
    # §2: attributes without values, quoted values with escapes.
    made = CoAPLink.new("/a").with_("obs").with_("title", 'x"y')
    assert made.has_attribute("obs") and made.attribute("obs") is None
    assert made.attributes == [("obs", None), ("title", 'x"y')]
    assert CoAPLink.format([made, CoAPLink.new("/b")]) == '</a>;obs;title="x\\"y",</b>'
    parsed = CoAPLink.parse('</a>;obs;title="x\\"y",</b>')
    assert [(link.target, link.attributes) for link in parsed] == [("/a", [("obs", None), ("title", 'x"y')]), ("/b", [])]
    assert CoAPLink.WELL_KNOWN_CORE == "/.well-known/core"
    for malformed in ["/a", "</a", "</a>;", "</a>;=1", "</a>x", '</a>;t="open']:
        with pytest.raises(CoAPError) as error:
            CoAPLink.parse(malformed)
        assert error.value.name == "Malformed", malformed


def test_rules():
    rule = CoAPRule.new("/sensors").with_method(CoAPCode.GET)
    assert rule.matches(get("/sensors/temp")) and rule.matches(get("/sensors", CoAPType.NON_CONFIRMABLE))
    assert not rule.matches(get("/sensorsx")) and not rule.matches(get("/other"))
    post = get("/sensors")
    post.code = CoAPCode.POST
    assert not rule.matches(post)
    root = CoAPRule.new("/")
    assert root.matches(get("/anything"))
    assert not root.matches(CoAPMessage.new(CoAPType.CONFIRMABLE, CoAPCode.CONTENT, 0))


def test_a_non_confirmable_notification_does_not_end_an_observation():
    # RFC 7641 §4.5: only a Confirmable notification that is not acknowledged, or a RST (§3.6), ends
    # an observation; a Non-confirmable one is never acknowledged.
    generator = random(b"non-confirmable")
    endpoint = CoAPEndpoint.new(None, generator)
    observers = CoAPObservers()
    request = with_option(get("/temp"), CoAPOptionNumber.OBSERVE, 0)
    request.token = b"\x01"
    assert observers.register(CLIENT, request, 0)
    observers.notify(endpoint, ["temp"], CoAPMessage.new(CoAPType.NON_CONFIRMABLE, CoAPCode.CONTENT, 0), False, MS, generator)
    assert CoAPMessage.decode(endpoint.transmit().message).kind == CoAPType.NON_CONFIRMABLE
    endpoint.expire(MS + 146_000 * MS)
    for event in Pair.events(endpoint):
        observers.handle(event)
    assert len(observers) == 1
