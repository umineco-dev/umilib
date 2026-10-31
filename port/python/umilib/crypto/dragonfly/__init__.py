"""The Dragonfly key exchange (RFC 7664). Mirrors ``umilib::crypto::dragonfly``.

Two peers that share a password each create a ``DragonflyPeer[C, H]`` on a
Weierstrass curve with a hash function, exchange their commits
(:meth:`DragonflyPeer.commit`, :meth:`DragonflyPeer.process`) and then their
confirms (:meth:`DragonflyPeer.finish`), which gives the master key.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import Any

from umilib.crypto import Names, Specialization
from umilib.crypto.random import Random
from umilib.ffi import Bytes, Fields, Handle, Library, Text
from umilib.hash import CryptographicDigest
from umilib.math.ec import WeierstrassCurve


@dataclass(frozen=True)
class DragonflyConfig:
    """The parameters of an exchange: the rounds of hunting and pecking that are always run (section
    3.2); 40 leave a probability of 2^-40 that more are needed and their number shows."""

    iterations: int

    @classmethod
    def default(cls) -> DragonflyConfig:
        """40 rounds."""
        return cls(Library.default().function("umilib_crypto_dragonfly_dragonfly_config_default")().iterations)

    def structure(self) -> Any:
        structure = Library.default().type("umilib_crypto_dragonfly_DragonflyConfig")()
        Fields.assign(structure, "iterations", self.iterations)
        return structure


class DragonflyPeer(Handle):
    """A peer of an exchange on the curve and with the hash function of ``DragonflyPeer[C, H]``;
    its secrets are zeroized when it is released."""

    FREE = "umilib_crypto_dragonfly_dragonfly_peer_free"
    PARAMETERS: tuple[Any, ...] | None = None

    def __class_getitem__(cls, parameters: Any) -> Any:
        curve, hash = Specialization.pair(parameters, "DragonflyPeer")
        curve = Names.require(curve, WeierstrassCurve, "DragonflyPeer")
        hash = Names.require(hash, CryptographicDigest, "DragonflyPeer")
        return Specialization.of(cls, (curve, hash), {})

    def __init__(
        self,
        config: DragonflyConfig,
        identity: bytes | bytearray | memoryview,
        peer_identity: bytes | bytearray | memoryview,
        password: bytes | bytearray | memoryview,
        random: Random,
    ) -> None:
        """The peer ``identity`` of an exchange with ``peer_identity`` over ``password`` (section 3.3),
        its secrets drawn from ``random``; raises ``InvalidParameter`` when no password element is
        found within the rounds of ``config``."""
        curve, hash = Specialization.require(self.PARAMETERS, "DragonflyPeer")
        structure = config.structure()
        arguments: list[Any] = [*Text.encode(curve.C_TYPE), *Text.encode(hash.C_TYPE), ctypes.byref(structure)]
        for value in (identity, peer_identity, password):
            arguments.extend(Bytes.readable(value))
        handle, name, length = random.source()
        super().__init__(Handle.create("umilib_crypto_dragonfly_dragonfly_peer_new", *arguments, handle, name, length))

    @classmethod
    def new(
        cls,
        config: DragonflyConfig,
        identity: bytes | bytearray | memoryview,
        peer_identity: bytes | bytearray | memoryview,
        password: bytes | bytearray | memoryview,
        random: Random,
    ) -> Any:
        return cls(config, identity, peer_identity, password, random)

    def commit(self) -> bytes:
        """The peer's commit, scalar || element, to send to the other peer."""
        return self.library.output("umilib_crypto_dragonfly_dragonfly_peer_commit", self.handle)

    def process(self, commit: bytes | bytearray | memoryview) -> bytes:
        """Processes the commit of the other peer (section 3.4) and returns the peer's confirm; raises
        ``InvalidKey`` for a commit that is invalid or a reflection of the peer's own."""
        data, length = Bytes.readable(commit)
        return self.library.output("umilib_crypto_dragonfly_dragonfly_peer_process", self.handle, data, length)

    def finish(self, confirm: bytes | bytearray | memoryview) -> bytearray:
        """Checks the confirm of the other peer and returns the master key, a secret to zeroize; raises
        ``AuthenticationFailed`` for a wrong confirm and ``InvalidParameter`` before :meth:`process`."""
        data, length = Bytes.readable(confirm)
        return self.library.output_secret("umilib_crypto_dragonfly_dragonfly_peer_finish", self.handle, data, length)

    def __repr__(self) -> str:
        return "DragonflyPeer(..)"


__all__ = ["DragonflyConfig", "DragonflyPeer"]
