"""Cryptography: block and stream ciphers, modes, AEADs, message authentication, key derivation and
random generation. Mirrors ``umilib::crypto``.

The types generic over a hash function or a block cipher in Rust, such as
``HMAC<SHA256>`` or ``GCM<AES128, 16>``, are written ``HMAC[SHA256]`` and
``GCM[AES128, 16]`` here: the subscript selects the class of the hash
function or the cipher, whose C type the C ABI receives, and the sizes.

The classes of this module mirror the traits of ``umilib::crypto``:
:class:`BlockCipher`, :class:`StreamCipher`, :class:`AEAD` and :class:`MAC`.
Operations in place take a ``bytearray``.

The public-key schemes mirror the traits ``KeyAgreement``,
``SignatureScheme`` and ``KeyEncapsulation`` (:class:`KeyAgreement`,
:class:`SignatureScheme`, :class:`KeyEncapsulation`): ``ECDH[P256]``,
``ECDSA[P256, SHA256]`` or ``MLKEM[MLKEM768]`` is a class of no instances
whose keys are :class:`PrivateKey`, :class:`PublicKey`, :class:`SigningKey`,
:class:`VerifyingKey`, :class:`DecapsulationKey` and
:class:`EncapsulationKey`, held as their encodings, secret ones in a
:class:`~umilib.secret.Secret`. Functions that draw random values take a
generator of :mod:`umilib.crypto.random`; secrets are written into a
``bytearray``, which the caller zeroizes.
"""

from __future__ import annotations

import contextlib
import ctypes
from typing import Any, ClassVar, Iterator, TypeVar

from umilib.ffi import Bytes, FFIError, Handle, Library, Preset, Text
from umilib.secret import Secret

T = TypeVar("T", bound="Handle")


class CryptoError(FFIError):
    """An error of a cryptographic primitive; ``name`` is the variant, such as ``AuthenticationFailed``."""


Library.register_error("crypto", CryptoError)


class Primitive(Handle):
    """An object of a cryptographic type of the C ABI: ``PREFIX`` starts the names of its C functions,
    such as ``umilib_crypto_aes_aes128``, and its handle is released by ``{PREFIX}_free``."""

    PREFIX: ClassVar[str] = ""

    def __init_subclass__(cls, **options: Any) -> None:
        super().__init_subclass__(**options)
        if cls.PREFIX:
            cls.FREE = f"{cls.PREFIX}_free"

    @classmethod
    def from_pointer(cls: type[T], pointer: int) -> T:
        """The object that owns ``pointer``, a handle of this type created by umilib."""
        state = cls.__new__(cls)
        Handle.__init__(state, pointer)
        return state

    def clone(self: T) -> T:
        """A copy of the object."""
        return type(self).from_pointer(Handle.create(f"{self.PREFIX}_clone", self.handle))  # type: ignore[attr-defined]

    def __repr__(self) -> str:
        return f"{type(self).__name__}(..)"


class BlockCipher(Primitive):
    """A block cipher, as the Rust traits ``BlockCipher`` and ``KeyInit``: ``AES128(key)``.

    ``C_TYPE`` is the C type name, which the C ABI of the modes, CMAC, the KDFs
    and CTR_DRBG uses to select the cipher, as in ``GCM[AES128, 16]``.
    """

    #: The C type name, such as ``umilib_crypto_aes_AES128``.
    C_TYPE: ClassVar[str] = ""
    BLOCK_SIZE: ClassVar[Any]
    MINIMUM_KEY_SIZE: ClassVar[Any]
    MAXIMUM_KEY_SIZE: ClassVar[Any]

    def __init_subclass__(cls, **options: Any) -> None:
        super().__init_subclass__(**options)
        if "PREFIX" in cls.__dict__:
            prefix = cls.PREFIX
            cls.C_TYPE = f"{cls.__module__.replace('.', '_')}_{cls.__name__}"
            cls.BLOCK_SIZE = Preset(lambda: Library.default().function(f"{prefix}_block_size")())
            cls.MINIMUM_KEY_SIZE = Preset(lambda: Library.default().function(f"{prefix}_minimum_key_size")())
            cls.MAXIMUM_KEY_SIZE = Preset(lambda: Library.default().function(f"{prefix}_maximum_key_size")())

    def __init__(self, key: bytes | bytearray | memoryview) -> None:
        data, length = Bytes.readable(key)
        super().__init__(Handle.create(f"{self.PREFIX}_new", data, length))

    @classmethod
    def new_from_slice(cls: type[T], key: bytes | bytearray | memoryview) -> T:
        return cls(key)  # type: ignore[call-arg]

    def encrypt_blocks(self, data: bytearray) -> None:
        """Encrypts ``data``, a whole number of blocks, in place, block by block."""
        self.library.call(f"{self.PREFIX}_encrypt_blocks", self.handle, Bytes.mutable(data), len(data))

    def decrypt_blocks(self, data: bytearray) -> None:
        """Decrypts ``data``, a whole number of blocks, in place, block by block."""
        self.library.call(f"{self.PREFIX}_decrypt_blocks", self.handle, Bytes.mutable(data), len(data))

    def encrypt_block(self, block: bytearray) -> None:
        """Encrypts one block in place."""
        if len(block) != self.BLOCK_SIZE:
            raise ValueError(f"a block has {self.BLOCK_SIZE} bytes")
        self.encrypt_blocks(block)

    def decrypt_block(self, block: bytearray) -> None:
        """Decrypts one block in place."""
        if len(block) != self.BLOCK_SIZE:
            raise ValueError(f"a block has {self.BLOCK_SIZE} bytes")
        self.decrypt_blocks(block)


class BlockCipherClass:
    """The checks of the block cipher classes that select the generic types."""

    @staticmethod
    def require(cipher: Any, user: str, block_size: int | None = None) -> type[BlockCipher]:
        """``cipher`` if it is a block cipher class (of blocks of ``block_size`` bytes, if given)."""
        if not (isinstance(cipher, type) and issubclass(cipher, BlockCipher) and cipher.C_TYPE):
            raise TypeError(f"{user} needs a block cipher class, such as {user}[AES128]")
        if block_size is not None and cipher.BLOCK_SIZE != block_size:
            raise TypeError(f"{user} needs a block cipher with {block_size}-byte blocks")
        return cipher


class Specialization:
    """The classes of the generic types, created once for each choice of parameters by a subscript,
    as ``GCM[AES128, 16]``."""

    classes: ClassVar[dict[tuple[type, tuple[Any, ...]], type]] = {}

    @staticmethod
    def of(base: type, parameters: tuple[Any, ...], attributes: dict[str, Any]) -> Any:
        """The subclass of ``base`` for ``parameters``, with the class attributes ``attributes``; a
        class that is already specialized cannot be specialized again."""
        if getattr(base, "PARAMETERS", None) is not None:
            raise TypeError(f"{base.__name__} already has its parameters")
        key = (base, parameters)
        existing = Specialization.classes.get(key)
        if existing is not None:
            return existing
        shown = ", ".join(parameter.__name__ if isinstance(parameter, type) else repr(parameter) for parameter in parameters)
        name = f"{base.__name__}[{shown}]"
        namespace = {**attributes, "PARAMETERS": parameters, "__module__": base.__module__, "__qualname__": name}
        # Two threads may race to create the class; both get the one stored first.
        return Specialization.classes.setdefault(key, type(name, (base,), namespace))

    @staticmethod
    def require(value: Any, user: str) -> Any:
        """``value`` if the class has been specialized, as ``GCM[AES128]``."""
        if value is None:
            raise TypeError(f"choose the parameters of {user} first, as in {user}[...]")
        return value

    @staticmethod
    def size(value: Any, allowed: Any, user: str, what: str) -> int:
        """``value`` if it is an integer (not a bool or a float) among ``allowed``, as the constant
        parameters of the Rust types are."""
        if type(value) is not int or value not in allowed:
            raise TypeError(f"{user} takes {what}")
        return value

    @staticmethod
    def pair(parameters: Any, user: str) -> tuple[Any, Any]:
        """The two parameters of a subscript such as ``GCM[AES128, 16]``."""
        if not (isinstance(parameters, tuple) and len(parameters) == 2):
            raise TypeError(f"{user} takes two parameters, as {user}[..., ...]")
        return parameters


class StreamCipher(Primitive):
    """A stream cipher, as the Rust trait ``StreamCipher``."""

    def apply_keystream(self, data: bytearray) -> None:
        """Xors the next ``len(data)`` bytes of key stream into ``data``; raises ``LimitExceeded``,
        changing nothing, past the end of the key stream."""
        self.library.call(f"{self.PREFIX}_apply_keystream", self.handle, Bytes.mutable(data), len(data))


class AEAD(Primitive):
    """An authenticated encryption with associated data, as the Rust trait ``AEAD``.

    :meth:`encrypt` returns the ciphertext followed by the tag (RFC 5116), and
    :meth:`decrypt` takes it. A failed decryption raises ``AuthenticationFailed``
    and leaves no plaintext.
    """

    def nonce_size(self) -> int:
        """The recommended nonce size."""
        return self.library.value(f"{self.PREFIX}_nonce_size", ctypes.c_size_t, self.handle)

    def tag_size(self) -> int:
        return self.library.value(f"{self.PREFIX}_tag_size", ctypes.c_size_t, self.handle)

    def encrypt_in_place(
        self,
        nonce: bytes | bytearray | memoryview,
        associated: bytes | bytearray | memoryview,
        buffer: bytearray,
    ) -> bytes:
        """Encrypts ``buffer`` in place and returns the tag."""
        nonce_data, nonce_length = Bytes.readable(nonce)
        associated_data, associated_length = Bytes.readable(associated)
        tag = (ctypes.c_uint8 * self.tag_size())()
        self.library.call(
            f"{self.PREFIX}_encrypt_in_place",
            self.handle,
            nonce_data,
            nonce_length,
            associated_data,
            associated_length,
            Bytes.mutable(buffer),
            len(buffer),
            tag,
            len(tag),
        )
        return bytes(tag)

    def decrypt_in_place(
        self,
        nonce: bytes | bytearray | memoryview,
        associated: bytes | bytearray | memoryview,
        buffer: bytearray,
        tag: bytes | bytearray | memoryview,
    ) -> None:
        """Decrypts ``buffer`` in place if ``tag`` authenticates it and ``associated``."""
        nonce_data, nonce_length = Bytes.readable(nonce)
        associated_data, associated_length = Bytes.readable(associated)
        tag_data, tag_length = Bytes.readable(tag)
        self.library.call(
            f"{self.PREFIX}_decrypt_in_place",
            self.handle,
            nonce_data,
            nonce_length,
            associated_data,
            associated_length,
            Bytes.mutable(buffer),
            len(buffer),
            tag_data,
            tag_length,
        )

    def encrypt(
        self,
        nonce: bytes | bytearray | memoryview,
        associated: bytes | bytearray | memoryview,
        plaintext: bytes | bytearray | memoryview,
    ) -> bytes:
        """The ciphertext of ``plaintext`` followed by the tag."""
        buffer = bytearray(plaintext)
        tag = self.encrypt_in_place(nonce, associated, buffer)
        return bytes(buffer) + tag

    def decrypt(
        self,
        nonce: bytes | bytearray | memoryview,
        associated: bytes | bytearray | memoryview,
        ciphertext: bytes | bytearray | memoryview,
    ) -> bytes:
        """The plaintext of ``ciphertext``, which is followed by its tag."""
        size = self.tag_size()
        if len(ciphertext) < size:
            raise CryptoError("crypto", "InputLength", "the input is shorter than a tag")
        buffer = bytearray(ciphertext[: len(ciphertext) - size])
        self.decrypt_in_place(nonce, associated, buffer, bytes(ciphertext[len(ciphertext) - size :]))
        return bytes(buffer)


class MAC(Primitive):
    """A message authentication code, as the Rust trait ``MAC``: the key is absorbed once."""

    def output_size(self) -> int:
        return self.library.value(f"{self.PREFIX}_output_size", ctypes.c_size_t, self.handle)

    def update(self, data: bytes | bytearray | memoryview) -> None:
        """Adds ``data`` to the message."""
        data, length = Bytes.readable(data)
        self.library.call(f"{self.PREFIX}_update", self.handle, data, length)

    def finalize(self) -> bytes:
        """The tag of the message; releases the state."""
        out = (ctypes.c_uint8 * self.output_size())()
        with self.locked():
            self.library.call(f"{self.PREFIX}_finalize", self.pointer, out, len(out))
            self.consumed()
        return bytes(out)

    def reset(self) -> None:
        """Returns to the state after the key."""
        self.library.call(f"{self.PREFIX}_reset", self.handle)

    def verify(self, tag: bytes | bytearray | memoryview) -> bool:
        """Whether ``tag`` is the tag of the message, compared in constant time; releases the state."""
        return self.verify_with(f"{self.PREFIX}_verify", tag)

    def verify_with(self, name: str, tag: bytes | bytearray | memoryview, *arguments: Any) -> bool:
        """Calls the verification ``name``, which releases the state."""
        data, length = Bytes.readable(tag)
        valid = ctypes.c_bool()
        with self.locked():
            self.library.call(name, self.pointer, data, length, *arguments, ctypes.byref(valid))
            self.consumed()
        return valid.value


class EncodedKey:
    """A key of a public-key scheme, held as its encoding of the C ABI: ``SECRET`` keys keep it in a
    :class:`~umilib.secret.Secret`, zeroized when the key is closed or collected, compare in constant
    time and print nothing of it."""

    SECRET: ClassVar[bool] = False

    def __init__(self, scheme: type, encoding: bytes | bytearray | memoryview) -> None:
        """The key of ``scheme`` of ``encoding``, which is not validated here: the schemes create keys
        through their functions, such as ``ECDH[P256].private_key_from_bytes``. A ``bytearray`` is
        zeroized once a secret key holds its copy."""
        self.scheme = scheme
        if self.SECRET:
            self.secret: Secret | None = Secret(encoding if isinstance(encoding, bytearray) else bytearray(encoding))
            self.value = b""
        else:
            self.secret = None
            self.value = bytes(encoding)

    @classmethod
    def allocate(cls, scheme: type, size: int) -> Any:
        """A key of ``size`` zero bytes, for a function of the C ABI to write (see :meth:`writable`)."""
        return cls(scheme, bytearray(size))

    def check(self, scheme: type) -> None:
        """Raises ``TypeError`` unless the key is of ``scheme``."""
        if self.scheme is not scheme:
            raise TypeError(f"a {type(self).__name__} of {self.scheme.__name__} is not one of {scheme.__name__}")

    @staticmethod
    @contextlib.contextmanager
    def encodings(*keys: EncodedKey, handles: tuple[Handle, ...] = ()) -> Iterator[list[tuple[Any, int]]]:
        """The addresses and lengths of the encodings of ``keys`` for a block, with the secret keys and
        the ``handles`` that the calls of the block pass locked, in the order :class:`Function` takes them."""
        secrets = [key.secret for key in keys if key.secret is not None]
        with Handle.locked_all(*secrets, *handles):
            yield [key.secret.location() if key.secret is not None else Bytes.readable(key.value) for key in keys]

    @contextlib.contextmanager
    def writable(self, handles: tuple[Handle, ...] = ()) -> Iterator[tuple[Any, int]]:
        """The address and length of the encoding of a secret key, to write it in place in a block."""
        if self.secret is None:
            raise TypeError("only a secret key is written in place")
        with Handle.locked_all(self.secret, *handles):
            yield self.secret.location_mut()

    def validate(self, check: Any) -> None:
        """Calls ``check(address, length)`` on the encoding, which raises for an invalid key; the
        encoding of a secret key is zeroized at once if it does."""
        try:
            with EncodedKey.encodings(self) as [(data, length)]:
                check(data, length)
        except BaseException:
            self.close()
            raise

    def to_bytes(self) -> bytes:
        """The encoding of a public key; secret keys are written into a ``bytearray`` by their scheme."""
        if self.secret is not None:
            raise TypeError("a secret key is written by its scheme into a bytearray")
        return self.value

    def write(self, out: bytearray) -> None:
        """Writes the encoding into ``out`` of its length."""
        with EncodedKey.encodings(self) as [(data, length)]:
            if len(out) != length:
                raise CryptoError("crypto", "InputLength", f"the key has {length} bytes")
            if length:
                ctypes.memmove(Bytes.mutable(out), data, length)

    def close(self) -> None:
        """Zeroizes and releases the encoding of a secret key."""
        if self.secret is not None:
            self.secret.close()

    def __eq__(self, other: object) -> bool:
        if type(other) is not type(self) or other.scheme is not self.scheme:  # type: ignore[attr-defined]
            return NotImplemented
        if self.secret is not None:
            return self.secret.ct_eq(other.secret).into_bool()  # type: ignore[attr-defined]
        return self.value == other.value  # type: ignore[attr-defined]

    def __hash__(self) -> int:
        if self.secret is not None:
            raise TypeError("secret keys are not hashable")
        return hash((self.scheme, self.value))

    def __repr__(self) -> str:
        shown = ".." if self.secret is not None else self.value.hex()
        return f"{type(self).__name__}({self.scheme.__name__}, {shown})"


class PrivateKey(EncodedKey):
    """A private key of a :class:`KeyAgreement`."""

    SECRET = True


class PublicKey(EncodedKey):
    """A public key of a :class:`KeyAgreement`, validated when it is created from bytes."""


class SigningKey(EncodedKey):
    """A signing key of a :class:`SignatureScheme`."""

    SECRET = True


class VerifyingKey(EncodedKey):
    """A verifying key of a :class:`SignatureScheme`, validated when it is created from bytes."""


class DecapsulationKey(EncodedKey):
    """A decapsulation key of a :class:`KeyEncapsulation`."""

    SECRET = True


class EncapsulationKey(EncodedKey):
    """An encapsulation key of a :class:`KeyEncapsulation`, checked when it is created from bytes."""


class NamedScheme:
    """A scheme of the C ABI chosen by the C type names of its parameters (``PARAMETERS``, set by a
    subscript such as ``ECDSA[P256, SHA256]``), whose functions start with ``PREFIX``."""

    PREFIX: ClassVar[str] = ""
    PARAMETERS: ClassVar[tuple[Any, ...] | None] = None

    @classmethod
    def names(cls) -> list[Any]:
        """The arguments that name the parameters: the C type name of each, as bytes and length."""
        arguments: list[Any] = []
        for parameter in Specialization.require(cls.PARAMETERS, cls.__name__):
            arguments.extend(Text.encode(parameter.C_TYPE))
        return arguments

    @classmethod
    def call(cls, function: str, *arguments: Any) -> None:
        """Calls ``{PREFIX}_{function}`` with the names of the parameters first."""
        Library.default().call(f"{cls.PREFIX}_{function}", *cls.names(), *arguments)

    @classmethod
    def sizes(cls) -> tuple[int, ...]:
        """The sizes ``{PREFIX}_sizes`` writes, as many as ``SIZES`` names."""
        out = (ctypes.c_size_t * len(getattr(cls, "SIZES", (0, 0, 0))))()
        cls.call("sizes", out)
        return tuple(out)

    @classmethod
    def specialize(cls, parameters: tuple[Any, ...], size_names: tuple[str, ...], attributes: dict[str, Any]) -> Any:
        """The class of ``cls`` for ``parameters``, whose sizes ``size_names`` are read on first use."""
        holder: list[Any] = []
        for index, name in enumerate(size_names):
            attributes[name] = Preset(lambda index=index: holder[0].sizes()[index])
        specialized = Specialization.of(cls, parameters, attributes)
        holder.append(specialized)
        return specialized


class KeyAgreement(NamedScheme):
    """A key agreement, as the Rust trait ``KeyAgreement``: ``ECDH[P256]`` is a class of no instances
    whose functions take and give :class:`PrivateKey` and :class:`PublicKey`."""

    SIZES: ClassVar[tuple[str, str, str]] = ("PRIVATE_KEY_SIZE", "PUBLIC_KEY_SIZE", "SHARED_SECRET_SIZE")
    PRIVATE_KEY_SIZE: ClassVar[Any]
    PUBLIC_KEY_SIZE: ClassVar[Any]
    SHARED_SECRET_SIZE: ClassVar[Any]

    @classmethod
    def generate(cls, random: Any) -> PrivateKey:
        """A private key drawn from the generator ``random``."""
        key = PrivateKey.allocate(cls, cls.PRIVATE_KEY_SIZE)
        handle, name, length = random.source()
        with key.writable((random,)) as (data, size):
            cls.call("generate", handle, name, length, data, size)
        return key

    @classmethod
    def private_key_from_bytes(cls, data: bytes | bytearray | memoryview) -> PrivateKey:
        """The private key of the encoding ``data``; raises ``InvalidKey`` for an invalid one."""
        key = PrivateKey(cls, data)
        key.validate(lambda encoded, length: cls.call("check_private_key", encoded, length))
        return key

    @classmethod
    def write_private_key(cls, key: PrivateKey, out: bytearray) -> None:
        key.check(cls)
        key.write(out)

    @classmethod
    def public_key(cls, key: PrivateKey) -> PublicKey:
        key.check(cls)
        out = (ctypes.c_uint8 * cls.PUBLIC_KEY_SIZE)()
        with EncodedKey.encodings(key) as [(data, length)]:
            cls.call("public_key", data, length, out, len(out))
        return PublicKey(cls, bytes(out))

    @classmethod
    def public_key_from_bytes(cls, data: bytes | bytearray | memoryview) -> PublicKey:
        """The public key of the encoding ``data``; raises ``InvalidKey`` for an invalid one."""
        encoded, length = Bytes.readable(data)
        cls.call("check_public_key", encoded, length)
        return PublicKey(cls, data)

    @classmethod
    def write_public_key(cls, key: PublicKey, out: bytearray) -> None:
        key.check(cls)
        key.write(out)

    @classmethod
    def agree(cls, private: PrivateKey, public: PublicKey, out: bytearray) -> None:
        """Writes the secret shared by ``private`` and ``public`` into ``out`` of ``SHARED_SECRET_SIZE`` bytes."""
        private.check(cls)
        public.check(cls)
        with EncodedKey.encodings(private, public) as [(private_data, private_length), (public_data, public_length)]:
            cls.call("agree", private_data, private_length, public_data, public_length, Bytes.mutable(out), len(out))


class SignatureScheme(NamedScheme):
    """A signature scheme, as the Rust trait ``SignatureScheme``: ``ECDSA[P256, SHA256]`` is a class of
    no instances whose functions take and give :class:`SigningKey` and :class:`VerifyingKey`."""

    SIZES: ClassVar[tuple[str, str, str]] = ("SIGNING_KEY_SIZE", "VERIFYING_KEY_SIZE", "SIGNATURE_SIZE")
    SIGNING_KEY_SIZE: ClassVar[Any]
    VERIFYING_KEY_SIZE: ClassVar[Any]
    SIGNATURE_SIZE: ClassVar[Any]

    @classmethod
    def generate(cls, random: Any) -> SigningKey:
        """A signing key drawn from the generator ``random``."""
        key = SigningKey.allocate(cls, cls.SIGNING_KEY_SIZE)
        handle, name, length = random.source()
        with key.writable((random,)) as (data, size):
            cls.call("generate", handle, name, length, data, size)
        return key

    @classmethod
    def signing_key_from_bytes(cls, data: bytes | bytearray | memoryview) -> SigningKey:
        """The signing key of the encoding ``data``; raises ``InvalidKey`` for an invalid one."""
        key = SigningKey(cls, data)
        key.validate(lambda encoded, length: cls.call("check_signing_key", encoded, length))
        return key

    @classmethod
    def write_signing_key(cls, key: SigningKey, out: bytearray) -> None:
        key.check(cls)
        key.write(out)

    @classmethod
    def verifying_key(cls, key: SigningKey) -> VerifyingKey:
        key.check(cls)
        out = (ctypes.c_uint8 * cls.VERIFYING_KEY_SIZE)()
        with EncodedKey.encodings(key) as [(data, length)]:
            cls.call("verifying_key", data, length, out, len(out))
        return VerifyingKey(cls, bytes(out))

    @classmethod
    def verifying_key_from_bytes(cls, data: bytes | bytearray | memoryview) -> VerifyingKey:
        """The verifying key of the encoding ``data``; raises ``InvalidKey`` for an invalid one."""
        encoded, length = Bytes.readable(data)
        cls.call("check_verifying_key", encoded, length)
        return VerifyingKey(cls, data)

    @classmethod
    def write_verifying_key(cls, key: VerifyingKey, out: bytearray) -> None:
        key.check(cls)
        key.write(out)

    @classmethod
    def sign(cls, key: SigningKey, message: bytes | bytearray | memoryview) -> bytes:
        """The signature of ``message`` under ``key``."""
        key.check(cls)
        out = (ctypes.c_uint8 * cls.SIGNATURE_SIZE)()
        message_data, message_length = Bytes.readable(message)
        with EncodedKey.encodings(key) as [(data, length)]:
            cls.call("sign", data, length, message_data, message_length, out, len(out))
        return bytes(out)

    @classmethod
    def verify(cls, key: VerifyingKey, message: bytes | bytearray | memoryview, signature: bytes | bytearray | memoryview) -> None:
        """Returns if ``signature`` is a signature of ``message`` under ``key``; raises
        ``InvalidSignature`` otherwise."""
        key.check(cls)
        message_data, message_length = Bytes.readable(message)
        signature_data, signature_length = Bytes.readable(signature)
        with EncodedKey.encodings(key) as [(data, length)]:
            cls.call("verify", data, length, message_data, message_length, signature_data, signature_length)


class ContextSignatureScheme(SignatureScheme):
    """A signature scheme whose signatures take a context and may pre-hash the message, as ML-DSA
    (FIPS 204) and SLH-DSA (FIPS 205) do: the functions of :class:`SignatureScheme` sign
    deterministically with the empty context; these sign with a context (at most 255 bytes) hedged by
    random values of a generator or deterministically, and their ``pre_hash`` forms (HashML-DSA,
    HashSLH-DSA) with a hash function of :mod:`umilib.hash` (SHA-2, SHA-3, SHAKE128, SHAKE256)."""

    @classmethod
    def sign_with_context(cls, key: SigningKey, message: Any, context: Any, random: Any) -> bytes:
        """The hedged signature of ``message`` with ``context``; raises ``InvalidParameter`` for a context
        of more than 255 bytes."""
        handle, name, length = random.source()
        return cls.sign_variant("sign_with_context", [], key, message, context, [handle, name, length], (random,))

    @classmethod
    def sign_deterministic_with_context(cls, key: SigningKey, message: Any, context: Any) -> bytes:
        """The deterministic signature of ``message`` with ``context``."""
        return cls.sign_variant("sign_deterministic_with_context", [], key, message, context, [], ())

    @classmethod
    def verify_with_context(cls, key: VerifyingKey, message: Any, context: Any, signature: Any) -> None:
        """Returns if ``signature`` is a signature of ``message`` with ``context``; raises
        ``InvalidSignature`` otherwise."""
        cls.verify_variant("verify_with_context", [], key, message, context, signature)

    @classmethod
    def sign_pre_hash(cls, hash: Any, key: SigningKey, message: Any, context: Any, random: Any) -> bytes:
        """The hedged pre-hash signature of ``message`` with ``context`` and the hash function ``hash``."""
        handle, name, length = random.source()
        names = [*Text.encode(hash.C_TYPE)]
        return cls.sign_variant("sign_pre_hash", names, key, message, context, [handle, name, length], (random,))

    @classmethod
    def sign_pre_hash_deterministic(cls, hash: Any, key: SigningKey, message: Any, context: Any) -> bytes:
        """The deterministic pre-hash signature of ``message`` with ``context`` and ``hash``."""
        return cls.sign_variant("sign_pre_hash_deterministic", [*Text.encode(hash.C_TYPE)], key, message, context, [], ())

    @classmethod
    def verify_pre_hash(cls, hash: Any, key: VerifyingKey, message: Any, context: Any, signature: Any) -> None:
        """Returns if ``signature`` is a pre-hash signature of ``message`` with ``context`` and ``hash``;
        raises ``InvalidSignature`` otherwise."""
        cls.verify_variant("verify_pre_hash", [*Text.encode(hash.C_TYPE)], key, message, context, signature)

    @classmethod
    def sign_variant(
        cls, function: str, names: list[Any], key: SigningKey, message: Any, context: Any, random: list[Any], handles: tuple[Any, ...]
    ) -> bytes:
        key.check(cls)
        out = (ctypes.c_uint8 * cls.SIGNATURE_SIZE)()
        message_data, message_length = Bytes.readable(message)
        context_data, context_length = Bytes.readable(context)
        with EncodedKey.encodings(key, handles=handles) as [(data, length)]:
            cls.call(function, *names, data, length, message_data, message_length, context_data, context_length, *random, out, len(out))
        return bytes(out)

    @classmethod
    def verify_variant(cls, function: str, names: list[Any], key: VerifyingKey, message: Any, context: Any, signature: Any) -> None:
        key.check(cls)
        message_data, message_length = Bytes.readable(message)
        context_data, context_length = Bytes.readable(context)
        signature_data, signature_length = Bytes.readable(signature)
        with EncodedKey.encodings(key) as [(data, length)]:
            cls.call(function, *names, data, length, message_data, message_length, context_data, context_length, signature_data, signature_length)


class KeyEncapsulation(NamedScheme):
    """A key-encapsulation mechanism, as the Rust trait ``KeyEncapsulation``: ``MLKEM[MLKEM768]`` is a
    class of no instances whose functions take and give :class:`DecapsulationKey` and
    :class:`EncapsulationKey`."""

    SIZES: ClassVar[tuple[str, ...]] = (
        "DECAPSULATION_KEY_SIZE",
        "ENCAPSULATION_KEY_SIZE",
        "CIPHERTEXT_SIZE",
        "SHARED_SECRET_SIZE",
    )
    DECAPSULATION_KEY_SIZE: ClassVar[Any]
    ENCAPSULATION_KEY_SIZE: ClassVar[Any]
    CIPHERTEXT_SIZE: ClassVar[Any]
    SHARED_SECRET_SIZE: ClassVar[Any]

    @classmethod
    def generate(cls, random: Any) -> DecapsulationKey:
        """A decapsulation key drawn from the generator ``random``."""
        key = DecapsulationKey.allocate(cls, cls.DECAPSULATION_KEY_SIZE)
        handle, name, length = random.source()
        with key.writable((random,)) as (data, size):
            cls.call("generate", handle, name, length, data, size)
        return key

    @classmethod
    def decapsulation_key_from_bytes(cls, data: bytes | bytearray | memoryview) -> DecapsulationKey:
        """The decapsulation key of the encoding ``data``; raises ``InvalidKey`` unless it passes the
        checks of the scheme."""
        key = DecapsulationKey(cls, data)
        key.validate(lambda encoded, length: cls.call("check_decapsulation_key", encoded, length))
        return key

    @classmethod
    def write_decapsulation_key(cls, key: DecapsulationKey, out: bytearray) -> None:
        key.check(cls)
        key.write(out)

    @classmethod
    def encapsulation_key(cls, key: DecapsulationKey) -> EncapsulationKey:
        key.check(cls)
        out = (ctypes.c_uint8 * cls.ENCAPSULATION_KEY_SIZE)()
        with EncodedKey.encodings(key) as [(data, length)]:
            cls.call("encapsulation_key", data, length, out, len(out))
        return EncapsulationKey(cls, bytes(out))

    @classmethod
    def encapsulation_key_from_bytes(cls, data: bytes | bytearray | memoryview) -> EncapsulationKey:
        """The encapsulation key of the encoding ``data``; raises ``InvalidKey`` unless it passes the
        checks of the scheme."""
        encoded, length = Bytes.readable(data)
        cls.call("check_encapsulation_key", encoded, length)
        return EncapsulationKey(cls, data)

    @classmethod
    def write_encapsulation_key(cls, key: EncapsulationKey, out: bytearray) -> None:
        key.check(cls)
        key.write(out)

    @classmethod
    def encapsulate(cls, key: EncapsulationKey, random: Any, shared: bytearray) -> bytes:
        """Returns a ciphertext for the owner of ``key`` and writes the secret it carries into ``shared``
        of ``SHARED_SECRET_SIZE`` bytes, with the random values of ``random``."""
        key.check(cls)
        ciphertext = (ctypes.c_uint8 * cls.CIPHERTEXT_SIZE)()
        handle, name, length = random.source()
        with EncodedKey.encodings(key, handles=(random,)) as [(data, key_length)]:
            cls.call(
                "encapsulate", data, key_length, handle, name, length, ciphertext, len(ciphertext), Bytes.mutable(shared), len(shared)
            )
        return bytes(ciphertext)

    @classmethod
    def decapsulate(cls, key: DecapsulationKey, ciphertext: bytes | bytearray | memoryview, shared: bytearray) -> None:
        """Writes the secret ``ciphertext`` carries for ``key`` into ``shared`` of ``SHARED_SECRET_SIZE`` bytes."""
        key.check(cls)
        ciphertext_data, ciphertext_length = Bytes.readable(ciphertext)
        with EncodedKey.encodings(key) as [(data, length)]:
            cls.call("decapsulate", data, length, ciphertext_data, ciphertext_length, Bytes.mutable(shared), len(shared))


class Names:
    """The checks of the classes that name the parameters of a scheme."""

    @staticmethod
    def require(value: Any, kind: type, user: str) -> Any:
        """``value`` if it is a named class of ``kind`` (a :class:`~umilib.ffi.Marker` or a hash function)."""
        if not (isinstance(value, type) and issubclass(value, kind) and getattr(value, "C_TYPE", "")):
            raise TypeError(f"{user} needs a {kind.__name__} class")
        return value


__all__ = [
    "AEAD",
    "BlockCipher",
    "BlockCipherClass",
    "ContextSignatureScheme",
    "CryptoError",
    "DecapsulationKey",
    "EncapsulationKey",
    "EncodedKey",
    "KeyAgreement",
    "KeyEncapsulation",
    "MAC",
    "NamedScheme",
    "Names",
    "Primitive",
    "PrivateKey",
    "PublicKey",
    "SignatureScheme",
    "SigningKey",
    "Specialization",
    "StreamCipher",
    "VerifyingKey",
]
