"""Reference key-material codec for the draft codex32 key-expression BIP.

This module implements the draft payload layouts. python-codex32 supplies BIP93
framing, checksums and share parsing; it is not modified by this example.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from codex32 import Share, parse_codex32, recover_secret
from codex32.bech32 import CHARSET, bech32_encode
from codex32.checksums import _CODEX32, _CODEX32_LONG

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
VERSIONS = {
    "xpub": bytes.fromhex("0488b21e"),
    "xprv": bytes.fromhex("0488ade4"),
    "tpub": bytes.fromhex("043587cf"),
    "tprv": bytes.fromhex("04358394"),
}
WIF_VERSIONS = {"main": 0x80, "test": 0xEF}
WIF_STATUS = {
    ("main", False): 0b0111,
    ("main", True): 0b1011,
    ("test", False): 0b0000,
    ("test", True): 0b1100,
}
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class InvalidKey(ValueError):
    """The codex32 string is valid but is not valid key material."""


@dataclass(frozen=True)
class ExtendedKey:
    """The BIP32 fields that can be round-tripped by this draft format."""

    kind: str
    depth: int
    parent_fingerprint: bytes
    child_number: int
    chain_code: bytes
    key: bytes  # compressed public key or 32-byte private scalar


@dataclass(frozen=True)
class DecodedKey:
    """The result of interpreting a validated, unshared codex32 secret."""

    kind: str
    key: bytes | ExtendedKey
    network: str | None = None
    compressed: bool | None = None


def _bits(value: int, width: int) -> str:
    if value < 0 or value >= 1 << width:
        raise InvalidKey(f"value does not fit in {width} bits")
    return f"{value:0{width}b}"


def _from_symbols(symbols: tuple[int, ...]) -> str:
    return "".join(_bits(value, 5) for value in symbols)


def _to_symbols(bits: str) -> list[int]:
    if len(bits) % 5:
        raise InvalidKey("payload must fill complete symbols")
    return [int(bits[position : position + 5], 2) for position in range(0, len(bits), 5)]


def _crc(bits: str, width: int) -> str:
    """Spare-bit CRC: remainder of (1 || M) * x**width, MSB first, XOR all ones above width 1."""
    polynomial = (1 << width) | 3
    value = int("1" + bits + "0" * width, 2)
    for shift in range(value.bit_length() - width - 1, -1, -1):
        if value & (1 << (shift + width)):
            value ^= polynomial << shift
    if width > 1:
        value ^= (1 << width) - 1
    return _bits(value, width)


def _check_scalar(scalar: bytes) -> None:
    if len(scalar) != 32 or not 1 <= int.from_bytes(scalar, "big") < N:
        raise InvalidKey("private scalar must satisfy 1 <= k < secp256k1 order")


def _check_point(key: bytes, *, xonly: bool = False) -> None:
    if xonly:
        if len(key) != 32:
            raise InvalidKey("x-only key must be 32 bytes")
        x = int.from_bytes(key, "big")
        if x >= P or pow(pow(x, 3, P) + 7, (P - 1) // 2, P) != 1:
            raise InvalidKey("x coordinate does not lift to secp256k1")
        return
    if len(key) == 33 and key[0] in (2, 3):
        x = int.from_bytes(key[1:], "big")
        if x >= P:
            raise InvalidKey("x coordinate is out of range")
        y2 = (pow(x, 3, P) + 7) % P
        y = pow(y2, (P + 1) // 4, P)
        if (y * y) % P != y2 or (y == 0 and key[0] == 3):
            raise InvalidKey("compressed point is not on secp256k1")
        return
    if len(key) == 65 and key[0] == 4:
        x = int.from_bytes(key[1:33], "big")
        y = int.from_bytes(key[33:], "big")
        if x < P and y < P and (y * y - x * x * x - 7) % P == 0:
            return
        raise InvalidKey("uncompressed point is not on secp256k1")
    raise InvalidKey("expected a compressed or uncompressed secp256k1 public key")


def _encode(hrp: str, bits: str, *, identifier: str, threshold: int) -> str:
    if threshold not in (0, *range(2, 10)):
        raise ValueError("threshold must be 0 or 2 through 9")
    if len(identifier) != 4 or any(letter not in CHARSET for letter in identifier):
        raise ValueError("identifier must contain four lowercase bech32 symbols")
    payload = _to_symbols(bits)
    header = [CHARSET.index(letter) for letter in f"{threshold}{identifier}s"]
    regular_length = 2 * len(hrp) + 1 + len(header) + len(payload) + _CODEX32.length
    checksum = _CODEX32 if regular_length <= 93 else _CODEX32_LONG
    encoded = bech32_encode(hrp, header + payload, checksum)
    parse_codex32(encoded)
    return encoded


def encode_public_key(key: bytes, *, identifier: str = "qqqq", threshold: int = 0) -> str:
    _check_point(key)
    if len(key) == 33:
        raw = _bits(key[0] - 2, 1) + _bits(int.from_bytes(key[1:], "big"), 256)
        return _encode("pk", raw + _crc(raw, 3), identifier=identifier, threshold=threshold)
    return _encode("pk", _bits(int.from_bytes(key, "big"), 520), identifier=identifier, threshold=threshold)


def encode_xonly_key(key: bytes, *, identifier: str = "qqqq", threshold: int = 0) -> str:
    _check_point(key, xonly=True)
    raw = _bits(int.from_bytes(key, "big"), 256)
    return _encode("xo", raw + _crc(raw, 4), identifier=identifier, threshold=threshold)


def encode_private_key(
    scalar: bytes, *, network: str, compressed: bool, identifier: str = "qqqq", threshold: int = 0
) -> str:
    _check_scalar(scalar)
    if type(compressed) is not bool:
        raise TypeError("compressed must be bool")
    try:
        status = WIF_STATUS[(network, compressed)]
    except KeyError as error:
        raise ValueError("network must be main or test; compressed must be bool") from error
    raw = _bits(status, 4) + _bits(int.from_bytes(scalar, "big"), 256)
    return _encode("wf", raw, identifier=identifier, threshold=threshold)


def encode_extended_key(key: ExtendedKey, *, identifier: str = "qqqq", threshold: int = 0) -> str:
    if key.kind not in VERSIONS:
        raise InvalidKey("unknown extended-key kind")
    if not 0 <= key.depth <= 31:
        raise InvalidKey("draft encoding permits depth 0 through 31")
    if len(key.parent_fingerprint) != 4 or len(key.chain_code) != 32:
        raise InvalidKey("parent fingerprint must be 4 bytes and chain code 32 bytes")
    if not 0 <= key.child_number < 1 << 32:
        raise InvalidKey("child number must be uint32")
    if key.depth == 0 and (key.parent_fingerprint != b"\0" * 4 or key.child_number != 0):
        raise InvalidKey("master metadata must be zero")
    raw = (
        _bits(key.depth, 5)
        + _bits(key.child_number >> 31, 1)
        + "000"
        + _bits(key.child_number & 0x7FFFFFFF, 31)
        + _bits(int.from_bytes(key.parent_fingerprint, "big"), 32)
        + _bits(int.from_bytes(key.chain_code, "big"), 256)
    )
    if key.kind.endswith("pub"):
        _check_point(key.key)
        if len(key.key) != 33:
            raise InvalidKey("extended public key must be compressed")
        raw += _bits(key.key[0] - 2, 1) + _bits(int.from_bytes(key.key[1:], "big"), 256)
    else:
        _check_scalar(key.key)
        raw += _bits(int.from_bytes(key.key, "big"), 256)
        raw += _crc(raw, 1)
    return _encode(key.kind, raw, identifier=identifier, threshold=threshold)


def decode_key(text: str) -> DecodedKey:
    artifact = parse_codex32(text)
    if isinstance(artifact, Share):
        raise InvalidKey("shares do not individually encode keys; recover the secret first")
    bits = _from_symbols(artifact.payload_symbols)
    hrp = artifact.hrp
    if hrp == "pk":
        if len(bits) == 260:
            raw, padding = bits[:257], bits[257:]
            if padding != _crc(raw, 3):
                raise InvalidKey("compressed public-key CRC mismatch")
            key = bytes([2 + int(raw[0])]) + int(raw[1:], 2).to_bytes(32, "big")
        elif len(bits) == 520:
            key = int(bits, 2).to_bytes(65, "big")
        else:
            raise InvalidKey("incorrect public-key payload length")
        _check_point(key)
        return DecodedKey(hrp, key)
    if hrp == "xo":
        if len(bits) != 260 or bits[256:] != _crc(bits[:256], 4):
            raise InvalidKey("x-only payload length or CRC mismatch")
        key = int(bits[:256], 2).to_bytes(32, "big")
        _check_point(key, xonly=True)
        return DecodedKey(hrp, key)
    if hrp == "wf":
        if len(bits) != 260:
            raise InvalidKey("incorrect WIF payload length")
        statuses = {value: status for status, value in WIF_STATUS.items()}
        status = statuses.get(int(bits[:4], 2))
        if status is None:
            raise InvalidKey("unknown WIF status")
        scalar = int(bits[4:], 2).to_bytes(32, "big")
        _check_scalar(scalar)
        return DecodedKey(hrp, scalar, *status)
    if hrp in VERSIONS:
        if len(bits) != 585 or bits[6:9] != "000":
            raise InvalidKey("extended-key length or child-number padding is invalid")
        depth = int(bits[:5], 2)
        child_number = (int(bits[5], 2) << 31) | int(bits[9:40], 2)
        fingerprint = int(bits[40:72], 2).to_bytes(4, "big")
        chain_code = int(bits[72:328], 2).to_bytes(32, "big")
        if hrp.endswith("pub"):
            public_bits = bits[328:]
            key = bytes([2 + int(public_bits[0])]) + int(public_bits[1:], 2).to_bytes(32, "big")
            _check_point(key)
        else:
            if bits[-1] != _crc(bits[:-1], 1):
                raise InvalidKey("extended-private-key parity mismatch")
            key = int(bits[328:584], 2).to_bytes(32, "big")
            _check_scalar(key)
        extended = ExtendedKey(hrp, depth, fingerprint, child_number, chain_code, key)
        if depth == 0 and (fingerprint != b"\0" * 4 or child_number != 0):
            raise InvalidKey("master metadata must be zero")
        return DecodedKey(hrp, extended)
    raise InvalidKey(f"unsupported key HRP: {hrp}")


def recover_key(share_texts: Sequence[str]) -> DecodedKey:
    """Recover exactly the declared threshold of BIP93 shares, then validate the key."""
    shares: list[Share] = []
    for text in share_texts:
        artifact = parse_codex32(text)
        if not isinstance(artifact, Share):
            raise InvalidKey("recovery inputs must be ordinary shares")
        shares.append(artifact)
    secret = recover_secret(shares)
    return decode_key(secret.text)


def _base58check_encode(payload: bytes) -> str:
    import hashlib

    checked = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    number = int.from_bytes(checked, "big")
    result = ""
    while number:
        number, digit = divmod(number, 58)
        result = BASE58[digit] + result
    return "1" * (len(checked) - len(checked.lstrip(b"\0"))) + result


def _base58check_decode(text: str) -> bytes:
    import hashlib

    number = 0
    for character in text:
        if character not in BASE58:
            raise InvalidKey("invalid Base58 character")
        number = number * 58 + BASE58.index(character)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    raw = b"\0" * (len(text) - len(text.lstrip("1"))) + raw
    if len(raw) < 5 or hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] != raw[-4:]:
        raise InvalidKey("invalid Base58Check checksum")
    return raw[:-4]


def extended_from_base58(text: str) -> ExtendedKey:
    raw = _base58check_decode(text)
    if len(raw) != 78:
        raise InvalidKey("BIP32 serialized key must be 78 bytes")
    kinds = {version: kind for kind, version in VERSIONS.items()}
    kind = kinds.get(raw[:4])
    if kind is None:
        raise InvalidKey("unknown BIP32 version")
    data = raw[45:]
    key = data if kind.endswith("pub") else data[1:]
    if kind.endswith("prv") and data[0] != 0:
        raise InvalidKey("BIP32 private-key marker must be zero")
    result = ExtendedKey(kind, raw[4], raw[5:9], int.from_bytes(raw[9:13], "big"), raw[13:45], key)
    if result.depth == 0 and (result.parent_fingerprint != b"\0" * 4 or result.child_number != 0):
        raise InvalidKey("master metadata must be zero")
    if kind.endswith("pub"):
        _check_point(key)
    else:
        _check_scalar(key)
    return result


def extended_to_base58(key: ExtendedKey) -> str:
    if key.kind not in VERSIONS or not 0 <= key.depth <= 255:
        raise InvalidKey("unknown extended-key kind or depth")
    if len(key.parent_fingerprint) != 4 or len(key.chain_code) != 32:
        raise InvalidKey("invalid BIP32 metadata")
    if not 0 <= key.child_number < 1 << 32:
        raise InvalidKey("child number must be uint32")
    if key.kind.endswith("pub"):
        _check_point(key.key)
        if len(key.key) != 33:
            raise InvalidKey("extended public key must be compressed")
        data = key.key
    else:
        _check_scalar(key.key)
        data = b"\0" + key.key
    return _base58check_encode(
        VERSIONS[key.kind]
        + bytes([key.depth])
        + key.parent_fingerprint
        + key.child_number.to_bytes(4, "big")
        + key.chain_code
        + data
    )


def wif_from_base58(text: str) -> tuple[bytes, str, bool]:
    raw = _base58check_decode(text)
    versions = {version: network for network, version in WIF_VERSIONS.items()}
    if not raw or raw[0] not in versions:
        raise InvalidKey("unknown WIF network")
    if len(raw) == 33:
        scalar, compressed = raw[1:], False
    elif len(raw) == 34 and raw[-1] == 1:
        scalar, compressed = raw[1:-1], True
    else:
        raise InvalidKey("invalid WIF length or compression marker")
    _check_scalar(scalar)
    return scalar, versions[raw[0]], compressed


def wif_to_base58(scalar: bytes, *, network: str, compressed: bool) -> str:
    _check_scalar(scalar)
    if network not in WIF_VERSIONS:
        raise InvalidKey("unknown WIF network")
    return _base58check_encode(bytes([WIF_VERSIONS[network]]) + scalar + (b"\1" if compressed else b""))
