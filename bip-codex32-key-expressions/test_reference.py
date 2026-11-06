"""Interoperability checks using BIP32's published extended-key vectors."""

import unittest
from dataclasses import replace
from functools import partial

from codex32 import CodexError, derive_share, parse_codex32
from codex32.bech32 import CHARSET, bech32_encode
from codex32.checksums import _CODEX32, _CODEX32_LONG
from codex32.errors import (
    DuplicateShareIndex,
    InvalidChecksum,
    MismatchedHrp,
    MismatchedIdentifier,
    MismatchedThreshold,
    WrongShareCount,
)

from reference import (
    VERSIONS,
    DecodedKey,
    ExtendedKey,
    InvalidKey,
    _base58check_encode,
    decode_key,
    encode_extended_key,
    encode_private_key,
    encode_public_key,
    encode_xonly_key,
    extended_from_base58,
    extended_to_base58,
    recover_key,
    wif_from_base58,
    wif_to_base58,
)

ID = "test"  # There is no default identifier.
# These strings are copied from BIP32 test vector 2.
XPUB_MASTER = (
    "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8"
    "ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
)
XPRV_MASTER = (
    "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3p"
    "Gz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
)
# Chain m/0.
XPUB = (
    "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUb"
    "C6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
)
XPRV = (
    "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3d"
    "KYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
)
# Every string in BIP32 test vector 5 is invalid.
INVALID_BASE58 = (
    "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm",
    "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH",
    "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn",
    "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ",
    "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4",
    "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J",
    "xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv",
    "xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ",
    "xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN",
    "xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8",
    "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4",
    "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9",
    "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx",
    "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G",
    "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY",
    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL",
)
GENERATOR = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
UNCOMPRESSED = bytes.fromhex(
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)


def _codex32(hrp, header, payload):
    data = [CHARSET.index(char) for char in header] + list(payload)
    checksum = _CODEX32 if 2 * len(hrp) + 1 + len(data) + _CODEX32.length <= 93 else _CODEX32_LONG
    return bech32_encode(hrp, data, checksum)


def _split(secret, *payloads, count):
    """Choose the payloads of the first k - 1 shares, then derive the rest as in BIP93."""
    hrp, _, data = secret.rpartition("1")
    chosen = [_codex32(hrp, data[:5] + index, payload) for index, payload in zip("ac", payloads)]
    basis = [parse_codex32(text) for text in (secret, *chosen)]
    return chosen + [derive_share(basis, index).text for index in "acdefgh"[len(chosen) : count]]


class ReferenceTests(unittest.TestCase):
    def test_public_key_shapes_and_validation(self):
        compressed = encode_public_key(GENERATOR, identifier=ID)
        uncompressed = encode_public_key(UNCOMPRESSED, identifier=ID)
        xonly = encode_xonly_key(GENERATOR[1:], identifier=ID)
        self.assertEqual((len(compressed), len(uncompressed), len(xonly)), (74, 128, 74))
        self.assertEqual(decode_key(compressed).key, GENERATOR)
        self.assertEqual(decode_key(uncompressed).key, UNCOMPRESSED)
        self.assertEqual(decode_key(xonly).key, GENERATOR[1:])
        with self.assertRaises(InvalidKey):
            encode_public_key(b"\x02" + b"\xff" * 32, identifier=ID)
        with self.assertRaises(InvalidKey):
            encode_xonly_key(b"\xff" * 32, identifier=ID)

    def test_private_key_wif_round_trip(self):
        first_symbols = {
            ("main", False): "w",
            ("main", True): "k",
            ("test", False): "q",
            ("test", True): "c",
        }
        for network in ("main", "test"):
            for compressed in (False, True):
                scalar = (1).to_bytes(32, "big")
                wif = wif_to_base58(scalar, network=network, compressed=compressed)
                self.assertEqual(wif_from_base58(wif), (scalar, network, compressed))
                encoded = encode_private_key(scalar, network=network, compressed=compressed, identifier=ID)
                self.assertEqual(encoded.split("1", 1)[1][6], first_symbols[(network, compressed)])
                decoded = decode_key(encoded)
                self.assertEqual(
                    (decoded.key, decoded.network, decoded.compressed), (scalar, network, compressed)
                )
                self.assertEqual(len(encoded), 74)
        with self.assertRaises(InvalidKey):
            encode_private_key(b"\x00" * 32, network="main", compressed=True, identifier=ID)

    def test_extended_key_round_trip(self):
        for serialized in (XPUB_MASTER, XPRV_MASTER, XPUB, XPRV):
            key = extended_from_base58(serialized)
            self.assertEqual(key.depth, 0 if serialized in (XPUB_MASTER, XPRV_MASTER) else 1)
            self.assertEqual(key.child_number, 0)
            self.assertEqual(extended_to_base58(key), serialized)
            encoded = encode_extended_key(key, identifier=ID)
            self.assertEqual(len(encoded), 144)
            self.assertEqual(decode_key(encoded).key, key)

    def test_hardened_child_and_padding(self):
        key = extended_from_base58(XPRV)
        hardened = ExtendedKey(
            key.kind, key.depth, key.parent_fingerprint, 0x80000001, key.chain_code, key.key
        )
        encoded = encode_extended_key(hardened, identifier=ID)
        self.assertEqual(decode_key(encoded).key, hardened)
        self.assertEqual(encoded[encoded.index("1") + 9], "s")
        for depth in (1, 31, 32, 255):
            deep = replace(hardened, depth=depth)
            self.assertEqual(decode_key(encode_extended_key(deep, identifier=ID)).key, deep)
        with self.assertRaises(InvalidKey):
            encode_extended_key(replace(hardened, depth=256), identifier=ID)
        data = [CHARSET.index(char) for char in encoded.split("1", 1)[1][:-15]]
        data[6:8] = [0b01000, 0]  # Depth 1 becomes 256, with the same parity.
        with self.assertRaisesRegex(InvalidKey, "depth exceeds 255"):
            decode_key(bech32_encode("xprv", data, _CODEX32_LONG))

    def test_invalid_base58(self):
        for serialized in INVALID_BASE58:
            with self.assertRaises(InvalidKey):
                extended_from_base58(serialized)

    def test_master_metadata(self):
        master = extended_from_base58(XPUB_MASTER)
        for fingerprint, child_number in ((b"\0\0\0\1", 0), (b"\0" * 4, 1), (b"\0\0\0\1", 1)):
            key = replace(master, parent_fingerprint=fingerprint, child_number=child_number)
            serialized = _base58check_encode(
                VERSIONS["xpub"]
                + b"\0"
                + fingerprint
                + child_number.to_bytes(4, "big")
                + key.chain_code
                + key.key
            )
            # Encode at depth 1, then zero the depth, the first two payload symbols.
            encoded = encode_extended_key(replace(key, depth=1), identifier=ID)
            data = [CHARSET.index(char) for char in encoded.split("1", 1)[1][:-15]]
            data[6:8] = [0, 0]
            for convert, value in (
                (extended_to_base58, key),
                (partial(encode_extended_key, identifier=ID), key),
                (extended_from_base58, serialized),
                (decode_key, bech32_encode("xpub", data, _CODEX32_LONG)),
            ):
                with self.assertRaisesRegex(InvalidKey, "master metadata"):
                    convert(value)

    def test_recovery_ignores_share_payload_rules(self):
        xprv = extended_from_base58(XPRV)
        wif = encode_private_key(xprv.key, network="main", compressed=True, identifier="keys", threshold=2)
        public = encode_public_key(GENERATOR, identifier="pkey", threshold=2, origin="d34db33f/84h/1h/0h")
        public_payload = parse_codex32(public).payload_symbols
        extended = encode_extended_key(xprv, identifier="xprv", threshold=3)
        sets = (
            (wif, (((23,) + (31,) * 51, "scalar"),)),
            (public, ((public_payload[:-1] + (public_payload[-1] ^ 1,), "CRC"),)),
            (extended, (((31,) * 118, "padding"), ((7, 31, 17) + (31,) * 114 + (30,), "parity"))),
        )
        for secret, chosen in sets:
            # Each chosen payload would be rejected as a secret.
            for payload, reason in chosen:
                with self.assertRaisesRegex(InvalidKey, reason):
                    decode_key(_codex32(secret.rpartition("1")[0], "0qqqqs", payload))
            shares = _split(secret, *(payload for payload, _ in chosen), count=5)
            for share in shares:
                with self.assertRaisesRegex(InvalidKey, "recover the secret first"):
                    decode_key(share)
            threshold = len(chosen) + 1
            for start in range(len(shares) - threshold + 1):
                self.assertEqual(recover_key(shares[start : start + threshold]), decode_key(secret))

    def test_recovery_rejects_bad_sets(self):
        scalar = extended_from_base58(XPRV).key
        payload = (23,) + (31,) * 51

        def wif(identifier="keys", threshold=2):
            return encode_private_key(
                scalar, network="main", compressed=True, identifier=identifier, threshold=threshold
            )

        secret = wif()
        a, c, d = _split(secret, payload, count=3)
        other_identifier = _split(wif(identifier="cafe"), payload, count=2)[1]
        other_hrp = _split(encode_public_key(GENERATOR, identifier="keys", threshold=2), payload, count=2)[1]
        other_threshold = _split(wif(threshold=3), payload, payload, count=3)[2]
        for shares, error in (
            ([a], WrongShareCount),
            ([a, c, d], WrongShareCount),
            ([a, a], DuplicateShareIndex),
            ([a, other_identifier], MismatchedIdentifier),
            ([a, other_hrp], MismatchedHrp),
            ([a, other_threshold], MismatchedThreshold),
            ([a, c[:-1] + ("q" if c[-1] != "q" else "p")], InvalidChecksum),
            ([secret, c], InvalidKey),
        ):
            with self.assertRaises(error):
                recover_key(shares)

    def test_origin_in_hrp(self):
        key = extended_from_base58(XPUB)
        origin = "d34db33f/48h/0'/0h/2h"
        encoded = encode_extended_key(key, identifier=ID, origin=origin)
        # A BIP380 parser splits the origin from the key as it would for base58.
        bracketed, _, rest = encoded.partition("]")
        self.assertEqual((bracketed, rest[:5]), ("[" + origin, "xpub1"))
        for text in (encoded, encoded.upper()):
            self.assertEqual(decode_key(text), DecodedKey("xpub", key, origin=origin))
        with self.assertRaises(CodexError):
            decode_key(encoded.replace("48h", "49h"))
        # A 74-character key moves to the long checksum.
        public = encode_public_key(GENERATOR, identifier=ID, origin="d34db33f/84h/0h/0h")
        self.assertEqual(len(public), len("[d34db33f/84h/0h/0h]") + 76)
        self.assertEqual(decode_key(public).origin, "d34db33f/84h/0h/0h")
        for bad in ("d34db33", "D34DB33F", "d34db33f/", "d34db33f/0x", "d34db33f/2147483648h"):
            with self.assertRaises(InvalidKey):
                encode_public_key(GENERATOR, identifier=ID, origin=bad)
        with self.assertRaisesRegex(InvalidKey, "83"):
            encode_public_key(GENERATOR, identifier=ID, origin="d34db33f" + "/0h" * 25)

    def test_identifier_is_required(self):
        with self.assertRaises(TypeError):
            encode_public_key(GENERATOR)

    def test_wrong_external_checksum(self):
        key = encode_public_key(GENERATOR, identifier=ID)
        with self.assertRaises(CodexError):
            decode_key(key[:-1] + ("q" if key[-1] != "q" else "p"))

    def test_internal_crc_and_zero_child_padding(self):
        public = encode_public_key(GENERATOR, identifier=ID)
        data = [CHARSET.index(char) for char in public.split("1", 1)[1][:-13]]
        data[-1] ^= 1
        with self.assertRaisesRegex(InvalidKey, "CRC mismatch"):
            decode_key(bech32_encode("pk", data, _CODEX32))

        extended = encode_extended_key(extended_from_base58(XPUB), identifier=ID)
        data = [CHARSET.index(char) for char in extended.split("1", 1)[1][:-15]]
        data[6 + 2] ^= 0b01000  # First reserved bit in the child-number field.
        with self.assertRaisesRegex(InvalidKey, "padding"):
            decode_key(bech32_encode("xpub", data, _CODEX32_LONG))


if __name__ == "__main__":
    unittest.main()
