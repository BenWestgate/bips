"""Interoperability checks using BIP32's published extended-key vectors."""

import unittest

from codex32 import CodexError
from codex32.bech32 import CHARSET, bech32_encode
from codex32.checksums import _CODEX32, _CODEX32_LONG

from reference import (
    ExtendedKey,
    InvalidKey,
    decode_key,
    encode_extended_key,
    encode_private_key,
    encode_public_key,
    encode_xonly_key,
    extended_from_base58,
    extended_to_base58,
    wif_from_base58,
    wif_to_base58,
)

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
GENERATOR = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
UNCOMPRESSED = bytes.fromhex(
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)


class ReferenceTests(unittest.TestCase):
    def test_public_key_shapes_and_validation(self):
        compressed = encode_public_key(GENERATOR)
        uncompressed = encode_public_key(UNCOMPRESSED)
        xonly = encode_xonly_key(GENERATOR[1:])
        self.assertEqual((len(compressed), len(uncompressed), len(xonly)), (74, 128, 74))
        self.assertEqual(decode_key(compressed).key, GENERATOR)
        self.assertEqual(decode_key(uncompressed).key, UNCOMPRESSED)
        self.assertEqual(decode_key(xonly).key, GENERATOR[1:])
        with self.assertRaises(InvalidKey):
            encode_public_key(b"\x02" + b"\xff" * 32)
        with self.assertRaises(InvalidKey):
            encode_xonly_key(b"\xff" * 32)

    def test_private_key_wif_round_trip(self):
        for network in ("main", "test"):
            for compressed in (False, True):
                scalar = (1).to_bytes(32, "big")
                wif = wif_to_base58(scalar, network=network, compressed=compressed)
                self.assertEqual(wif_from_base58(wif), (scalar, network, compressed))
                encoded = encode_private_key(scalar, network=network, compressed=compressed)
                decoded = decode_key(encoded)
                self.assertEqual(
                    (decoded.key, decoded.network, decoded.compressed), (scalar, network, compressed)
                )
                self.assertEqual(len(encoded), 74)
        with self.assertRaises(InvalidKey):
            encode_private_key(b"\x00" * 32, network="main", compressed=True)

    def test_extended_key_round_trip(self):
        for serialized in (XPUB_MASTER, XPRV_MASTER, XPUB, XPRV):
            key = extended_from_base58(serialized)
            self.assertEqual(key.depth, 0 if serialized in (XPUB_MASTER, XPRV_MASTER) else 1)
            self.assertEqual(key.child_number, 0)
            self.assertEqual(extended_to_base58(key), serialized)
            encoded = encode_extended_key(key)
            self.assertEqual(len(encoded), 143)
            self.assertEqual(decode_key(encoded).key, key)

    def test_hardened_child_and_padding(self):
        key = extended_from_base58(XPRV)
        hardened = ExtendedKey(
            key.kind, key.depth, key.parent_fingerprint, 0x80000001, key.chain_code, key.key
        )
        encoded = encode_extended_key(hardened)
        self.assertEqual(decode_key(encoded).key, hardened)
        self.assertEqual(encoded[encoded.index("1") + 8], "s")
        with self.assertRaises(InvalidKey):
            encode_extended_key(
                ExtendedKey(key.kind, 32, key.parent_fingerprint, key.child_number, key.chain_code, key.key)
            )

    def test_wrong_external_checksum(self):
        key = encode_public_key(GENERATOR)
        with self.assertRaises(CodexError):
            decode_key(key[:-1] + ("q" if key[-1] != "q" else "p"))

    def test_internal_crc_and_zero_child_padding(self):
        public = encode_public_key(GENERATOR)
        data = [CHARSET.index(char) for char in public.split("1", 1)[1][:-13]]
        data[-1] ^= 1
        with self.assertRaisesRegex(InvalidKey, "CRC mismatch"):
            decode_key(bech32_encode("pk", data, _CODEX32))

        extended = encode_extended_key(extended_from_base58(XPUB))
        data = [CHARSET.index(char) for char in extended.split("1", 1)[1][:-15]]
        data[6 + 1] ^= 0b01000  # First reserved bit in the child-number field.
        with self.assertRaisesRegex(InvalidKey, "padding"):
            decode_key(bech32_encode("xpub", data, _CODEX32_LONG))


if __name__ == "__main__":
    unittest.main()
