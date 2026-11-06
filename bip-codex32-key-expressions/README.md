# Key-expression codec experiment

`reference.py` independently implements the draft key-material bit layouts and
round trips them to BIP 32 Base58Check and WIF. It imports the generic codex32
parser, checksum encoder, and share recovery from
[`python-codex32`](https://github.com/BenWestgate/python-codex32/tree/reviewability-v1).
`requirements.txt` pins the validated commit
`9b99862eb14d15d86977cec202a6d39abcac2a88`, since the branch moves. The checksum
objects imported from `codex32.checksums` are private APIs, so this is an
experimental dependency until that library exposes a public generic encoder.

Run from this directory with Python 3.12 or 3.13:

```sh
python -m pip install -r requirements.txt
python -m unittest -v test_reference.py
```

The module implements `pk`, `xo`, `wf`, `xpub`, `xprv`, `tpub`, and `tprv`.
`decode_key` rejects ordinary shares as key material; `recover_key` first uses
BIP 93 recovery with exactly the declared threshold and then validates the
recovered key. A key origin, when given, is part of the HRP; trailing
derivation paths stay outside the string. There is no Bitcoin Core wallet
integration here.

The format is still a draft, and the test suite is an initial set of round
trips and negative cases rather than the complete normative vector set.
