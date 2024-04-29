import hashlib
import sys
from verystable import core


def recoveryauth_phrase_to_key(phrase: str) -> core.key.ECKey:
    """
    The intent of the recovery authorization key is to prevent passive attackers from
    fee-griefing recovery transactions, so it doesn't need to be as secure as most keys.

    Use key derivation to generate a privkey based on a memorable phrase that can be
    trivially written down offline and used in case of need for recovery.
    """
    seed = hashlib.pbkdf2_hmac(
        "sha256", phrase.encode(), salt=b"OP_VAULT", iterations=3_000_000
    )
    (key := core.key.ECKey()).set(seed, compressed=True)
    return key


def txid_to_int(txid: str) -> int:
    return int.from_bytes(bytes.fromhex(txid), byteorder="big")


def btc_to_sats(btc) -> int:
    return int(btc * core.messages.COIN)


def _sigint_handler(*args, **kwargs):
    sys.exit(0)


def print_activity(*lines) -> None:
    oth = "\n     ".join(str(i) for i in lines[1:])
    print(f" {lines[0]}\n    {oth}\n")
