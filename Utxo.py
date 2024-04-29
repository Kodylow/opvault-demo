from dataclasses import dataclass
from functools import cached_property
from utils import txid_to_int
from verystable.wallet import Outpoint
from verystable.core.script import CScript
from verystable.core.messages import COutPoint, CTxIn, CTxOut
import verystable.core as core


@dataclass(frozen=True)
class Utxo:
    outpoint: Outpoint
    address: str
    value_sats: int
    height: int

    @cached_property
    def scriptPubKey(self) -> CScript:
        return core.address.address_to_scriptpubkey(self.address)

    @cached_property
    def coutpoint(self) -> COutPoint:
        return COutPoint(txid_to_int(self.outpoint.txid), self.outpoint.n)

    @cached_property
    def output(self) -> CTxOut:
        return CTxOut(nValue=self.value_sats, scriptPubKey=self.scriptPubKey)

    @cached_property
    def as_txin(self) -> CTxIn:
        return CTxIn(self.coutpoint)

    @property
    def outpoint_str(self) -> str:
        return str(self.outpoint)

    def __hash__(self) -> int:
        return hash(str(self.outpoint))
