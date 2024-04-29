from dataclasses import dataclass
from verystable.core.messages import CTxOut
import verystable.core as core


@dataclass(frozen=True)
class PaymentDestination:
    addr: str
    value_sats: int

    def as_vout(self) -> CTxOut:
        return CTxOut(
            nValue=self.value_sats,
            scriptPubKey=core.address.address_to_scriptpubkey(self.addr),
        )
