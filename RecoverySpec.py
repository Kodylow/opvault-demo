from dataclasses import dataclass, field
from verystable.script import CTransaction
from verystable.wallet import Outpoint


@dataclass
class RecoverySpec:
    tx: CTransaction
    spent_vault_outpoints: list[Outpoint] = field(default_factory=list)
    spent_fee_outpoints: list[Outpoint] = field(default_factory=list)
