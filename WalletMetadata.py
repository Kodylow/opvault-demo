from dataclasses import dataclass, field
from pathlib import Path
from RecoverySpec import RecoverySpec
from TriggerSpec import TriggerSpec
from verystable.serialization import VSJson
from verystable.wallet import Outpoint

from VaultConfig import VaultConfig

TriggerId = str


@dataclass
class WalletMetadata:
    config: VaultConfig
    triggers: dict[TriggerId, TriggerSpec] = field(default_factory=dict)
    recoveries: list[RecoverySpec] = field(default_factory=list)
    address_cursor: int = 0
    filepath: Path | None = None

    # In practice, you wouldn't persist this here but for the purposes of a demo
    # it's fine.
    fee_wallet_seed: bytes = b"\x01" * 32

    _json_exclude = ("filepath",)

    def save(self):
        assert self.filepath
        self.filepath.write_text(VSJson.dumps(self, indent=2))
        log.info("saved wallet state to %s", self.filepath)

    @classmethod
    def load(cls, filepath: Path) -> "WalletMetadata":
        obj = VSJson.loads(filepath.read_text())
        obj.filepath = filepath
        return obj

    def all_trigger_addresses(self) -> list[str]:
        """Get all trigger addresses, including attempted theft triggers."""
        return [spec.address for spec in self.triggers.values()]

    def get_vault_utxos_spent_by_triggers(self) -> set[Outpoint]:
        return {
            op for trig in self.triggers.values() for op in trig.spent_vault_outpoints
        }

    def get_locked_fee_outpoints(self) -> set[Outpoint]:
        specs: list[TriggerSpec | RecoverySpec] = self.recoveries + list(
            self.triggers.values()
        )
        return {op for spec in specs for op in spec.spent_fee_outpoints}

    def get_next_deposit_addr(self) -> str:
        next_spec = self.config.get_spec_for_vault_num(self.address_cursor)
        return next_spec.address
