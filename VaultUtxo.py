from dataclasses import dataclass
from TriggerSpec import TriggerSpec

from Utxo import Utxo
from VaultConfig import VaultConfig
from VaultSpec import VaultSpec


@dataclass(frozen=True)
class VaultUtxo(Utxo):
    config: VaultConfig

    vault_spec: VaultSpec | None = None
    trigger_spec: TriggerSpec | None = None

    def __post_init__(self):
        assert bool(self.trigger_spec) ^ bool(self.vault_spec)

    @property
    def spec(self) -> VaultSpec | TriggerSpec:
        assert (s := self.trigger_spec or self.vault_spec)
        return s

    def get_taproot_info(self):
        """Return the most relevant taproot info."""
        return self.spec.taproot_info

    def __str__(self) -> str:
        return (
            f"{str(self.outpoint)} ({self.value_sats} sats)\n    (addr={self.address})"
        )

    def __hash__(self) -> int:
        return hash(self.outpoint)
