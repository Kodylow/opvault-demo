from dataclasses import dataclass, field
import datetime
from functools import cached_property
from PaymentDestination import PaymentDestination
from verystable.wallet import Outpoint
from verystable.script import CTransaction
from verystable.core.script import CScript
from verystable.core import script
from VaultSpec import VaultSpec


@dataclass
class TriggerSpec:
    """Manages script constructions and parameters for a triggered vault coin."""

    vault_specs: list[VaultSpec]
    destination_ctv_hash: bytes
    trigger_value_sats: int
    revault_value_sats: int
    created_at: datetime.datetime = field(default_factory=datetime.datetime.utcnow)

    # The following are set after the trigger transaction is actually constructed.
    trigger_vout_idx: int = -1
    revault_vout_idx: int | None = None
    spent_vault_outpoints: list[Outpoint] = field(default_factory=list)
    spent_fee_outpoints: list[Outpoint] = field(default_factory=list)
    trigger_tx: CTransaction | None = None
    withdrawal_tx: CTransaction | None = None
    # Used only for logging.
    destination: PaymentDestination | None = None

    broadcast_trigger_at: datetime.datetime | None = None
    saw_trigger_confirmed_at: datetime.datetime | None = None
    saw_withdrawn_at: datetime.datetime | None = None

    def __post_init__(self):
        specs = self.vault_specs
        vault_spec = specs[0]

        def assert_specs_have_same(key):
            assert len(set(getattr(spec, key) for spec in specs)) == 1

        assert_specs_have_same("spend_delay")
        assert_specs_have_same("leaf_update_script_body")
        assert_specs_have_same("recovery_script")
        assert_specs_have_same("recovery_pubkey")

        self.withdrawal_script = CScript(
            [
                self.destination_ctv_hash,
                vault_spec.spend_delay,
                *vault_spec.leaf_update_script_body,
            ]
        )
        self.recovery_script = vault_spec.recovery_script

        self.taproot_info = script.taproot_construct(
            vault_spec.recovery_pubkey,
            scripts=[
                ("recover", self.recovery_script),
                ("withdraw", self.withdrawal_script),
            ],
        )
        self.scriptPubKey = self.taproot_info.scriptPubKey
        self.address = self.taproot_info.p2tr_address

    @property
    def id(self) -> str:
        """Return a unique ID for this trigger spec."""
        assert self.trigger_tx
        return self.trigger_tx.rehash()

    @property
    def vault_num(self) -> int:
        return self.vault_specs[0].vault_num

    @cached_property
    def spend_delay(self) -> int:
        return self.vault_specs[0].spend_delay

    @cached_property
    def recovery_address(self) -> str:
        return self.vault_specs[0].recovery_address
