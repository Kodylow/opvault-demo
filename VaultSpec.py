from dataclasses import dataclass
from functools import cached_property
from verystable.core.script import CScript
from verystable.core import script
import typing as t
from verystable import core


@dataclass
class VaultSpec:
    """Manages script constructions and parameters for a particular vaulted coin."""

    # Incrementing ID that determines trigger key paths.
    vault_num: int
    spend_delay: int
    trigger_pubkey: bytes
    recovery_pubkey: bytes
    recovery_spk: CScript
    recoveryauth_pubkey: bytes

    # Determines the behavior of the withdrawal process.
    leaf_update_script_body = (
        script.OP_CHECKSEQUENCEVERIFY,
        script.OP_DROP,
        script.OP_CHECKTEMPLATEVERIFY,
    )  # yapf: disable

    def __post_init__(self):
        assert len(self.trigger_pubkey) == 32
        assert len(self.recovery_pubkey) == 32
        assert len(self.recoveryauth_pubkey) == 32

        recov_hash = core.key.TaggedHash(
            "VaultRecoverySPK", core.messages.ser_string(self.recovery_spk)
        )

        self.recovery_script = CScript(
            [
                self.recoveryauth_pubkey,
                script.OP_CHECKSIGVERIFY,
                recov_hash,
                script.OP_VAULT_RECOVER,
            ]
        )  # yapf: disable

        self.trigger_script = CScript(
            [
                self.trigger_pubkey,
                script.OP_CHECKSIGVERIFY,
                self.spend_delay,
                2,
                CScript(self.leaf_update_script_body),
                script.OP_VAULT,
            ]
        )  # yapf: disable

        self.taproot_info = script.taproot_construct(
            self.recovery_pubkey,
            scripts=[
                ("recover", self.recovery_script),
                ("trigger", self.trigger_script),
            ],
        )
        self.output_pubkey = self.taproot_info.output_pubkey
        self.scriptPubKey = self.taproot_info.scriptPubKey
        self.address = core.address.output_key_to_p2tr(self.output_pubkey)

    @cached_property
    def recovery_address(self) -> str:
        # TODO: this assumes recovery is a p2tr - not always true!
        return core.address.output_key_to_p2tr(self.recovery_pubkey)


def _are_all_vaultspecs(lst: t.Any) -> t.TypeGuard[list[VaultSpec]]:
    return all(isinstance(s, VaultSpec) for s in lst)
