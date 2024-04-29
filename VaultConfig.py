from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from verystable.script import TaprootInfo
from verystable.core import script
import verystable.core as core
from bip32 import BIP32
from VaultSpec import VaultSpec


@dataclass
class VaultConfig:
    """
    Static, non-secret configuration that describes the compatible parameters for a
    set of vault coins.
    """

    spend_delay: int
    recovery_pubkey: bytes
    recoveryauth_pubkey: bytes
    trigger_xpub: str
    network: str = "signet"

    # Determines where trigger keys will be generated.
    trigger_xpub_path_prefix: str = "m/0"

    # The blockheight that this wallet was created at.
    # Note: we won't scan for any activity beneath this height, so be careful when
    # specifying it.
    birthday_height: int = 0

    secrets_filepath: Path = Path("./secrets.json")

    def __post_init__(self) -> None:
        assert len(self.recovery_pubkey) == 32
        assert len(self.recoveryauth_pubkey) == 32
        self.trigger_xpub_path_prefix = self.trigger_xpub_path_prefix.rstrip("/")

    @property
    def id(self) -> str:
        """A string that uniquely IDs this vault configuration."""
        return (
            f"{self.network}-{self.spend_delay}-{self.recovery_pubkey.hex()}-"
            f"{self.recoveryauth_pubkey.hex()}-{self.trigger_xpub}"
        )

    @cached_property
    def recov_taproot_info(self) -> TaprootInfo:
        return script.taproot_construct(self.recovery_pubkey)

    @cached_property
    def recov_address(self) -> str:
        return core.address.output_key_to_p2tr(self.recov_taproot_info.output_pubkey)

    def get_trigger_xonly_pubkey(self, num: int) -> bytes:
        b32 = BIP32.from_xpub(self.trigger_xpub)
        got = b32.get_pubkey_from_path(f"{self.trigger_xpub_path_prefix}/{num}")
        assert len(got) == 33
        return got[1:]

    def get_spec_for_vault_num(self, num: int) -> "VaultSpec":
        return VaultSpec(
            vault_num=num,
            spend_delay=self.spend_delay,
            trigger_pubkey=self.get_trigger_xonly_pubkey(num),
            recovery_pubkey=self.recov_taproot_info.output_pubkey,
            recovery_spk=self.recov_taproot_info.scriptPubKey,
            recoveryauth_pubkey=self.recoveryauth_pubkey,
        )
