from dataclasses import dataclass, field
from VaultSpec import VaultSpec
from VaultsState import VaultsState
from verystable.rpc import BitcoinRPC

from WalletMetadata import WalletMetadata


@dataclass
class ChainMonitor:
    """
    Fetches data from a bitcoin RPC to build the state of the vault.
    """

    wallet_metadata: "WalletMetadata"
    rpc: BitcoinRPC
    addr_to_vault_spec: dict[str, VaultSpec] = field(default_factory=dict)
    last_height_scanned: int = 0
    raw_history: list[tuple[int, dict]] = field(default_factory=list)
    latest_state: VaultsState | None = None

    def __post_init__(self):
        DEFAULT_GAP_LIMIT = 200
        for i in range(DEFAULT_GAP_LIMIT):
            spec = self.wallet_metadata.config.get_spec_for_vault_num(i)
            self.addr_to_vault_spec[spec.address] = spec

    def refresh_raw_history(self) -> None:
        MAX_REORG_DEPTH = 200
        start_height = max(
            0,
            max(
                self.wallet_metadata.config.birthday_height,
                self.last_height_scanned,
            )
            - MAX_REORG_DEPTH,
        )

        # All vault + trigger output addresses, including attempted thefts.
        addrs: set[str] = set(self.addr_to_vault_spec.keys())
        addrs.update(self.wallet_metadata.all_trigger_addresses())

        # TODO theoretically could miss early theft-trigger-recovers here if this is
        # None.
        if self.latest_state:
            # Pull in all vault UTXOs that we know of (as belt-and-suspenders).
            addrs.update({u.address for u in self.latest_state.vault_utxos.values()})
            addrs.update(
                {u.address for u in self.latest_state.theft_trigger_utxos.keys()}
            )

        # Evict history that we're going to refresh.
        new_history = [pair for pair in self.raw_history if pair[0] < start_height]
        new_history += wallet.get_relevant_blocks(self.rpc, addrs, start_height)
        self.raw_history = list(sorted(new_history))

    def rescan(self) -> VaultsState:
        self.refresh_raw_history()
        tip = self.rpc.getblock(self.rpc.getbestblockhash())
        s = VaultsState(
            tip["hash"],
            tip["height"],
            vault_config=self.wallet_metadata.config,
            authorized_triggers=list(self.wallet_metadata.triggers.values()),
            addr_to_vault_spec=self.addr_to_vault_spec,
        )

        # Replay blocks in ascending order, updating wallet state.
        for height, block in self.raw_history:
            for tx in block["tx"]:
                s.update_for_tx(height, block, tx)

            self.last_height_scanned = height

        self.latest_state = s
        return s
