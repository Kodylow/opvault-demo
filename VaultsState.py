from dataclasses import dataclass, field
from TriggerSpec import TriggerSpec
from utils import btc_to_sats
from verystable.wallet import Outpoint
from verystable.script import CTransaction
from logger_config import log

from VaultConfig import VaultConfig
from VaultSpec import VaultSpec
from VaultUtxo import VaultUtxo


@dataclass
class VaultsState:
    """
    A snapshot of the current state of the vault at a particular block (tip).

    A "pure" class in the sense tha it doesn't make RPC calls or manipulate
    any state outside of what is maintained in this class - it just interpets
    a history of blocks to build a snapshot of the vault.
    """

    blockhash: str
    height: int
    vault_config: VaultConfig
    authorized_triggers: list[TriggerSpec]
    addr_to_vault_spec: dict[str, VaultSpec]

    vault_utxos: dict[Outpoint, VaultUtxo] = field(default_factory=dict)
    trigger_utxos: dict[Outpoint, VaultUtxo] = field(default_factory=dict)
    theft_trigger_utxos: dict[VaultUtxo, CTransaction] = field(default_factory=dict)
    recovered_vaults: dict[VaultUtxo, str] = field(default_factory=dict)
    txid_to_completed_trigger: dict[str, VaultUtxo] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.vault_outpoint_to_good_trigger = {}
        self.txid_to_trigger_spec = {}

        for trig in self.authorized_triggers:
            assert trig.spent_vault_outpoints
            for outpoint in trig.spent_vault_outpoints:
                assert outpoint
                self.vault_outpoint_to_good_trigger[outpoint] = trig

            self.txid_to_trigger_spec[trig.id] = trig

        log.info(
            "vault outpoints to good triggers: %s",
            {k: v.id for k, v in self.vault_outpoint_to_good_trigger.items()},
        )

    def update_for_tx(self, height: int, block: dict, tx: dict) -> None:
        txid = tx["txid"]
        trig_spec = self.txid_to_trigger_spec.get(txid)
        ctx = CTransaction.fromhex(tx["hex"])

        def get_spk(vout: dict) -> str | None:
            return vout.get("scriptPubKey", {}).get("address")

        # Examine outputs
        for vout in tx["vout"]:
            if addr := get_spk(vout):
                op = Outpoint(txid, vout["n"])

                # Detect deposits
                if spec := self.addr_to_vault_spec.get(addr):
                    self.vault_utxos[op] = (
                        utxo := VaultUtxo(
                            op,
                            addr,
                            btc_to_sats(vout["value"]),
                            height,
                            config=self.vault_config,
                            vault_spec=spec,
                        )
                    )
                    log.info("found deposit to %s: %s", addr, utxo)

                elif trig_spec and addr == trig_spec.address:
                    # Note: this does not cover *unknown* triggers, i.e. thefts. That
                    # is covered below.
                    trig_utxo = VaultUtxo(
                        op,
                        addr,
                        btc_to_sats(vout["value"]),
                        height,
                        config=self.vault_config,
                        trigger_spec=trig_spec,
                    )
                    self.trigger_utxos[op] = trig_utxo
                    log.info("found trigger confirmation: %s", trig_utxo)

        def find_vout_with_address(findaddr: str) -> dict | None:
            for v in tx["vout"]:
                if findaddr == get_spk(v):
                    return v
            return None

        op_to_theft_trigger = {u.outpoint: u for u in self.theft_trigger_utxos.keys()}

        # Detect vault movements
        for vin in filter(lambda vin: "txid" in vin, tx["vin"]):
            spent_txid = vin["txid"]
            spent_op = Outpoint(spent_txid, vin.get("vout"))

            if spent := self.vault_utxos.get(spent_op):
                # Vault spent to recovery
                if find_vout_with_address(self.vault_config.recov_address):
                    self.mark_vault_recovered(spent_op, txid)

                # Vault spent to trigger
                elif trigger := self.vault_outpoint_to_good_trigger.get(spent_op):
                    assert trigger.trigger_tx
                    if txid != trigger.trigger_tx.rehash():
                        log.warning(
                            "got bad trigger! expected\n%s",
                            trigger.trigger_tx.pformat(),
                        )
                        log.warning("got bad trigger! got\n%s", ctx.pformat())
                        self.mark_vault_theft(spent, ctx)
                    else:
                        self.mark_vault_good_trigger(spent, trigger, height)

                # Vault spent to ??? -- theft!
                else:
                    self.mark_vault_theft(spent, ctx)

            elif spent_trigger := self.trigger_utxos.get(spent_op):
                assert spent_trigger.trigger_spec
                assert (trigspec := spent_trigger.trigger_spec).withdrawal_tx

                # Trigger spent to recovery path
                if find_vout_with_address(trigspec.recovery_address):
                    self.mark_trigger_recovered(spent_trigger, txid)

                # Trigger spent to final withdrawal txn
                elif txid == trigspec.withdrawal_tx.rehash():
                    self.mark_trigger_completed(spent_trigger, txid)
                else:
                    log.warning("!!! unrecognized spend of trigger - shouldn't happen")

            elif spent_theft_trigger := op_to_theft_trigger.get(spent_op):
                if find_vout_with_address(spent_theft_trigger.spec.recovery_address):
                    # An attemped theft was thwarted successfully
                    log.warning("at risk trigger was succesfully recovered!")
                    self.recovered_vaults[spent_theft_trigger] = txid
                    self.theft_trigger_utxos.pop(spent_theft_trigger)
                else:
                    log.warning(
                        "at risk trigger was stolen, funds lost: game over, man ;("
                    )

    def mark_vault_recovered(self, op: Outpoint, txid: str) -> None:
        spent = self.vault_utxos.pop(op)
        log.info("found recovery of untriggered vault %s", spent)
        self.recovered_vaults[spent] = txid

    def mark_vault_good_trigger(
        self, spent: VaultUtxo, trigger: TriggerSpec, height: int
    ) -> None:
        log.info("found good trigger spend of vault %s", spent)
        self.vault_utxos.pop(spent.outpoint)

    def mark_vault_theft(self, spent: VaultUtxo, tx: CTransaction) -> None:
        log.warning("found unrecognized spend (attempted theft?) of vault %s", spent)
        self.vault_utxos.pop(spent.outpoint)
        self.theft_trigger_utxos[get_recoverable_utxo_from_theft_tx(tx, spent)] = tx

    def mark_trigger_recovered(self, spent_trigger: VaultUtxo, txid: str) -> None:
        log.info("found recovery of triggered vault %s", spent_trigger)
        spent = self.trigger_utxos.pop(spent_trigger.outpoint)
        self.recovered_vaults[spent] = txid

    def mark_trigger_completed(self, spent_trigger: VaultUtxo, txid: str) -> None:
        log.info("found completed trigger %s", spent_trigger)
        self.txid_to_completed_trigger[txid] = self.trigger_utxos.pop(
            spent_trigger.outpoint
        )

    def get_next_deposit_num(self) -> int:
        """Get the next unused vault number."""
        utxos = [
            *self.vault_utxos.values(),
            *self.recovered_vaults.keys(),
            *self.trigger_utxos.values(),
            *self.txid_to_completed_trigger.values(),
        ]
        nums = {u.spec.vault_num for u in utxos}
        return 0 if not nums else max(nums) + 1
