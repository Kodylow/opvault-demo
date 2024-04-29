from pathlib import Path
import sys
from ChainMonitor import ChainMonitor
from PaymentDestination import PaymentDestination
from RecoverySpec import RecoverySpec
from TriggerSpec import TriggerSpec
from VaultConfig import VaultConfig
from VaultSpec import _are_all_vaultspecs
from VaultUtxo import VaultUtxo
from VaultsState import VaultsState
from WalletMetadata import WalletMetadata
from utils import txid_to_int
from verystable.wallet import SingleAddressWallet, Outpoint
import typing as t
from verystable.script import CTransaction, TaprootInfo, cscript_bytes_to_int
from verystable.core import script
from verystable.core.messages import CTxOut
from verystable.core.script import CScript
from verystable import core, wallet
from verystable.core.messages import COutPoint, CTxOut, CTxIn
from verystable.rpc import BitcoinRPC
from config import BITCOIN_RPC_URL, FEE_VALUE_SATS


def get_recovery_tx(
    config: VaultConfig,
    fees: SingleAddressWallet,
    utxos: list[VaultUtxo],
    recoveryauth_signer: t.Callable[[bytes], bytes],
) -> CTransaction:
    total_sats = sum(u.value_sats for u in utxos)
    recov_spk = config.recov_taproot_info.scriptPubKey
    fee_utxo = fees.get_utxo()
    fee_change = fee_utxo.value_sats - FEE_VALUE_SATS
    assert fee_change > 0

    tx = CTransaction()
    tx.nVersion = 2
    tx.vin = [u.as_txin for u in utxos] + [fee_utxo.as_txin]
    tx.vout = [
        CTxOut(nValue=total_sats, scriptPubKey=recov_spk),
        CTxOut(nValue=fee_change, scriptPubKey=fees.fee_spk),
    ]
    recov_vout_idx = 0

    spent_outputs = [u.output for u in utxos] + [fee_utxo.output]

    # Authorize each input recovery with a schnorr signature.
    for i, utxo in enumerate(utxos):
        witness = core.messages.CTxInWitness()
        tx.wit.vtxinwit += [witness]

        tr_info: TaprootInfo = utxo.get_taproot_info()
        recover_script: CScript = tr_info.leaves["recover"].script

        sigmsg = script.TaprootSignatureHash(
            tx,
            spent_outputs,
            input_index=i,
            hash_type=0,
            scriptpath=True,
            script=recover_script,
        )

        witness.scriptWitness.stack = [
            script.bn2vch(recov_vout_idx),
            recoveryauth_signer(sigmsg),
            recover_script,
            tr_info.controlblock_for_script_spend("recover"),
        ]

    # Sign for the fee input
    fee_witness = core.messages.CTxInWitness()
    tx.wit.vtxinwit += [fee_witness]

    sigmsg = script.TaprootSignatureHash(
        tx, spent_outputs, input_index=len(utxos), hash_type=0
    )

    fee_witness.scriptWitness.stack = [fees.sign_msg(sigmsg)]
    return RecoverySpec(
        tx,
        spent_vault_outpoints=[u.outpoint for u in utxos],
        spent_fee_outpoints=[fee_utxo.outpoint],
    )


def start_withdrawal(
    config: VaultConfig,
    fees: wallet.SingleAddressWallet,
    utxos: list[VaultUtxo],
    dest: PaymentDestination,
    trigger_xpriv_signer: t.Callable[[bytes, int], bytes],
) -> TriggerSpec:
    """
    Return TriggerSpec necessary to trigger a withdrawal to a single destination.

    Any remaining vault balance will be revaulted back into the vault.

    TODO generalize to multiple destinations
    TODO generalize to multiple incompatible vaults (i.e. many trigger outs)
    """
    fee_utxo = fees.get_utxo()
    fee_change = fee_utxo.value_sats - FEE_VALUE_SATS
    assert fee_change > 0

    # Choose the UTXO that we'll be revaulting from; this is the largest value, and
    # `utxos` should have been chosen so that the destination amount is covered by only
    # having one additional vault UTXO.
    revault_utxo = max(utxos, key=lambda u: u.value_sats)

    # Verify that coin selection was done properly.
    required_trigger_value = dest.value_sats + FEE_VALUE_SATS
    tmp_utxos = list(utxos)
    while required_trigger_value >= 0 and tmp_utxos:
        u = tmp_utxos.pop()
        required_trigger_value -= u.value_sats

    if required_trigger_value > 0 or len(tmp_utxos) not in [1, 0]:
        raise RuntimeError("coin selection is wrong! need at most one excess coin")

    needs_revault = required_trigger_value < 0
    total_vault_value = sum(u.value_sats for u in utxos)

    # Revault the remaining balance of the vault, less some fees that will be consumed
    # by the final withdrawal txn.
    #
    # This means that the input to the final withdrawal txn (ultimately provided by
    # the trigger output) will be slightly more than the destination payout.
    revault_value = total_vault_value - dest.value_sats - FEE_VALUE_SATS
    trigger_value = total_vault_value - revault_value
    assert revault_value > 0
    assert trigger_value > 0

    # Compute the final withdrawal transaction so that we may CTV hash it, and then
    # embed that hash in the trigger script. This is what "locks" the destination of
    # the withdrawal into place.

    final_tx = CTransaction()
    final_tx.nVersion = 2
    final_tx.vin = [CTxIn(nSequence=config.spend_delay)]
    final_tx.vout = [dest.as_vout()]
    ctv_hash = final_tx.get_standard_template_hash(0)

    specs = [u.vault_spec for u in utxos]
    assert _are_all_vaultspecs(specs)
    trigger_spec = TriggerSpec(
        specs,
        ctv_hash,
        trigger_value,
        revault_value,
        spent_vault_outpoints=[u.outpoint for u in utxos],
        spent_fee_outpoints=[fee_utxo.outpoint],
        destination=dest,
    )

    trigger_out = CTxOut(nValue=trigger_value, scriptPubKey=trigger_spec.scriptPubKey)
    fee_change_out = CTxOut(nValue=fee_change, scriptPubKey=fees.fee_spk)
    revault_out = None
    revault_idx = None

    tx = CTransaction()
    tx.nVersion = 2
    tx.vin = [u.as_txin for u in utxos] + [fee_utxo.as_txin]
    tx.vout = [trigger_out, fee_change_out]
    trigger_vout_idx = 0

    if needs_revault:
        revault_out = CTxOut(
            nValue=revault_value, scriptPubKey=revault_utxo.scriptPubKey
        )
        tx.vout.append(revault_out)
        revault_idx = len(tx.vout) - 1

    trigger_spec.trigger_vout_idx = trigger_vout_idx
    trigger_spec.revault_vout_idx = revault_idx

    spent_outputs = [u.output for u in utxos] + [fee_utxo.output]
    for i, utxo in enumerate(utxos):
        assert (spec := utxo.vault_spec)
        assert (trigger_script := spec.trigger_script)

        msg = script.TaprootSignatureHash(
            tx,
            spent_outputs,
            input_index=i,
            hash_type=0,
            scriptpath=True,
            script=trigger_script,
        )
        sig: bytes = trigger_xpriv_signer(msg, spec.vault_num)
        revault_value_script = script.bn2vch(0)
        revault_idx_script = script.bn2vch(-1)

        if needs_revault and utxo == revault_utxo:
            revault_value_script = script.bn2vch(revault_value)
            revault_idx_script = script.bn2vch(revault_idx)

        wit = core.messages.CTxInWitness()
        tx.wit.vtxinwit += [wit]
        wit.scriptWitness.stack = [
            revault_value_script,
            revault_idx_script,
            CScript([trigger_vout_idx]) if trigger_vout_idx != 0 else b"",
            ctv_hash,
            sig,
            trigger_script,
            utxo.get_taproot_info().controlblock_for_script_spend("trigger"),
        ]

    # Sign for the fee input
    fee_witness = core.messages.CTxInWitness()
    tx.wit.vtxinwit += [fee_witness]
    sigmsg = script.TaprootSignatureHash(
        tx, spent_outputs, input_index=len(utxos), hash_type=0
    )
    fee_witness.scriptWitness.stack = [fees.sign_msg(sigmsg)]

    final_tx.vin[0].prevout = COutPoint(txid_to_int(tx.rehash()), trigger_vout_idx)
    final_tx.wit.vtxinwit += [core.messages.CTxInWitness()]
    final_tx.wit.vtxinwit[0].scriptWitness.stack = [
        trigger_spec.taproot_info.leaves["withdraw"].script,
        trigger_spec.taproot_info.controlblock_for_script_spend("withdraw"),
    ]
    assert final_tx.get_standard_template_hash(0) == ctv_hash

    trigger_spec.trigger_tx = tx
    trigger_spec.withdrawal_tx = final_tx
    return trigger_spec


def get_recoverable_utxo_from_theft_tx(
    theft_trigger_tx: CTransaction, at_risk_utxo: VaultUtxo
) -> VaultUtxo:
    """
    Given an unrecognized trigger transaction (presumed to be a theft), create a
    VaultUtxo that can be used to spend it to the recovery path.
    """
    coutp = at_risk_utxo.coutpoint
    [vin_num] = [
        i
        for i, vin in enumerate(theft_trigger_tx.vin)
        if vin.prevout.hash == coutp.hash and vin.prevout.n == coutp.n
    ]

    # Deconstruct the witness stack of the thief's trigger tx to recover parameters
    # (e.g. CTV hash) which we don't yet know, but will use to construct a recovery
    # script witness to spend this trigger with.

    wit = theft_trigger_tx.wit.vtxinwit[vin_num]
    stack = wit.scriptWitness.stack
    assert len(stack) == 7  # matches witstack format in start_withdrawal()
    revault_value_sats = cscript_bytes_to_int(stack[0])
    revault_idx = cscript_bytes_to_int(stack[1])
    trigger_vout_idx = cscript_bytes_to_int(stack[2])
    ctv_hash = stack[3]

    trigger_vout = theft_trigger_tx.vout[trigger_vout_idx]
    trigger_value_sats = trigger_vout.nValue

    assert at_risk_utxo.vault_spec

    adversary_spec = TriggerSpec(
        [at_risk_utxo.vault_spec],
        ctv_hash,
        trigger_value_sats,
        revault_value_sats,
        trigger_vout_idx=trigger_vout_idx,
        revault_vout_idx=revault_idx,
        trigger_tx=theft_trigger_tx,
    )

    return VaultUtxo(
        Outpoint(theft_trigger_tx.rehash(), trigger_vout_idx),
        address=adversary_spec.address,
        value_sats=trigger_value_sats,
        height=0,
        config=at_risk_utxo.config,
        trigger_spec=adversary_spec,
    )


def load(
    cfg_file: Path | str,
) -> tuple[WalletMetadata, BitcoinRPC, SingleAddressWallet, ChainMonitor, VaultsState]:
    """
    Load configuration from the fileystem and initialize wallet state.
    """
    if not isinstance(cfg_file, Path):
        cfg_file = Path(cfg_file)
    if not cfg_file.exists():
        print("call ./createconfig.py")
        sys.exit(1)

    wallet_metadata = WalletMetadata.load(cfg_file)
    rpc = BitcoinRPC(
        net_name=wallet_metadata.config.network, service_url=BITCOIN_RPC_URL
    )
    fees = SingleAddressWallet(
        rpc,
        locked_utxos=wallet_metadata.get_locked_fee_outpoints(),
        seed=wallet_metadata.fee_wallet_seed,
    )
    fees.rescan()

    monitor = ChainMonitor(wallet_metadata, rpc)
    state = monitor.rescan()
    wallet_metadata.address_cursor = state.get_next_deposit_num()

    return wallet_metadata, rpc, fees, monitor, state
