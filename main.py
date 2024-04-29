#!/usr/bin/env python3
import os
import sys
import random
import datetime
import signal
import json
import hashlib
import time
import typing as t
from functools import cached_property
from dataclasses import dataclass, field
from pathlib import Path, PosixPath
from ChainMonitor import ChainMonitor
from PaymentDestination import PaymentDestination
from TriggerSpec import TriggerSpec
from VaultConfig import VaultConfig
from VaultSpec import VaultSpec
from WalletMetadata import WalletMetadata
from utils import _sigint_handler, print_activity, recoveryauth_phrase_to_key
from wallet_actions import get_recovery_tx, load, start_withdrawal
from logger_config import log

from clii import App
from bip32 import BIP32
import verystable
from verystable import core
from verystable.rpc import JSONRPCError
from verystable.wallet import Outpoint
from verystable.serialization import VSJson
from rich import print

verystable.softforks.activate_bip345_vault()
verystable.softforks.activate_bip119_ctv()

# Wire up JSON serialization for the classes above.
VSJson.add_allowed_classes(
    Outpoint,
    WalletMetadata,
    VaultConfig,
    VaultSpec,
    TriggerSpec,
    PaymentDestination,
    Path,
    PosixPath,
)


cli = App()


@cli.main
@cli.cmd
def monitor():
    """
    Vault watchtower functionality. Leave this running!
    """
    config_path = Path("./config.json")
    wallet_metadata, rpc, fees, monitor, state = load(config_path)

    print(
        """


                 w e l c o m e
                                t o
                      y o u r
                                      ▀██    ▄
            ▄▄▄▄ ▄▄▄  ▄▄▄▄   ▄▄▄ ▄▄▄   ██  ▄██▄
             ▀█▄  █  ▀▀ ▄██   ██  ██   ██   ██
              ▀█▄█   ▄█▀ ██   ██  ██   ██   ██
               ▀█    ▀█▄▄▀█▀  ▀█▄▄▀█▄ ▄██▄  ▀█▄▀


"""
    )

    print_activity(
        f"[cyan bold]=>[/] next deposit address",
        wallet_metadata.get_next_deposit_addr(),
    )
    if state.vault_utxos:
        print(" [bold]Vaulted coins[/]\n")
        for u in state.vault_utxos.values():
            print(f"  - {u.address} ({u.value_sats} sats)")
            print(f"    outpoint: {str(u.outpoint)}")
        print()

    if state.trigger_utxos:
        print(" [bold]Pending triggers[/]\n")
        for trig in state.trigger_utxos.values():
            confs = state.height - trig.height + 1
            print(f"  - {trig.spec.address} ({confs} confs) -> {trig.spec.destination}")
        print()

    if state.recovered_vaults:
        print("[bold]Recovered vaults[/]\n")
        for u in state.recovered_vaults:
            print(f"  - {str(u)}")
        print()

    print(f"[green bold] $$[/] fee wallet address: {fees.fee_addr}")
    for u in fees.utxos[:3]:
        print(f"  - {u.value_sats}: {u.outpoint_str}")
    print()

    # Ensure any completed triggers have been marked completed.
    for trig_utxo in state.txid_to_completed_trigger.values():
        spec = wallet_metadata.triggers[trig_utxo.spec.id]
        now = datetime.datetime.utcnow()

        needs_save = False
        if not spec.saw_trigger_confirmed_at:
            spec.saw_trigger_confirmed_at = now
            needs_save = True
        if not spec.saw_withdrawn_at:
            spec.saw_withdrawn_at = now
            needs_save = True

        if needs_save:
            print_activity(
                f"[bold]✔ [/] found that withdrawal has completed", trig_utxo
            )
            # Save performed below

    wallet_metadata.save()
    trigger_txids_completed = set()

    signal.signal(signal.SIGINT, _sigint_handler)

    while True:
        new_state = monitor.rescan()
        # Reload wallet metadata file to pick up on new trigger jobs from `withdraw`.
        wallet_metadata = WalletMetadata.load(wallet_metadata.filepath)
        # TODO clean this up. If we don't set in lockstep with metadata refresh,
        # triggers will be unrecognized.
        monitor.wallet_metadata = wallet_metadata

        def new_values(key):
            newd = getattr(new_state, key)
            keydiff = set(newd.keys()) - set(getattr(state, key).keys())
            return {newd[k] for k in keydiff}

        # Submit trigger transactions for inflight withdrawals.
        for trig_spec in wallet_metadata.triggers.values():
            assert (tx := trig_spec.trigger_tx)

            if trig_spec.broadcast_trigger_at:
                # Trigger has already been broadcast.
                continue

            try:
                rpc.sendrawtransaction(tx.tohex())
            except JSONRPCError as e:
                # Already in blockchain.
                if e.code != -27:
                    raise
            else:
                print_activity(
                    "[bold]❏ [/] submitted trigger txn for",
                    trig_spec.destination,
                    f"(txid={tx.rehash()})",
                )
                trig_spec.broadcast_trigger_at = datetime.datetime.utcnow()
                wallet_metadata.save()

        # Submit final withdrawal transactions for matured triggers.
        for trig_utxo in new_state.trigger_utxos.values():
            confs = new_state.height - trig_utxo.height + 1
            left = (spec := trig_utxo.spec).spend_delay - confs
            is_mature = left <= 0
            finaltx = spec.withdrawal_tx
            txid = spec.trigger_tx.rehash()

            if not spec.saw_trigger_confirmed_at:
                wallet_metadata.triggers[txid].saw_trigger_confirmed_at = (
                    datetime.datetime.utcnow()
                )
                wallet_metadata.save()

            if is_mature and txid not in trigger_txids_completed:
                print_activity("[yellow]✅[/] trigger has matured", trig_utxo)
                print_activity(
                    "[bold]<-[/] broadcasting withdrawal txn", finaltx.rehash()
                )
                try:
                    rpc.sendrawtransaction(finaltx.tohex())
                except Exception:
                    log.exception("failed to broadcast withdrawal for %s", trig_utxo)
                    print_activity(
                        "[yellow bold]!![/] failed to broadcast withdrawal transaction",
                        "run the following to save the trigger:",
                        f"`./main.py recover --outpoint {str(trig_utxo.outpoint)}`",
                    )
                else:
                    trigger_txids_completed.add(txid)
            elif new_state.height != state.height:
                print_activity(
                    f"[bold]--[/] trigger has {confs} confs ({left} to go)",
                    f"(txid={txid})",
                    spec.destination,
                )

        # Mark completed withdrawals as such.
        for trig_utxo in (has_new := new_values("txid_to_completed_trigger")):
            spec = trig_utxo.spec
            print_activity("[blue]✅[/] withdrawal completed", spec.destination)
            wallet_metadata.triggers[spec.id].saw_withdrawn_at = (
                datetime.datetime.utcnow()
            )
            wallet_metadata.save()

        # Check for new vault deposits.
        for newv in (has_new := new_values("vault_utxos")):
            print_activity("[green]$$[/] saw new deposit", newv)
            wallet_metadata.address_cursor += 1

        if has_new:
            wallet_metadata.save()
            print_activity(
                "[bold]▢ [/] new deposit address",
                wallet_metadata.get_next_deposit_addr(),
            )

        # Alert on unrecognized spends.
        for theft_utxo, tx in state.theft_trigger_utxos.items():
            # TODO cooler alerting here
            print_activity(
                "[red bold]!![/] detected unrecognized spend!",
                "  you might be hacked! run `recover` now!",
                f"(bad txid={tx.rehash()})",
            )

        if new_state.recovered_vaults and not new_state.vault_utxos:
            print()
            print_activity(
                "[cyan bold]✔✔[/] vault configuration fully recovered",
                f"recovered to: [blue]{wallet_metadata.config.recov_address}[/]",
                "",
                "check your opsec, change your trigger key, and start over!",
            )
            print(" vaults recovered:")
            for recovered in new_state.recovered_vaults:
                print(f"  - {recovered}")
            print()

            sys.exit(0)

        state = new_state
        time.sleep(2)


@cli.cmd
def withdraw(to_addr: str, amount_sats: int):
    """Trigger the start of a withdrawal process from the vault."""
    _cli_start_withdrawal(to_addr, amount_sats)


@cli.cmd
def steal(to_addr: str, amount_sats: int):
    """Simulate a theft out of the vault."""
    _cli_start_withdrawal(to_addr, amount_sats, simulate_theft=True)


def _cli_start_withdrawal(to_addr, amount_sats, simulate_theft: bool = False):
    wallet_metadata, rpc, fees, monitor, state = load("./config.json")
    config = wallet_metadata.config
    dest = PaymentDestination(to_addr, amount_sats)

    # Use random coin selection to cover the amount.
    wallet_utxos = list(state.vault_utxos.values())

    if not simulate_theft:
        already_locked = wallet_metadata.get_vault_utxos_spent_by_triggers()
        # If we aren't thieving, exclude UTXOs that are already locked by other
        # pending triggers.
        wallet_utxos = [u for u in wallet_utxos if u.outpoint not in already_locked]

    utxos = []
    while amount_sats > 0:
        random.shuffle(wallet_utxos)
        try:
            utxos.append(utxo := wallet_utxos.pop())
        except IndexError:
            print()
            print_activity(
                "[red bold]!![/] not enough vault coins to cover the withdrawal "
                "amount - deposit to next addr ",
                wallet_metadata.get_next_deposit_addr(),
            )
            sys.exit(1)
        amount_sats -= utxo.value_sats

    def trigger_key_signer(msg: bytes, vault_num: int) -> bytes:
        """Obviously don't use this in production; replace with something better."""
        try:
            secdict = json.loads(config.secrets_filepath.read_text())[config.id]
            b32 = BIP32.from_xpriv(secdict["trigger_xpriv"])
        except Exception:
            log.exception("unable to find secrets for vault config %s", config.id)
            sys.exit(1)

        privkey = b32.get_privkey_from_path(
            f"{config.trigger_xpub_path_prefix}/{vault_num}"
        )
        sig = core.key.sign_schnorr(privkey, msg)
        return sig

    spec = start_withdrawal(
        wallet_metadata.config, fees, utxos, dest, trigger_key_signer
    )
    assert spec.id not in wallet_metadata.triggers
    assert spec.trigger_tx

    if not simulate_theft:
        # Add the trigger spec as recognized and queue it for processing
        # by the watchtower.
        wallet_metadata.triggers[spec.id] = spec
        wallet_metadata.save()
        print("started withdrawal process, `monitor` should pick it up")
    else:
        rpc.sendrawtransaction(spec.trigger_tx.tohex())
        print("started theft, `monitor` should detect it after block is mined")


@cli.cmd
def recover(outpoint: str = ""):
    wallet_metadata, rpc, fees, monitor, state = load("./config.json")
    utxos = [
        *state.vault_utxos.values(),
        *state.trigger_utxos.values(),
        *state.theft_trigger_utxos.keys(),
    ]

    if outpoint:
        txid, n = outpoint.split(":")
        op = Outpoint(txid, int(n))
        utxos = [u for u in utxos if u.outpoint == op]
        if not utxos:
            print("failed to find utxo!")
            sys.exit(1)

    print("\nRecovering...")
    for u in utxos:
        print(f"  - {u}")

    print()
    phrase = input("Enter recovery phrase (check `secrets.json`): ")
    recovery_privkey = recoveryauth_phrase_to_key(phrase).get_bytes()

    def recoveryauth_signer(msg: bytes) -> bytes:
        """Prompt the user for the recovery phrase."""
        return core.key.sign_schnorr(recovery_privkey, msg)

    spec = get_recovery_tx(wallet_metadata.config, fees, utxos, recoveryauth_signer)
    wallet_metadata.recoveries.append(spec)

    rpc.sendrawtransaction(spec.tx.tohex())
    print(f"recovery txn ({spec.tx.rehash()}) now in mempool - mine some blocks")


if __name__ == "__main__":
    cli.run()
