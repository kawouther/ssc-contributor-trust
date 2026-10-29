"""
Minimal transaction runner on top of the official Ethereum execution
specification (ethereum/execution-specs, Prague fork).

The interpreter, gas schedule, warm/cold access accounting (EIP-2929),
SSTORE pricing (EIP-2200/3529), calldata pricing incl. the EIP-7623 floor,
and refunds are those of the specification itself, so the gas figures are
the gas a Prague-compatible client (geth, Nethermind, Besu, ...) charges.

What is NOT reproduced here: signature recovery (the sender is given
directly) and block-level effects. Neither changes gas used by a transaction.
Each transaction is executed in its own block.
"""
from __future__ import annotations

import json, os, sys, time
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEPS = Path(os.environ.get("EVM_DEPS", "/tmp/dl"))
for p in [HERE / "shims2", HERE / "shims", DEPS / "ethereum-types/src",
          DEPS / "ethereum-rlp/src", DEPS / "execution-specs/src"]:
    sys.path.insert(0, str(p))
import sitecustomize  # noqa: F401  (stubs precompile-only libraries)

from ethereum_types.bytes import Bytes, Bytes0, Bytes20, Bytes32
from ethereum_types.numeric import U64, U256, Uint
from ethereum.crypto.hash import keccak256
from ethereum.state import Account, EMPTY_CODE_HASH
from ethereum.state_mpt import State, apply_changes_to_state, set_account as mpt_set_account
from ethereum.forks.prague import vm
from ethereum.forks.prague.state_tracker import (
    BlockState, TransactionState, get_account, increment_nonce,
    incorporate_tx_into_block, extract_block_diff,
)
from ethereum.forks.prague.transactions import FeeMarketTransaction, calculate_intrinsic_cost
from ethereum.forks.prague.utils.message import prepare_message
from ethereum.forks.prague.utils.address import compute_contract_address
from ethereum.forks.prague.vm.interpreter import process_message_call

BLOCK_GAS_LIMIT = Uint(36_000_000)


@dataclass
class Receipt:
    gas_used: int
    intrinsic: int
    success: bool
    output: bytes
    logs: list
    created: bytes | None
    wall_ms: float


class Chain:
    def __init__(self):
        self.state = State()
        self.number = 1
        self.time = 1_700_000_000
        self.nonces: dict[bytes, int] = {}

    def fund(self, addr: bytes, wei: int = 10**24):
        mpt_set_account(self.state, Bytes20(addr),
                        Account(nonce=Uint(0), balance=U256(wei), code_hash=EMPTY_CODE_HASH))
        self.nonces[addr] = 0

    def send(self, sender: bytes, to: bytes | None, data: bytes, gas: int = 15_000_000) -> Receipt:
        t0 = time.perf_counter()
        block_state = BlockState(pre_state=self.state)
        block_env = vm.BlockEnvironment(
            chain_id=U64(31337), state=block_state, block_gas_limit=BLOCK_GAS_LIMIT,
            block_hashes=[], coinbase=Bytes20(b"\xcb" * 20), number=Uint(self.number),
            base_fee_per_gas=Uint(0), time=U256(self.time), prev_randao=Bytes32(b"\0" * 32),
            excess_blob_gas=U64(0), parent_beacon_block_root=Bytes32(b"\0" * 32),
        )
        tx = FeeMarketTransaction(
            chain_id=U64(31337), nonce=U256(self.nonces[sender]),
            max_priority_fee_per_gas=Uint(0), max_fee_per_gas=Uint(0), gas=Uint(gas),
            to=Bytes0(b"") if to is None else Bytes20(to), value=U256(0), data=Bytes(data),
            access_list=(), y_parity=U256(0), r=U256(0), s=U256(0),
        )
        intrinsic = calculate_intrinsic_cost(tx)
        tx_state = TransactionState(parent=block_state)
        sender_a = Bytes20(sender)
        increment_nonce(tx_state, sender_a)
        tx_env = vm.TransactionEnvironment(
            origin=sender_a, gas_price=Uint(0), gas=Uint(gas) - intrinsic.regular,
            access_list_addresses={block_env.coinbase}, access_list_storage_keys=set(),
            state=tx_state, blob_versioned_hashes=(), authorizations=(),
            index_in_block=Uint(0), tx_hash=None,
        )
        msg = prepare_message(block_env, tx_env, tx)
        out = process_message_call(msg)

        used_before_refund = Uint(gas) - out.gas_left
        refund = min(used_before_refund // Uint(5), Uint(out.refund_counter))
        used = max(used_before_refund - refund, intrinsic.calldata_floor)

        incorporate_tx_into_block(tx_state)
        apply_changes_to_state(self.state, extract_block_diff(block_state))
        self.nonces[sender] += 1
        self.number += 1
        self.time += 12
        created = None
        if to is None and out.error is None:
            created = bytes(compute_contract_address(sender_a, Uint(self.nonces[sender] - 1)))
        return Receipt(int(used), int(intrinsic.regular), out.error is None,
                       bytes(out.return_data) if hasattr(out, "return_data") else b"",
                       list(out.logs), created, (time.perf_counter() - t0) * 1000)


# ---------------------------------------------------------------- ABI helpers
def selector(sig: str) -> bytes:
    return bytes(keccak256(sig.encode()))[:4]


def enc_word(v) -> bytes:
    if isinstance(v, (bytes, bytearray)):
        assert len(v) <= 32
        return bytes(v).ljust(32, b"\0")
    v = int(v)
    return (v % (1 << 256)).to_bytes(32, "big")


def encode_call(sig: str, *args) -> bytes:
    """Static types + a single trailing dynamic bytes32[] are supported."""
    head, tail = [], b""
    n = len(args)
    for a in args:
        if isinstance(a, list):
            head.append(enc_word(32 * n + len(tail)))
            tail += enc_word(len(a)) + b"".join(enc_word(x) for x in a)
        else:
            head.append(enc_word(a))
    return selector(sig) + b"".join(head) + tail


def load_build(path: Path):
    d = json.loads(path.read_text())["contracts"]
    return {k.split(":")[1]: v for k, v in d.items()}
