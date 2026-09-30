from __future__ import annotations

import argparse
import hashlib
import json
from functools import lru_cache
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

P = 3 * 2**30 + 1
GENERATOR = 5
WIDTH = 8
ROUNDS = 40
CHAINS = 64
TARGET_SUM = 140
TRACE_COLUMNS = 34
MASK_DEGREE = 64
BLOWUP = 8
CAPACITY = (101, 211, 307, 401)
ROOT_IV = (503, 601, 701, 809, 907, 1009, 1103, 1201)
PHASES = ("member_init", "perm", "member_path", "member_final", "rehash", "acc", "new", "switch", "final", "idle")
FIXED_COLUMNS = len(PHASES) + WIDTH + 1


def inv(x: int) -> int:
    return pow(x % P, P - 2, P)


def _round_constants() -> tuple[tuple[int, ...], ...]:
    return tuple(
        tuple(
            int.from_bytes(
                hashlib.sha256(f"zk-shrincs-m31-v1/{r}/{j}".encode()).digest(), "big"
            )
            % P
            for j in range(WIDTH)
        )
        for r in range(ROUNDS)
    )


def _mds() -> tuple[tuple[int, ...], ...]:
    # A Cauchy matrix is MDS when all x_i and y_j are distinct and disjoint.
    return tuple(
        tuple(inv((i + 1) + (j + WIDTH + 1)) for j in range(WIDTH))
        for i in range(WIDTH)
    )


ROUND_CONSTANTS = _round_constants()
MDS = _mds()


def permute_round(state: Sequence[int], round_index: int) -> tuple[int, ...]:
    sbox = [pow((state[j] + ROUND_CONSTANTS[round_index][j]) % P, 5, P) for j in range(WIDTH)]
    return tuple(sum(MDS[i][j] * sbox[j] for j in range(WIDTH)) % P for i in range(WIDTH))


def permute(state: Sequence[int]) -> tuple[int, ...]:
    out = tuple(x % P for x in state)
    for r in range(ROUNDS):
        out = permute_round(out, r)
    return out


def chain_hash(value: Sequence[int]) -> tuple[int, ...]:
    if len(value) != 4:
        raise ValueError("chain hash input must contain four M31 elements")
    return permute(tuple(value) + CAPACITY)[:4]


def root_absorb(root: Sequence[int], endpoint: Sequence[int]) -> tuple[int, ...]:
    state = tuple((root[i] + endpoint[i]) % P for i in range(4)) + tuple(root[4:])
    return permute(state)


@lru_cache(maxsize=None)
def derive_digits(message: bytes) -> tuple[int, tuple[int, ...]]:
    for counter in range(2**32):
        digest = hashlib.sha256(b"ZK-SHRINCS-WOTS-C\x00" + message + counter.to_bytes(4, "big")).digest()[:16]
        digits = tuple((byte >> shift) & 3 for byte in digest for shift in (6, 4, 2, 0))
        if sum(digits) == TARGET_SUM:
            return counter, digits
    raise RuntimeError("WOTS+C grinding exhausted")


def keygen() -> dict:
    secret = [[secrets.randbelow(P) for _ in range(4)] for _ in range(CHAINS)]
    endpoints = []
    for value in secret:
        endpoint = tuple(value)
        for _ in range(3):
            endpoint = chain_hash(endpoint)
        endpoints.append(endpoint)
    root = ROOT_IV
    for endpoint in endpoints:
        root = root_absorb(root, endpoint)
    return {"secret": secret, "public": list(root)}


def sign(key: dict, message: bytes) -> dict:
    counter, digits = derive_digits(message)
    signature = []
    for secret_value, digit in zip(key["secret"], digits):
        value = tuple(secret_value)
        for _ in range(digit):
            value = chain_hash(value)
        signature.append(list(value))
    return {"counter": counter, "digits": list(digits), "signature": signature}


def verify_share(public_key: Sequence[int], message: bytes, share: dict) -> bool:
    counter, digits = derive_digits(message)
    if share.get("counter") != counter or tuple(share.get("digits", ())) != digits:
        return False
    if len(share.get("signature", ())) != CHAINS:
        return False
    root = ROOT_IV
    for value, digit in zip(share["signature"], digits):
        endpoint = tuple(value)
        if len(endpoint) != 4 or any(not 0 <= x < P for x in endpoint):
            return False
        for _ in range(3 - digit):
            endpoint = chain_hash(endpoint)
        root = root_absorb(root, endpoint)
    return tuple(public_key) == root

def policy_layers(policy: Sequence[Sequence[int]]) -> list[list[tuple[int, ...]]]:
    if not policy or len(policy) > 128:
        raise ValueError("policy must contain between 1 and 128 members")
    leaves = [tuple(permute(public_key)[:4]) for public_key in policy]
    padding_leaf = tuple(
        int.from_bytes(hashlib.sha256(f"zk-shrincs-policy-padding-v1/{i}".encode()).digest(), "big") % P
        for i in range(4)
    )
    if padding_leaf in leaves:
        raise ValueError("policy member collides with the reserved padding leaf")
    leaves.extend([padding_leaf] * (128 - len(leaves)))
    layers = [leaves]
    while len(layers[-1]) > 1:
        previous = layers[-1]
        layers.append([
            tuple(permute(previous[i] + previous[i + 1])[:4])
            for i in range(0, len(previous), 2)
        ])
    return layers


def policy_path(layers: Sequence[Sequence[Sequence[int]]], index: int) -> tuple[list[tuple[int, ...]], list[int]]:
    siblings: list[tuple[int, ...]] = []
    directions: list[int] = []
    for layer in layers[:-1]:
        siblings.append(tuple(layer[index ^ 1]))
        directions.append(index & 1)
        index //= 2
    return siblings, directions


def ntt(values: list[int], root: int) -> list[int]:
    n = len(values)
    if n == 0 or n & (n - 1):
        raise ValueError("NTT length must be a power of two")
    out = [x % P for x in values]
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i < j:
            out[i], out[j] = out[j], out[i]
    length = 2
    while length <= n:
        step = pow(root, n // length, P)
        for start in range(0, n, length):
            w = 1
            half = length // 2
            for i in range(start, start + half):
                u = out[i]
                v = out[i + half] * w % P
                out[i] = (u + v) % P
                out[i + half] = (u - v) % P
                w = w * step % P
        length <<= 1
    return out


def intt(values: list[int], root: int) -> list[int]:
    out = ntt(values, inv(root))
    scale = inv(len(values))
    return [x * scale % P for x in out]


def interpolate_subgroup(values: Sequence[int]) -> list[int]:
    n = len(values)
    root = pow(GENERATOR, (P - 1) // n, P)
    return intt(list(values), root)


def evaluate_coset(coefficients: Sequence[int], size: int, offset: int = GENERATOR) -> list[int]:
    if len(coefficients) > size:
        raise ValueError("polynomial does not fit evaluation domain")
    scaled = [0] * size
    power = 1
    for i, coefficient in enumerate(coefficients):
        scaled[i] = coefficient * power % P
        power = power * offset % P
    root = pow(GENERATOR, (P - 1) // size, P)
    return ntt(scaled, root)


def interpolate_coset(values: Sequence[int], offset: int = GENERATOR) -> list[int]:
    size = len(values)
    root = pow(GENERATOR, (P - 1) // size, P)
    scaled = intt(list(values), root)
    inverse_offset = inv(offset)
    power = 1
    for i in range(size):
        scaled[i] = scaled[i] * power % P
        power = power * inverse_offset % P
    while scaled and scaled[-1] == 0:
        scaled.pop()
    return scaled


def mask_polynomial(coefficients: Sequence[int]) -> list[int]:
    n = len(coefficients)
    out = list(coefficients) + [0] * MASK_DEGREE
    for i in range(MASK_DEGREE):
        random_coefficient = secrets.randbelow(P)
        out[i] = (out[i] - random_coefficient) % P
        out[n + i] = (out[n + i] + random_coefficient) % P
    return out


def field_bytes(values: Sequence[int]) -> bytes:
    return b"".join(int(value).to_bytes(4, "big") for value in values)


class MerkleTree:
    def __init__(self, rows: Sequence[Sequence[int]]):
        if not rows or len(rows) & (len(rows) - 1):
            raise ValueError("Merkle input length must be a nonzero power of two")
        self.rows = [tuple(int(x) for x in row) for row in rows]
        level = [hashlib.sha256(field_bytes(row)).digest() for row in self.rows]
        self.levels = [level]
        while len(level) > 1:
            level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
            self.levels.append(level)
        self.root = self.levels[-1][0]

    def path(self, index: int) -> list[bytes]:
        result = []
        for level in self.levels[:-1]:
            result.append(level[index ^ 1])
            index //= 2
        return result


def verify_path(row: Sequence[int], index: int, path: Sequence[bytes], root: bytes) -> bool:
    current = hashlib.sha256(field_bytes(row)).digest()
    for sibling in path:
        current = hashlib.sha256((sibling + current) if index & 1 else (current + sibling)).digest()
        index //= 2
    return current == root


@dataclass(frozen=True)
class Row:
    state: tuple[int, ...]
    root: tuple[int, ...]
    target: tuple[int, ...]
    index: int
    path_acc: int
    direction: int
    delta_bits: tuple[int, ...]

    def values(self) -> tuple[int, ...]:
        return self.state + self.root + self.target + (self.index, self.path_acc, self.direction) + self.delta_bits


def build_trace(
    policy: Sequence[Sequence[int]], signer_indices: Sequence[int], shares: Sequence[dict]
) -> tuple[list[Row], list[str], list[int | None], list[int]]:
    if not signer_indices or len(signer_indices) != len(shares):
        raise ValueError("the signer and share counts must match and be nonzero")
    if list(signer_indices) != sorted(set(signer_indices)) or any(index < 0 or index >= len(policy) for index in signer_indices):
        raise ValueError("signers must be distinct policy members in ascending order")
    layers = policy_layers(policy)
    rows: list[Row] = []
    phases: list[str] = []
    rounds: list[int | None] = []
    level_weights: list[int] = []

    def append(
        row: Row,
        prior_phase: str | None = None,
        prior_round: int | None = None,
        prior_level_weight: int = 0,
    ) -> None:
        if rows:
            if prior_phase is None:
                raise ValueError("outgoing phase required")
            phases.append(prior_phase)
            rounds.append(prior_round)
            level_weights.append(prior_level_weight)
        rows.append(row)

    def with_state(row: Row, state: Sequence[int]) -> Row:
        return Row(tuple(state), row.root, row.target, row.index, row.path_acc, row.direction, row.delta_bits)

    for signer_slot, signer_index in enumerate(signer_indices):
        share = shares[signer_slot]
        digits = tuple(share["digits"])
        if len(digits) != CHAINS or sum(digits) != TARGET_SUM:
            raise ValueError("invalid WOTS+C digits")
        target = tuple(policy[signer_index])
        siblings, directions = policy_path(layers, signer_index)
        if signer_slot + 1 < len(signer_indices):
            delta = signer_indices[signer_slot + 1] - signer_index - 1
            delta_bits = tuple((delta >> bit) & 1 for bit in range(7))
        else:
            delta_bits = (0,) * 7
        member = Row(target, siblings[0] + (0,) * 4, target, signer_index, 0, directions[0], delta_bits)
        if not rows:
            append(member)
            append(member, "member_init")
        else:
            append(member, "switch")
        current = member
        for round_index in range(ROUNDS):
            next_row = with_state(current, permute_round(current.state, round_index))
            append(next_row, "perm", round_index)
            current = next_row
        for level, (sibling, direction) in enumerate(zip(siblings, directions)):
            digest = current.state[:4]
            reset_state = digest + sibling if direction == 0 else sibling + digest
            reset = Row(
                reset_state,
                sibling + (0,) * 4,
                target,
                signer_index,
                current.path_acc + direction * (1 << level),
                direction,
                delta_bits,
            )
            append(reset, "member_path", prior_level_weight=1 << level)
            current = reset
            for round_index in range(ROUNDS):
                next_row = with_state(current, permute_round(current.state, round_index))
                append(next_row, "perm", round_index)
                current = next_row

        root = ROOT_IV
        for chain_index in range(CHAINS):
            signature_value = tuple(int(x) for x in share["signature"][chain_index])
            if len(signature_value) != 4:
                raise ValueError("invalid signature chain value")
            initial = Row(
                signature_value + CAPACITY,
                root,
                target,
                signer_index,
                current.path_acc,
                current.direction,
                delta_bits,
            )
            append(
                initial,
                "member_final" if chain_index == 0 else "new",
            )
            current = initial
            for hash_index in range(3 - digits[chain_index]):
                for round_index in range(ROUNDS):
                    next_row = with_state(current, permute_round(current.state, round_index))
                    append(next_row, "perm", round_index)
                    current = next_row
                if hash_index + 1 < 3 - digits[chain_index]:
                    reset = with_state(current, current.state[:4] + CAPACITY)
                    append(reset, "rehash")
                    current = reset
            absorb_state = tuple((current.root[i] + current.state[i]) % P for i in range(4)) + current.root[4:]
            absorb = with_state(current, absorb_state)
            append(absorb, "acc")
            current = absorb
            for round_index in range(ROUNDS):
                next_row = with_state(current, permute_round(current.state, round_index))
                append(next_row, "perm", round_index)
                current = next_row
            root = current.state
        if tuple(root) != target:
            raise ValueError(f"share trace does not end at signer {signer_index}'s public key")
    final = rows[-1]
    append(final, "final")
    trace_size = max(2**14, 1 << (len(rows) - 1).bit_length())
    while len(rows) < trace_size:
        append(final, "idle")
    phases.append("")
    rounds.append(None)
    level_weights.append(0)
    return rows, phases, rounds, level_weights


def fixed_columns(
    phases: Sequence[str],
    rounds: Sequence[int | None],
    level_weights: Sequence[int],
) -> list[list[int]]:
    columns = [[0] * len(phases) for _ in range(FIXED_COLUMNS)]
    constants_offset = len(PHASES)
    level_offset = constants_offset + WIDTH
    for i, phase in enumerate(phases):
        if phase:
            columns[PHASES.index(phase)][i] = 1
        if phase == "perm":
            assert rounds[i] is not None
            for j in range(WIDTH):
                columns[constants_offset + j][i] = ROUND_CONSTANTS[rounds[i]][j]
        columns[level_offset][i] = level_weights[i]
    return columns


def fixed_trace_metadata(
    signer_count: int, message: bytes
) -> tuple[list[str], list[int | None], list[int]]:
    if signer_count < 1:
        raise ValueError("signer count must be positive")
    _, digits = derive_digits(message)
    phases: list[str] = []
    rounds: list[int | None] = []
    level_weights: list[int] = []
    row_count = 0

    def append(
        prior_phase: str | None = None,
        prior_round: int | None = None,
        prior_level_weight: int = 0,
    ) -> None:
        nonlocal row_count
        if row_count:
            if prior_phase is None:
                raise ValueError("outgoing phase required")
            phases.append(prior_phase)
            rounds.append(prior_round)
            level_weights.append(prior_level_weight)
        row_count += 1

    for signer_slot in range(signer_count):
        if signer_slot == 0:
            append()
            append("member_init")
        else:
            append("switch")
        for round_index in range(ROUNDS):
            append("perm", round_index)
        for level in range(7):
            append("member_path", prior_level_weight=1 << level)
            for round_index in range(ROUNDS):
                append("perm", round_index)
        for chain_index, digit in enumerate(digits):
            append("member_final" if chain_index == 0 else "new")
            for hash_index in range(3 - digit):
                for round_index in range(ROUNDS):
                    append("perm", round_index)
                if hash_index + 1 < 3 - digit:
                    append("rehash")
            append("acc")
            for round_index in range(ROUNDS):
                append("perm", round_index)
    append("final")
    trace_size = max(2**14, 1 << (row_count - 1).bit_length())
    while row_count < trace_size:
        append("idle")
    phases.append("")
    rounds.append(None)
    level_weights.append(0)
    return phases, rounds, level_weights


def fixed_commitment_root(signer_count: int, message: bytes) -> bytes:
    phases, rounds, level_weights = fixed_trace_metadata(signer_count, message)
    trace_size = len(phases)
    fixed_base = fixed_columns(phases, rounds, level_weights)
    fixed_extended = [
        evaluate_coset(interpolate_subgroup(column), trace_size * BLOWUP)
        for column in fixed_base
    ]
    fixed_rows = [
        tuple(column[i] for column in fixed_extended)
        for i in range(trace_size * BLOWUP)
    ]
    return MerkleTree(fixed_rows).root


def constraint_residuals(
    current: Sequence[int],
    nxt: Sequence[int],
    fixed: Sequence[int],
    committed_policy_root: Sequence[int],
) -> list[int]:
    state, root, target = current[:8], current[8:16], current[16:24]
    index, path_acc, direction = current[24:27]
    delta_bits = current[27:34]
    next_state, next_root, next_target = nxt[:8], nxt[8:16], nxt[16:24]
    next_index, next_path_acc, next_direction = nxt[24:27]
    next_delta_bits = nxt[27:34]
    flags = fixed[: len(PHASES)]
    constants = fixed[len(PHASES) : len(PHASES) + WIDTH]
    level_weight = fixed[len(PHASES) + WIDTH]
    residuals: list[int] = []

    def gated(flag: int, values: Iterable[int]) -> None:
        residuals.extend(flag * (value % P) % P for value in values)

    member_init, perm_flag, member_path, member_final, rehash, acc, new, switch, final, idle = flags
    gated(member_init, [state[i] - target[i] for i in range(8)])
    gated(member_init, [path_acc])
    gated(member_init, [nxt[i] - current[i] for i in range(TRACE_COLUMNS)])

    sbox = [pow((state[j] + constants[j]) % P, 5, P) for j in range(8)]
    expected = [sum(MDS[i][j] * sbox[j] for j in range(8)) % P for i in range(8)]
    gated(perm_flag, [next_state[i] - expected[i] for i in range(8)])
    gated(perm_flag, [nxt[i] - current[i] for i in range(8, TRACE_COLUMNS)])

    gated(member_path, [next_direction * (next_direction - 1)])
    gated(member_path, [
        next_state[i] - ((1 - next_direction) * state[i] + next_direction * next_root[i])
        for i in range(4)
    ])
    gated(member_path, [
        next_state[i + 4] - ((1 - next_direction) * next_root[i] + next_direction * state[i])
        for i in range(4)
    ])
    gated(member_path, [next_root[i] for i in range(4, 8)])
    gated(member_path, [next_target[i] - target[i] for i in range(8)])
    gated(member_path, [next_index - index])
    gated(member_path, [next_path_acc - path_acc - next_direction * level_weight])
    gated(member_path, [next_delta_bits[i] - delta_bits[i] for i in range(7)])

    gated(member_final, [state[i] - committed_policy_root[i] for i in range(4)])
    gated(member_final, [path_acc - index])
    gated(member_final, [next_state[i + 4] - CAPACITY[i] for i in range(4)])
    gated(member_final, [next_root[i] - ROOT_IV[i] for i in range(8)])
    gated(member_final, [next_target[i] - target[i] for i in range(8)])
    gated(member_final, [next_index - index, next_path_acc - path_acc])
    gated(member_final, [next_delta_bits[i] - delta_bits[i] for i in range(7)])

    auxiliary = list(range(16, TRACE_COLUMNS))
    gated(rehash, [next_state[i] - state[i] for i in range(4)])
    gated(rehash, [next_state[i + 4] - CAPACITY[i] for i in range(4)])
    gated(rehash, [next_root[i] - root[i] for i in range(8)])
    gated(rehash, [nxt[i] - current[i] for i in auxiliary])

    gated(acc, [next_state[i] - root[i] - state[i] for i in range(4)])
    gated(acc, [next_state[i] - root[i] for i in range(4, 8)])
    gated(acc, [next_root[i] - root[i] for i in range(8)])
    gated(acc, [nxt[i] - current[i] for i in auxiliary])

    gated(new, [next_state[i + 4] - CAPACITY[i] for i in range(4)])
    gated(new, [next_root[i] - state[i] for i in range(8)])
    gated(new, [nxt[i] - current[i] for i in auxiliary])

    gated(switch, [state[i] - target[i] for i in range(8)])
    gated(switch, [next_state[i] - next_target[i] for i in range(8)])
    gated(switch, [next_path_acc])
    gated(switch, [bit * (bit - 1) for bit in delta_bits])
    gated(switch, [next_index - index - 1 - sum((1 << bit) * delta_bits[bit] for bit in range(7))])
    gated(switch, [next_root[i] for i in range(4, 8)])
    gated(switch, [next_direction * (next_direction - 1)])

    gated(final, [state[i] - target[i] for i in range(8)])
    gated(idle, [nxt[i] - current[i] for i in range(TRACE_COLUMNS)])
    return residuals


class Transcript:
    def __init__(self, seed: bytes):
        self.state = hashlib.sha256(seed).digest()

    def mix(self, value: bytes | int) -> None:
        data = value.to_bytes(4, "big") if isinstance(value, int) else value
        self.state = hashlib.sha256(self.state + data).digest()

    def draw(self, modulus: int) -> int:
        result = int.from_bytes(self.state, "big") % modulus
        self.state = hashlib.sha256(self.state).digest()
        return result


def combine_constraints(residuals: Sequence[int], alpha: int) -> int:
    group_lengths = (43, 34, 30, 34, 34, 34, 30, 30, 8, 34)
    if len(residuals) != sum(group_lengths):
        raise ValueError("unexpected AIR constraint count")
    groups = []
    offset = 0
    for length in group_lengths:
        group = 0
        for residual in reversed(residuals[offset : offset + length]):
            group = (residual + alpha * group) % P
        groups.append(group)
        offset += length
    result = 0
    for group in reversed(groups):
        result = (group + alpha * result) % P
    return result


def _path_json(path: Sequence[bytes]) -> list[str]:
    return [item.hex() for item in path]


def _row_proof(tree: MerkleTree, index: int) -> dict:
    return {"values": list(tree.rows[index]), "path": _path_json(tree.path(index))}


def _fold_coefficients(coefficients: Sequence[int], beta: int) -> list[int]:
    even = list(coefficients[::2])
    odd = list(coefficients[1::2])
    if len(odd) < len(even):
        odd.append(0)
    out = [(even[i] + beta * odd[i]) % P for i in range(len(even))]
    while out and out[-1] == 0:
        out.pop()
    return out or [0]


def prove(policy: Sequence[Sequence[int]], signer_indices: Sequence[int], shares: Sequence[dict], message: bytes) -> dict:
    for index, share in zip(signer_indices, shares):
        if not verify_share(policy[index], message, share):
            raise ValueError(f"invalid share for signer {index}")
    rows, phases, rounds, level_weights = build_trace(policy, signer_indices, shares)
    if (phases, rounds, level_weights) != fixed_trace_metadata(len(signer_indices), message):
        raise ValueError("trace schedule does not match the signed message")
    n = len(rows)
    extended_size = n * BLOWUP
    trace_columns = [[row.values()[j] for row in rows] for j in range(TRACE_COLUMNS)]
    trace_extended = [evaluate_coset(mask_polynomial(interpolate_subgroup(column)), extended_size) for column in trace_columns]
    trace_rows = [tuple(column[i] for column in trace_extended) for i in range(extended_size)]
    trace_tree = MerkleTree(trace_rows)

    fixed_base = fixed_columns(phases, rounds, level_weights)
    fixed_extended = [evaluate_coset(interpolate_subgroup(column), extended_size) for column in fixed_base]
    fixed_rows = [tuple(column[i] for column in fixed_extended) for i in range(extended_size)]
    fixed_tree = MerkleTree(fixed_rows)

    transcript = Transcript(message)
    transcript.mix(fixed_tree.root)
    transcript.mix(trace_tree.root)
    alpha = transcript.draw(P)

    root_m = pow(GENERATOR, (P - 1) // extended_size, P)
    coset_x = GENERATOR
    z_scale = pow(GENERATOR, n, P)
    z_step = pow(root_m, n, P)
    composition_values = []
    committed_policy_root = policy_layers(policy)[-1][0]
    for i in range(extended_size):
        current = trace_rows[i]
        nxt = trace_rows[(i + BLOWUP) % extended_size]
        numerator = combine_constraints(
            constraint_residuals(current, nxt, fixed_rows[i], committed_policy_root), alpha
        )
        z = (z_scale * pow(z_step, i, P) - 1) % P
        composition_values.append(numerator * inv(z) % P)
    composition_coefficients = interpolate_coset(composition_values)

    fri_layers: list[tuple[list[int], MerkleTree, list[int]]] = []
    coefficients = composition_coefficients
    domain_size = extended_size
    while len(coefficients) > 1:
        evaluations = evaluate_coset(coefficients, domain_size, coset_x)
        tree = MerkleTree([(value,) for value in evaluations])
        transcript.mix(tree.root)
        beta = transcript.draw(P)
        fri_layers.append((evaluations, tree, coefficients))
        coefficients = _fold_coefficients(coefficients, beta)
        coset_x = coset_x * coset_x % P
        domain_size //= 2
    last = coefficients[0]
    transcript.mix(last)
    query_index = transcript.draw(extended_size)

    query = {
        "index": query_index,
        "trace": _row_proof(trace_tree, query_index),
        "trace_next": _row_proof(trace_tree, (query_index + BLOWUP) % extended_size),
        "fixed": _row_proof(fixed_tree, query_index),
        "fri": [],
    }
    index = query_index
    for evaluations, tree, _ in fri_layers:
        layer_size = len(evaluations)
        a = index % layer_size
        b = (a + layer_size // 2) % layer_size
        query["fri"].append({"a": _row_proof(tree, a), "b": _row_proof(tree, b)})

    return {
        "version": 1,
        "field_modulus": P,
        "trace_size": n,
        "blowup": BLOWUP,
        "message": message.hex(),
        "signer_indices": list(signer_indices),
        "fixed_root": fixed_tree.root.hex(),
        "trace_root": trace_tree.root.hex(),
        "fri_roots": [tree.root.hex() for _, tree, _ in fri_layers],
        "last": last,
        "query": query,
    }


def verify_proof(
    policy: Sequence[Sequence[int]],
    proof: dict,
    expected_fixed_root: bytes | None = None,
) -> bool:
    try:
        trace_size = proof["trace_size"]
        if proof["version"] != 1 or proof["field_modulus"] != P or trace_size < 2**14 or trace_size & (trace_size - 1) or proof["blowup"] != BLOWUP:
            return False
        signer_indices = proof["signer_indices"]
        if not signer_indices or len(set(signer_indices)) != len(signer_indices) or any(index < 0 or index >= len(policy) for index in signer_indices):
            return False
        message = bytes.fromhex(proof["message"])
        fixed_root = bytes.fromhex(proof["fixed_root"])
        if expected_fixed_root is None:
            expected_fixed_root = fixed_commitment_root(len(signer_indices), message)
        if fixed_root != expected_fixed_root:
            return False
        trace_root = bytes.fromhex(proof["trace_root"])
        fri_roots = [bytes.fromhex(root) for root in proof["fri_roots"]]
        transcript = Transcript(message)
        transcript.mix(fixed_root)
        transcript.mix(trace_root)
        alpha = transcript.draw(P)
        betas = []
        for root in fri_roots:
            transcript.mix(root)
            betas.append(transcript.draw(P))
        transcript.mix(proof["last"])
        extended_size = proof["trace_size"] * BLOWUP
        expected_index = transcript.draw(extended_size)
        query = proof["query"]
        if query["index"] != expected_index or len(query["fri"]) != len(fri_roots):
            return False

        def decode_opening(opening: dict) -> tuple[tuple[int, ...], list[bytes]]:
            return tuple(opening["values"]), [bytes.fromhex(x) for x in opening["path"]]

        current, current_path = decode_opening(query["trace"])
        nxt, next_path = decode_opening(query["trace_next"])
        fixed, fixed_path = decode_opening(query["fixed"])
        if len(current) != TRACE_COLUMNS or len(nxt) != TRACE_COLUMNS or len(fixed) != FIXED_COLUMNS:
            return False
        if not verify_path(current, expected_index, current_path, trace_root):
            return False
        next_index = (expected_index + BLOWUP) % extended_size
        if not verify_path(nxt, next_index, next_path, trace_root):
            return False
        if not verify_path(fixed, expected_index, fixed_path, fixed_root):
            return False

        root_m = pow(GENERATOR, (P - 1) // extended_size, P)
        x = GENERATOR * pow(root_m, expected_index, P) % P
        numerator = combine_constraints(
            constraint_residuals(current, nxt, fixed, policy_layers(policy)[-1][0]), alpha
        )
        cp = numerator * inv((pow(x, proof["trace_size"], P) - 1) % P) % P
        index = expected_index
        domain_x = x
        for layer_index, (root, beta, opening) in enumerate(zip(fri_roots, betas, query["fri"])):
            a_values, a_path = decode_opening(opening["a"])
            b_values, b_path = decode_opening(opening["b"])
            if len(a_values) != 1 or len(b_values) != 1:
                return False
            layer_size = extended_size >> layer_index
            a_index = index % layer_size
            b_index = (a_index + layer_size // 2) % layer_size
            if not verify_path(a_values, a_index, a_path, root) or not verify_path(b_values, b_index, b_path, root):
                return False
            if a_values[0] != cp:
                return False
            cp = ((a_values[0] + b_values[0]) * inv(2) + beta * (a_values[0] - b_values[0]) * inv(2 * domain_x % P)) % P
            domain_x = domain_x * domain_x % P
        return cp == proof["last"]
    except (KeyError, TypeError, ValueError, ZeroDivisionError):
        return False


def _load(path: str) -> dict:
    return json.loads(Path(path).read_text())


def _dump(path: str, value: object) -> None:
    Path(path).write_text(json.dumps(value, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    setup_parser = sub.add_parser("setup")
    setup_parser.add_argument("--out", required=True)
    setup_parser.add_argument("--participants", type=int, default=3)
    setup_parser.add_argument("--threshold", type=int, default=2)
    sign_parser = sub.add_parser("sign")
    sign_parser.add_argument("--key", required=True)
    sign_parser.add_argument("--message", required=True)
    sign_parser.add_argument("--out", required=True)
    prove_parser = sub.add_parser("prove")
    prove_parser.add_argument("--policy", required=True)
    prove_parser.add_argument("--indices", required=True)
    prove_parser.add_argument("--shares", nargs="+", required=True)
    prove_parser.add_argument("--message", required=True)
    prove_parser.add_argument("--out", required=True)
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--policy", required=True)
    verify_parser.add_argument("--proof", required=True)
    args = parser.parse_args()

    if args.command == "setup":
        if args.participants < 1 or args.threshold < 1 or args.threshold > args.participants:
            raise SystemExit("threshold must be in 1..=participants")
        directory = Path(args.out)
        directory.mkdir(parents=True, exist_ok=False)
        keys = [keygen() for _ in range(args.participants)]
        for i, key in enumerate(keys):
            _dump(str(directory / f"signer-{i}.json"), key)
        _dump(str(directory / "policy.json"), {"threshold": args.threshold, "public_keys": [key["public"] for key in keys]})
    elif args.command == "sign":
        _dump(args.out, sign(_load(args.key), bytes.fromhex(args.message)))
    elif args.command == "prove":
        policy_file = _load(args.policy)
        policy = policy_file["public_keys"]
        indices = [int(value) for value in args.indices.split(",")]
        if len(indices) != policy_file["threshold"] or len(args.shares) != policy_file["threshold"]:
            raise SystemExit("the proof must contain exactly threshold distinct shares")
        proof = prove(policy, indices, [_load(path) for path in args.shares], bytes.fromhex(args.message))
        _dump(args.out, proof)
    elif args.command == "verify":
        policy_file = _load(args.policy)
        proof = _load(args.proof)
        if len(proof.get("signer_indices", ())) != policy_file["threshold"] or not verify_proof(policy_file["public_keys"], proof):
            raise SystemExit("invalid proof")
        print("valid")


if __name__ == "__main__":
    main()
