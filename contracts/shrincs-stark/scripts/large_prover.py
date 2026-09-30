from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import json
import secrets
import subprocess
from pathlib import Path
from typing import Sequence

import numpy as np

import protocol

P = protocol.P
GENERATOR = protocol.GENERATOR
BLOWUP = protocol.BLOWUP
MASK_DEGREE = protocol.MASK_DEGREE
TRACE_COLUMNS = protocol.TRACE_COLUMNS
FIXED_COLUMNS = protocol.FIXED_COLUMNS

U64 = np.uint64


class Accelerator:
    def __init__(self) -> None:
        source = Path(__file__).with_name("large_accel.c")
        library = source.with_suffix(".so")
        if not library.exists() or library.stat().st_mtime < source.stat().st_mtime:
            subprocess.run(
                ["cc", "-O3", "-shared", "-fPIC", str(source), "-lcrypto", "-o", str(library)],
                check=True,
            )
        self.lib = ctypes.CDLL(str(library))
        self.lib.field_powers.argtypes = [
            ctypes.POINTER(ctypes.c_uint64), ctypes.c_size_t, ctypes.c_uint64, ctypes.c_uint64
        ]
        self.lib.hash_field_rows.argtypes = [
            ctypes.POINTER(ctypes.c_uint64), ctypes.c_size_t, ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_ubyte),
        ]
        self.lib.hash_merkle_parents.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t, ctypes.POINTER(ctypes.c_ubyte)
        ]

    @staticmethod
    def _u64_ptr(array: np.ndarray):
        return array.ctypes.data_as(ctypes.POINTER(ctypes.c_uint64))

    @staticmethod
    def _byte_ptr(array: np.ndarray):
        return array.ctypes.data_as(ctypes.POINTER(ctypes.c_ubyte))

    def powers(self, length: int, start: int, step: int) -> np.ndarray:
        out = np.empty(length, dtype=np.uint64)
        self.lib.field_powers(self._u64_ptr(out), length, start, step)
        return out

    def hash_rows(self, rows: np.ndarray) -> np.ndarray:
        rows = np.ascontiguousarray(rows, dtype=np.uint64)
        if rows.ndim == 1:
            rows = rows.reshape(-1, 1)
        if rows.shape[1] > 64:
            raise ValueError("row hashing accelerator supports at most 64 field columns")
        out = np.empty((rows.shape[0], 32), dtype=np.uint8)
        self.lib.hash_field_rows(self._u64_ptr(rows), rows.shape[0], rows.shape[1], self._byte_ptr(out))
        return out

    def parents(self, children: np.ndarray) -> np.ndarray:
        children = np.ascontiguousarray(children, dtype=np.uint8)
        out = np.empty((children.shape[0] // 2, 32), dtype=np.uint8)
        self.lib.hash_merkle_parents(self._byte_ptr(children), out.shape[0], self._byte_ptr(out))
        return out


ACCEL = Accelerator()
_BIT_REVERSE: dict[int, np.ndarray] = {}


def bit_reverse(size: int) -> np.ndarray:
    cached = _BIT_REVERSE.get(size)
    if cached is not None:
        return cached
    source = np.arange(size, dtype=np.uint32)
    work = source.copy()
    result = np.zeros(size, dtype=np.uint32)
    for _ in range(size.bit_length() - 1):
        result = (result << U64(1)) | (work & U64(1))
        work >>= U64(1)
    _BIT_REVERSE[size] = result
    return result


def ntt(values: np.ndarray, root: int) -> np.ndarray:
    size = len(values)
    if size == 0 or size & (size - 1):
        raise ValueError("NTT length must be a power of two")
    source = np.ascontiguousarray(values, dtype=np.uint64)
    one_dimensional = source.ndim == 1
    if one_dimensional:
        source = source.reshape(size, 1)
    out = source[bit_reverse(size)].copy()
    columns = out.shape[1]
    length = 2
    while length <= size:
        half = length // 2
        step = pow(root, size // length, P)
        twiddles = ACCEL.powers(half, 1, step).reshape(1, half, 1)
        blocks = out.reshape(-1, length, columns)
        left = blocks[:, :half, :].copy()
        right = (blocks[:, half:, :] * twiddles) % U64(P)
        blocks[:, :half, :] = (left + right) % U64(P)
        blocks[:, half:, :] = (left + U64(P) - right) % U64(P)
        length <<= 1
    return out[:, 0] if one_dimensional else out


def intt(values: np.ndarray, root: int) -> np.ndarray:
    out = ntt(values, pow(root, P - 2, P))
    return (out * U64(pow(len(values), P - 2, P))) % U64(P)


def interpolate_subgroup(values: np.ndarray) -> np.ndarray:
    root = pow(GENERATOR, (P - 1) // len(values), P)
    return intt(values, root)


def evaluate_coset(coefficients: np.ndarray, size: int, offset: int = GENERATOR) -> np.ndarray:
    if len(coefficients) > size:
        raise ValueError("polynomial does not fit evaluation domain")
    source = np.asarray(coefficients, dtype=np.uint64)
    one_dimensional = source.ndim == 1
    if one_dimensional:
        source = source.reshape(-1, 1)
    scaled = np.zeros((size, source.shape[1]), dtype=np.uint64)
    powers = ACCEL.powers(len(source), 1, offset).reshape(-1, 1)
    scaled[: len(source)] = (source * powers) % U64(P)
    root = pow(GENERATOR, (P - 1) // size, P)
    result = ntt(scaled, root)
    return result[:, 0] if one_dimensional else result


def interpolate_coset(values: np.ndarray, offset: int = GENERATOR) -> np.ndarray:
    size = len(values)
    root = pow(GENERATOR, (P - 1) // size, P)
    coefficients = intt(values, root)
    inverse_offset = pow(offset, P - 2, P)
    coefficients = (coefficients * ACCEL.powers(size, 1, inverse_offset)) % U64(P)
    nonzero = np.flatnonzero(coefficients)
    return coefficients[: nonzero[-1] + 1].copy() if len(nonzero) else np.zeros(1, dtype=np.uint64)


def mask_polynomial(coefficients: np.ndarray) -> np.ndarray:
    source = np.asarray(coefficients, dtype=np.uint64)
    one_dimensional = source.ndim == 1
    if one_dimensional:
        source = source.reshape(-1, 1)
    size, columns = source.shape
    out = np.zeros((size + MASK_DEGREE, columns), dtype=np.uint64)
    out[:size] = source
    random_values = np.fromiter(
        (secrets.randbelow(P) for _ in range(MASK_DEGREE * columns)), dtype=np.uint64
    ).reshape(MASK_DEGREE, columns)
    out[:MASK_DEGREE] = (out[:MASK_DEGREE] + U64(P) - random_values) % U64(P)
    out[size:] = random_values
    return out[:, 0] if one_dimensional else out


class MerkleTree:
    def __init__(self, rows: np.ndarray):
        if len(rows) == 0 or len(rows) & (len(rows) - 1):
            raise ValueError("Merkle input length must be a power of two")
        level = ACCEL.hash_rows(rows)
        self.levels = [level]
        while len(level) > 1:
            level = ACCEL.parents(level)
            self.levels.append(level)

    @property
    def root(self) -> bytes:
        return self.levels[-1][0].tobytes()

    def path(self, index: int) -> list[bytes]:
        result = []
        for level in self.levels[:-1]:
            result.append(level[index ^ 1].tobytes())
            index //= 2
        return result


def permutation_batch(states: np.ndarray) -> np.ndarray:
    states = np.ascontiguousarray(states, dtype=np.uint64)
    constants = np.asarray(protocol.ROUND_CONSTANTS, dtype=np.uint64)
    mds = np.asarray(protocol.MDS, dtype=np.uint64)
    for round_index in range(protocol.ROUNDS):
        x = (states + constants[round_index]) % U64(P)
        x2 = (x * x) % U64(P)
        x5 = (((x2 * x2) % U64(P)) * x) % U64(P)
        next_states = np.zeros_like(states)
        for i in range(protocol.WIDTH):
            value = np.zeros(states.shape[:-1], dtype=np.uint64)
            for j in range(protocol.WIDTH):
                value = (value + (x5[..., j] * mds[i, j]) % U64(P)) % U64(P)
            next_states[..., i] = value
        states = next_states
    return states


def setup(participants: int, threshold: int, out: Path) -> None:
    if participants < 1 or threshold < 1 or threshold > participants:
        raise ValueError("threshold must be in 1..=participants")
    out.mkdir(parents=True, exist_ok=False)
    secret = np.fromiter(
        (secrets.randbelow(P) for _ in range(participants * protocol.CHAINS * 4)),
        dtype=np.uint64,
    ).reshape(participants, protocol.CHAINS, 4)
    endpoints = secret.copy()
    capacity = np.asarray(protocol.CAPACITY, dtype=np.uint64)
    for _ in range(3):
        states = np.concatenate([endpoints, np.broadcast_to(capacity, endpoints.shape)], axis=-1)
        endpoints = permutation_batch(states)[..., :4]
    roots = np.broadcast_to(np.asarray(protocol.ROOT_IV, dtype=np.uint64), (participants, 8)).copy()
    for chain in range(protocol.CHAINS):
        states = roots.copy()
        states[:, :4] = (states[:, :4] + endpoints[:, chain]) % U64(P)
        roots = permutation_batch(states)
    for i in range(participants):
        key = {"secret": secret[i].astype(int).tolist(), "public": roots[i].astype(int).tolist()}
        (out / f"signer-{i}.json").write_text(json.dumps(key, separators=(",", ":")) + "\n")
    policy = {"threshold": threshold, "public_keys": roots.astype(int).tolist()}
    (out / "policy.json").write_text(json.dumps(policy, separators=(",", ":")) + "\n")


def sign_selected(directory: Path, indices: Sequence[int], message: bytes) -> None:
    counter, digits_tuple = protocol.derive_digits(message)
    digits = np.asarray(digits_tuple, dtype=np.uint64)
    keys = [json.loads((directory / f"signer-{index}.json").read_text()) for index in indices]
    signatures = np.asarray([key["secret"] for key in keys], dtype=np.uint64)
    capacity = np.asarray(protocol.CAPACITY, dtype=np.uint64)
    for step in range(3):
        mask = digits > step
        if not np.any(mask):
            continue
        selected = signatures[:, mask, :]
        states = np.concatenate([selected, np.broadcast_to(capacity, selected.shape)], axis=-1)
        signatures[:, mask, :] = permutation_batch(states)[..., :4]
    for slot, index in enumerate(indices):
        share = {
            "counter": counter,
            "digits": [int(value) for value in digits],
            "signature": signatures[slot].astype(int).tolist(),
        }
        (directory / f"share-{index}.json").write_text(json.dumps(share, separators=(",", ":")) + "\n")


def extend_columns(base: np.ndarray, extended_size: int, masked: bool) -> np.ndarray:
    result = np.empty((extended_size, base.shape[1]), dtype=np.uint64)
    batch_size = 4
    for start in range(0, base.shape[1], batch_size):
        stop = min(start + batch_size, base.shape[1])
        coefficients = interpolate_subgroup(base[:, start:stop])
        if masked:
            coefficients = mask_polynomial(coefficients)
        result[:, start:stop] = evaluate_coset(coefficients, extended_size)
    return result


def sub(a, b):
    return (a + U64(P) - b) % U64(P)


def fold_group(flag: np.ndarray, expressions: Sequence) -> np.ndarray:
    result = np.zeros(len(flag), dtype=np.uint64)
    for expression in reversed(expressions):
        residual = expression() if callable(expression) else expression
        result = (residual + result * U64(CURRENT_ALPHA)) % U64(P)
    return (flag * result) % U64(P)


CURRENT_ALPHA = 0


def composition_numerators(
    trace: np.ndarray, fixed: np.ndarray, alpha: int, committed_policy_root: Sequence[int]
) -> np.ndarray:
    global CURRENT_ALPHA
    CURRENT_ALPHA = alpha
    current = trace
    nxt = np.roll(trace, -BLOWUP, axis=0)
    state, root, target = current[:, :8], current[:, 8:16], current[:, 16:24]
    next_state, next_root, next_target = nxt[:, :8], nxt[:, 8:16], nxt[:, 16:24]
    index, path_acc, direction = current[:, 24], current[:, 25], current[:, 26]
    next_index, next_path_acc, next_direction = nxt[:, 24], nxt[:, 25], nxt[:, 26]
    delta, next_delta = current[:, 27:34], nxt[:, 27:34]
    flags = [fixed[:, i] for i in range(10)]
    constants = fixed[:, 10:18]
    level_weight = fixed[:, 18]
    policy_root = np.asarray(committed_policy_root, dtype=np.uint64)
    capacity = protocol.CAPACITY
    groups: list[np.ndarray] = []

    groups.append(fold_group(flags[0], [
        *[(lambda i=i: sub(state[:, i], target[:, i])) for i in range(8)],
        path_acc,
        *[(lambda i=i: sub(nxt[:, i], current[:, i])) for i in range(TRACE_COLUMNS)],
    ]))

    x = (state + constants) % U64(P)
    x2 = (x * x) % U64(P)
    sbox = (((x2 * x2) % U64(P)) * x) % U64(P)
    expected = []
    for i in range(8):
        value = np.zeros(len(trace), dtype=np.uint64)
        for j in range(8):
            value = (value + sbox[:, j] * U64(protocol.MDS[i][j])) % U64(P)
        expected.append(value)
    groups.append(fold_group(flags[1], [
        *[(lambda i=i: sub(next_state[:, i], expected[i])) for i in range(8)],
        *[(lambda i=i: sub(nxt[:, i], current[:, i])) for i in range(8, TRACE_COLUMNS)],
    ]))
    del x, x2, sbox, expected

    groups.append(fold_group(flags[2], [
        next_direction * sub(next_direction, U64(1)) % U64(P),
        *[
            (lambda i=i: sub(
                next_state[:, i],
                (state[:, i] + next_direction * sub(next_root[:, i], state[:, i])) % U64(P),
            ))
            for i in range(4)
        ],
        *[
            (lambda i=i: sub(
                next_state[:, i + 4],
                (next_root[:, i] + next_direction * sub(state[:, i], next_root[:, i])) % U64(P),
            ))
            for i in range(4)
        ],
        *[(lambda i=i: next_root[:, i + 4]) for i in range(4)],
        *[(lambda i=i: sub(next_target[:, i], target[:, i])) for i in range(8)],
        sub(next_index, index),
        sub(next_path_acc, (path_acc + next_direction * level_weight) % U64(P)),
        *[(lambda i=i: sub(next_delta[:, i], delta[:, i])) for i in range(7)],
    ]))

    groups.append(fold_group(flags[3], [
        *[(lambda i=i: sub(state[:, i], policy_root[i])) for i in range(4)],
        sub(path_acc, index),
        *[(lambda i=i: sub(next_state[:, i + 4], U64(capacity[i]))) for i in range(4)],
        *[(lambda i=i: sub(next_root[:, i], U64(protocol.ROOT_IV[i]))) for i in range(8)],
        *[(lambda i=i: sub(next_target[:, i], target[:, i])) for i in range(8)],
        sub(next_index, index),
        sub(next_path_acc, path_acc),
        *[(lambda i=i: sub(next_delta[:, i], delta[:, i])) for i in range(7)],
    ]))

    groups.append(fold_group(flags[4], [
        *[(lambda i=i: sub(next_state[:, i], state[:, i])) for i in range(4)],
        *[(lambda i=i: sub(next_state[:, i + 4], U64(capacity[i]))) for i in range(4)],
        *[(lambda i=i: sub(next_root[:, i], root[:, i])) for i in range(8)],
        *[(lambda i=i: sub(nxt[:, i], current[:, i])) for i in range(16, TRACE_COLUMNS)],
    ]))
    groups.append(fold_group(flags[5], [
        *[(lambda i=i: sub(next_state[:, i], (root[:, i] + state[:, i]) % U64(P))) for i in range(4)],
        *[(lambda i=i: sub(next_state[:, i], root[:, i])) for i in range(4, 8)],
        *[(lambda i=i: sub(next_root[:, i], root[:, i])) for i in range(8)],
        *[(lambda i=i: sub(nxt[:, i], current[:, i])) for i in range(16, TRACE_COLUMNS)],
    ]))
    groups.append(fold_group(flags[6], [
        *[(lambda i=i: sub(next_state[:, i + 4], U64(capacity[i]))) for i in range(4)],
        *[(lambda i=i: sub(next_root[:, i], state[:, i])) for i in range(8)],
        *[(lambda i=i: sub(nxt[:, i], current[:, i])) for i in range(16, TRACE_COLUMNS)],
    ]))

    delta_value = np.zeros(len(trace), dtype=np.uint64)
    for bit in range(7):
        delta_value = (delta_value + U64(1 << bit) * delta[:, bit]) % U64(P)
    groups.append(fold_group(flags[7], [
        *[(lambda i=i: sub(state[:, i], target[:, i])) for i in range(8)],
        *[(lambda i=i: sub(next_state[:, i], next_target[:, i])) for i in range(8)],
        next_path_acc,
        *[
            (lambda i=i: delta[:, i] * sub(delta[:, i], U64(1)) % U64(P))
            for i in range(7)
        ],
        sub(next_index, (index + U64(1) + delta_value) % U64(P)),
        *[(lambda i=i: next_root[:, i + 4]) for i in range(4)],
        next_direction * sub(next_direction, U64(1)) % U64(P),
    ]))
    del delta_value

    groups.append(fold_group(flags[8], [
        *[(lambda i=i: sub(state[:, i], target[:, i])) for i in range(8)],
    ]))
    groups.append(fold_group(flags[9], [
        *[(lambda i=i: sub(nxt[:, i], current[:, i])) for i in range(TRACE_COLUMNS)],
    ]))

    result = np.zeros(len(trace), dtype=np.uint64)
    for group in reversed(groups):
        result = (group + U64(alpha) * result) % U64(P)
    return result


def row_opening(rows: np.ndarray, tree: MerkleTree, index: int) -> dict:
    return {
        "values": [int(value) for value in rows[index]],
        "path": [value.hex() for value in tree.path(index)],
    }


def fixed_commitment_root(signer_count: int, message: bytes) -> bytes:
    phases, rounds, level_weights = protocol.fixed_trace_metadata(signer_count, message)
    fixed_base = np.asarray(
        protocol.fixed_columns(phases, rounds, level_weights), dtype=np.uint64
    ).T.copy()
    fixed = extend_columns(fixed_base, len(phases) * BLOWUP, masked=False)
    return MerkleTree(fixed).root


def prove(directory: Path, indices: Sequence[int], message: bytes, output: Path) -> None:
    policy_file = json.loads((directory / "policy.json").read_text())
    if len(indices) != policy_file["threshold"]:
        raise ValueError("signer count must equal policy threshold")
    policy = policy_file["public_keys"]
    shares = [json.loads((directory / f"share-{index}.json").read_text()) for index in indices]
    for index, share in zip(indices, shares):
        if not protocol.verify_share(policy[index], message, share):
            raise ValueError(f"invalid share for signer {index}")

    rows, phases, rounds, level_weights = protocol.build_trace(policy, indices, shares)
    expected_metadata = protocol.fixed_trace_metadata(len(indices), message)
    if (phases, rounds, level_weights) != expected_metadata:
        raise ValueError("trace schedule does not match the signed message")
    trace_base = np.asarray([row.values() for row in rows], dtype=np.uint64)
    fixed_base = np.asarray(
        protocol.fixed_columns(phases, rounds, level_weights), dtype=np.uint64
    ).T.copy()
    trace_size = len(rows)
    extended_size = trace_size * BLOWUP

    trace = extend_columns(trace_base, extended_size, masked=True)
    trace_tree = MerkleTree(trace)
    fixed = extend_columns(fixed_base, extended_size, masked=False)
    fixed_tree = MerkleTree(fixed)

    transcript = protocol.Transcript(message)
    transcript.mix(fixed_tree.root)
    transcript.mix(trace_tree.root)
    alpha = transcript.draw(P)

    numerators = composition_numerators(trace, fixed, alpha, protocol.policy_layers(policy)[-1][0])
    z_scale = pow(GENERATOR, trace_size, P)
    root_m = pow(GENERATOR, (P - 1) // extended_size, P)
    z_step = pow(root_m, trace_size, P)
    z_values = np.asarray([(z_scale * pow(z_step, i, P) - 1) % P for i in range(BLOWUP)], dtype=np.uint64)
    z_inverse = np.asarray([pow(int(value), P - 2, P) for value in z_values], dtype=np.uint64)
    composition = (numerators * np.resize(z_inverse, extended_size)) % U64(P)
    del numerators
    coefficients = interpolate_coset(composition)
    del composition

    fri_layers: list[tuple[np.ndarray, MerkleTree]] = []
    domain_size = extended_size
    coset_x = GENERATOR
    while len(coefficients) > 1:
        evaluations = evaluate_coset(coefficients, domain_size, coset_x)
        tree = MerkleTree(evaluations)
        transcript.mix(tree.root)
        beta = transcript.draw(P)
        fri_layers.append((evaluations, tree))
        even = coefficients[::2]
        odd = coefficients[1::2]
        if len(odd) < len(even):
            odd = np.pad(odd, (0, 1))
        coefficients = (even + U64(beta) * odd) % U64(P)
        nonzero = np.flatnonzero(coefficients)
        coefficients = coefficients[: nonzero[-1] + 1].copy() if len(nonzero) else np.zeros(1, dtype=np.uint64)
        coset_x = coset_x * coset_x % P
        domain_size //= 2

    last = int(coefficients[0])
    transcript.mix(last)
    query_index = transcript.draw(extended_size)
    query = {
        "index": query_index,
        "trace": row_opening(trace, trace_tree, query_index),
        "trace_next": row_opening(trace, trace_tree, (query_index + BLOWUP) % extended_size),
        "fixed": row_opening(fixed, fixed_tree, query_index),
        "fri": [],
    }
    index = query_index
    for evaluations, tree in fri_layers:
        layer_size = len(evaluations)
        a = index % layer_size
        b = (a + layer_size // 2) % layer_size
        query["fri"].append({
            "a": row_opening(evaluations.reshape(-1, 1), tree, a),
            "b": row_opening(evaluations.reshape(-1, 1), tree, b),
        })

    proof = {
        "version": 1,
        "field_modulus": P,
        "trace_size": trace_size,
        "blowup": BLOWUP,
        "message": message.hex(),
        "signer_indices": list(indices),
        "fixed_root": fixed_tree.root.hex(),
        "trace_root": trace_tree.root.hex(),
        "fri_roots": [tree.root.hex() for _, tree in fri_layers],
        "last": last,
        "query": query,
    }
    output.write_text(json.dumps(proof, separators=(",", ":")) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    setup_parser = sub.add_parser("setup")
    setup_parser.add_argument("--participants", type=int, required=True)
    setup_parser.add_argument("--threshold", type=int, required=True)
    setup_parser.add_argument("--out", type=Path, required=True)
    sign_parser = sub.add_parser("sign-selected")
    sign_parser.add_argument("--directory", type=Path, required=True)
    sign_parser.add_argument("--indices", required=True)
    sign_parser.add_argument("--message", required=True)
    prove_parser = sub.add_parser("prove")
    prove_parser.add_argument("--directory", type=Path, required=True)
    prove_parser.add_argument("--indices", required=True)
    prove_parser.add_argument("--message", required=True)
    prove_parser.add_argument("--out", type=Path, required=True)
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--policy", type=Path, required=True)
    verify_parser.add_argument("--proof", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "setup":
        setup(args.participants, args.threshold, args.out)
    elif args.command == "sign-selected":
        sign_selected(args.directory, [int(value) for value in args.indices.split(",")], bytes.fromhex(args.message))
    elif args.command == "prove":
        prove(args.directory, [int(value) for value in args.indices.split(",")], bytes.fromhex(args.message), args.out)
    else:
        policy_file = json.loads(args.policy.read_text())
        proof = json.loads(args.proof.read_text())
        expected = fixed_commitment_root(
            policy_file["threshold"], bytes.fromhex(proof["message"])
        )
        if (
            len(proof.get("signer_indices", ())) != policy_file["threshold"]
            or not protocol.verify_proof(policy_file["public_keys"], proof, expected)
        ):
            raise SystemExit("invalid proof")
        print("valid")


if __name__ == "__main__":
    main()
