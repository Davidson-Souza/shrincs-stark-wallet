from __future__ import annotations

import argparse
import json
from pathlib import Path

from protocol import (
    BLOWUP,
    CAPACITY,
    FIXED_COLUMNS,
    GENERATOR,
    MDS,
    P,
    ROOT_IV,
    TRACE_COLUMNS,
    Transcript,
    fixed_commitment_root as reference_fixed_commitment_root,
    policy_layers,
)

TRACE_SIZE = 2**14
EXTENDED_SIZE = TRACE_SIZE * BLOWUP
FRI_LAYERS = 17
DOMAIN_ROOT = pow(GENERATOR, (P - 1) // EXTENDED_SIZE, P)


def tuple_type(name: str, count: int) -> str:
    return "(" + ", ".join([name] * count) + ")"


def tuple_value(values) -> str:
    return "(" + ", ".join(str(value) for value in values) + ")"



def exact_path_type(depth: int) -> str:
    return "u256" if depth == 1 else tuple_type("u256", depth)


def exact_path_value(values: list[str]) -> str:
    encoded = [str(int(value, 16)) for value in values]
    return encoded[0] if len(encoded) == 1 else tuple_value(encoded)


def merkle_function(depth: int) -> str:
    lines = [
        f"fn merkle_verify_{depth}(leaf: u256, path: u32, proof: {exact_path_type(depth)}, root: u256) {{"
    ]
    if depth == 1:
        siblings = ["proof"]
    else:
        siblings = [f"p{i}" for i in range(depth)]
        lines.append(f"    let ({', '.join(siblings)}): {exact_path_type(depth)} = proof;")
    lines.append("    let acc: MerkleAcc = (leaf, path);")
    lines.extend(f"    let acc: MerkleAcc = merkle_step({sibling}, acc);" for sibling in siblings)
    lines += ["    let (computed, _): MerkleAcc = acc;", "    assert!(jet::eq_256(computed, root));", "}"]
    return "\n".join(lines)


def opening_value(opening: dict) -> tuple[int, list[str]]:
    values = opening["values"]
    if len(values) != 1:
        raise ValueError("FRI opening must contain one field element")
    return values[0], opening["path"]


def add_residual(lines: list[str], expression: str, index: int) -> None:
    lines.append(f"    let residual_{index}: u32 = {expression};")


def gated(flag: str, residual: str) -> tuple[str, str]:
    return flag, residual


def sub(a: str, b: str) -> str:
    return f"sub_mod({a}, {b})"


def sum_mod(values: list[str]) -> str:
    if not values:
        return "0"
    value = values[0]
    for item in values[1:]:
        value = f"add_mod({value}, {item})"
    return value


def mul(a: str, b: str) -> str:
    return f"mul_mod({a}, {b})"


def constraint_function(committed_policy_root) -> str:
    fixed_names = [
        "member_init", "perm", "member_path", "member_final", "rehash", "acc_phase",
        "new_chain", "switch_signer", "final_phase", "idle",
        "c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7", "level_weight",
    ]
    current_names = (
        [f"s{i}" for i in range(8)]
        + [f"r{i}" for i in range(8)]
        + [f"t{i}" for i in range(8)]
        + ["index", "path_acc", "direction"]
        + [f"d{i}" for i in range(7)]
    )
    next_names = (
        [f"n{i}" for i in range(8)]
        + [f"nr{i}" for i in range(8)]
        + [f"nt{i}" for i in range(8)]
        + ["next_index", "next_path_acc", "next_direction"]
        + [f"nd{i}" for i in range(7)]
    )
    lines = [
        "fn composition_numerator(current: TraceRow, next: TraceRow, fixed: FixedRow, alpha: u32) -> u32 {",
        f"    let ({', '.join(current_names)}): TraceRow = current;",
        f"    let ({', '.join(next_names)}): TraceRow = next;",
        f"    let ({', '.join(fixed_names)}): FixedRow = fixed;",
    ]
    residuals: list[tuple[str, str]] = []
    state = [f"s{i}" for i in range(8)]
    nxt = [f"n{i}" for i in range(8)]
    root = [f"r{i}" for i in range(8)]
    next_root = [f"nr{i}" for i in range(8)]
    target = [f"t{i}" for i in range(8)]
    next_target = [f"nt{i}" for i in range(8)]
    delta = [f"d{i}" for i in range(7)]
    next_delta = [f"nd{i}" for i in range(7)]

    residuals += [gated("member_init", sub(state[i], target[i])) for i in range(8)]
    residuals.append(gated("member_init", "path_acc"))
    residuals += [
        gated("member_init", sub(next_names[i], current_names[i])) for i in range(TRACE_COLUMNS)
    ]

    for i in range(8):
        lines.append(f"    let x{i}: u32 = add_mod(s{i}, c{i});")
        lines.append(f"    let x{i}_2: u32 = mul_mod(x{i}, x{i});")
        lines.append(f"    let x{i}_4: u32 = mul_mod(x{i}_2, x{i}_2);")
        lines.append(f"    let x{i}_5: u32 = mul_mod(x{i}_4, x{i});")
    for i in range(8):
        terms = [mul(str(MDS[i][j]), f"x{j}_5") for j in range(8)]
        residuals.append(gated("perm", sub(nxt[i], sum_mod(terms))))
    residuals += [
        gated("perm", sub(next_names[i], current_names[i])) for i in range(8, TRACE_COLUMNS)
    ]

    residuals.append(gated("member_path", mul("next_direction", sub("next_direction", "1"))))
    residuals += [
        gated(
            "member_path",
            sub(
                nxt[i],
                sum_mod([
                    mul(sub("1", "next_direction"), state[i]),
                    mul("next_direction", next_root[i]),
                ]),
            ),
        )
        for i in range(4)
    ]
    residuals += [
        gated(
            "member_path",
            sub(
                nxt[i + 4],
                sum_mod([
                    mul(sub("1", "next_direction"), next_root[i]),
                    mul("next_direction", state[i]),
                ]),
            ),
        )
        for i in range(4)
    ]
    residuals += [
        gated("member_path", next_root[i + 4]) for i in range(4)
    ]
    residuals += [
        gated("member_path", sub(next_target[i], target[i])) for i in range(8)
    ]
    residuals.append(gated("member_path", sub("next_index", "index")))
    residuals.append(
        gated(
            "member_path",
            sub("next_path_acc", sum_mod(["path_acc", mul("next_direction", "level_weight")])),
        )
    )
    residuals += [
        gated("member_path", sub(next_delta[i], delta[i])) for i in range(7)
    ]

    residuals += [
        gated("member_final", sub(state[i], str(committed_policy_root[i]))) for i in range(4)
    ]
    residuals.append(gated("member_final", sub("path_acc", "index")))
    residuals += [
        gated("member_final", sub(nxt[i + 4], str(CAPACITY[i]))) for i in range(4)
    ]
    residuals += [
        gated("member_final", sub(next_root[i], str(ROOT_IV[i]))) for i in range(8)
    ]
    residuals += [
        gated("member_final", sub(next_target[i], target[i])) for i in range(8)
    ]
    residuals += [
        gated("member_final", sub("next_index", "index")),
        gated("member_final", sub("next_path_acc", "path_acc")),
    ]
    residuals += [
        gated("member_final", sub(next_delta[i], delta[i])) for i in range(7)
    ]

    residuals += [gated("rehash", sub(nxt[i], state[i])) for i in range(4)]
    residuals += [gated("rehash", sub(nxt[i + 4], str(CAPACITY[i]))) for i in range(4)]
    residuals += [gated("rehash", sub(next_root[i], root[i])) for i in range(8)]
    residuals += [
        gated("rehash", sub(next_names[i], current_names[i])) for i in range(16, TRACE_COLUMNS)
    ]

    residuals += [
        gated("acc_phase", sub(nxt[i], sum_mod([root[i], state[i]]))) for i in range(4)
    ]
    residuals += [gated("acc_phase", sub(nxt[i], root[i])) for i in range(4, 8)]
    residuals += [gated("acc_phase", sub(next_root[i], root[i])) for i in range(8)]
    residuals += [
        gated("acc_phase", sub(next_names[i], current_names[i]))
        for i in range(16, TRACE_COLUMNS)
    ]

    residuals += [gated("new_chain", sub(nxt[i + 4], str(CAPACITY[i]))) for i in range(4)]
    residuals += [gated("new_chain", sub(next_root[i], state[i])) for i in range(8)]
    residuals += [
        gated("new_chain", sub(next_names[i], current_names[i]))
        for i in range(16, TRACE_COLUMNS)
    ]

    residuals += [gated("switch_signer", sub(state[i], target[i])) for i in range(8)]
    residuals += [
        gated("switch_signer", sub(nxt[i], next_target[i])) for i in range(8)
    ]
    residuals.append(gated("switch_signer", "next_path_acc"))
    residuals += [
        gated("switch_signer", mul(delta[i], sub(delta[i], "1")))
        for i in range(7)
    ]
    delta_value = sum_mod(
        ["index", "1"] + [mul(str(1 << i), delta[i]) for i in range(7)]
    )
    residuals.append(gated("switch_signer", sub("next_index", delta_value)))
    residuals += [
        gated("switch_signer", next_root[i + 4]) for i in range(4)
    ]
    residuals.append(
        gated("switch_signer", mul("next_direction", sub("next_direction", "1")))
    )

    residuals += [gated("final_phase", sub(state[i], target[i])) for i in range(8)]
    residuals += [
        gated("idle", sub(next_names[i], current_names[i])) for i in range(TRACE_COLUMNS)
    ]

    for i, (_, residual) in enumerate(residuals):
        add_residual(lines, residual, i)
    groups: list[tuple[str, list[int]]] = []
    for i, (flag, _) in enumerate(residuals):
        if not groups or groups[-1][0] != flag:
            groups.append((flag, []))
        groups[-1][1].append(i)
    for group_index, (flag, indices) in enumerate(groups):
        lines.append(f"    let group_{group_index}: u32 = 0;")
        for i in reversed(indices):
            lines.append(
                f"    let group_{group_index}: u32 = add_mod(residual_{i}, mul_mod(alpha, group_{group_index}));"
            )
        lines.append(f"    let group_{group_index}: u32 = mul_mod({flag}, group_{group_index});")
    lines.append("    let acc: u32 = 0;")
    for group_index in reversed(range(len(groups))):
        lines.append(f"    let acc: u32 = add_mod(group_{group_index}, mul_mod(alpha, acc));")
    lines += ["    acc", "}"]
    if len(residuals) != 311:
        raise AssertionError(f"unexpected residual count {len(residuals)}")
    return "\n".join(lines)


def source(policy_file: dict, proof: dict) -> str:
    policy = policy_file["public_keys"]
    signer_indices = proof["signer_indices"]
    if len(signer_indices) != policy_file["threshold"] or len(set(signer_indices)) != len(signer_indices) or any(index < 0 or index >= len(policy) for index in signer_indices):
        raise ValueError("proof must name threshold distinct policy members")
    try:
        from large_prover import fixed_commitment_root as compute_fixed_commitment_root
    except ImportError:
        compute_fixed_commitment_root = reference_fixed_commitment_root

    expected_fixed_root = compute_fixed_commitment_root(
        policy_file["threshold"], bytes.fromhex(proof["message"])
    ).hex()
    if proof["fixed_root"] != expected_fixed_root:
        raise ValueError("proof fixed commitment does not match the policy threshold and message")
    trace_row_type = tuple_type("u32", TRACE_COLUMNS)
    hash_trace = "\n".join(
        [
            "fn hash_trace_row(row: TraceRow) -> u256 {",
            "    let (" + ", ".join(f"v{i}" for i in range(TRACE_COLUMNS)) + "): TraceRow = row;",
            "    let ctx: Ctx8 = jet::sha_256_ctx_8_init();",
        ]
        + [f"    let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, v{i});" for i in range(TRACE_COLUMNS)]
        + ["    jet::sha_256_ctx_8_finalize(ctx)", "}"]
    )
    hash_fixed = "\n".join(
        [
            "fn hash_fixed_row(row: FixedRow) -> u256 {",
            "    let (" + ", ".join(f"v{i}" for i in range(FIXED_COLUMNS)) + "): " + tuple_type("u32", FIXED_COLUMNS) + " = row;",
            "    let ctx: Ctx8 = jet::sha_256_ctx_8_init();",
        ]
        + [f"    let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, v{i});" for i in range(FIXED_COLUMNS)]
        + ["    jet::sha_256_ctx_8_finalize(ctx)", "}"]
    )
    merkle_functions = "\n\n".join(merkle_function(depth) for depth in range(1, FRI_LAYERS + 1))
    commitment_steps = []
    for i in range(FRI_LAYERS):
        commitment_steps += [
            f"    let root{i}: u256 = witness::FRI_ROOT_{i};",
            f"    let state: ChannelState = channel_mix_256(state, root{i});",
            f"    let (state, beta{i}): (ChannelState, u32) = channel_draw_32(state, FIELD_MODULUS);",
        ]
    fri_steps = []
    for i in range(FRI_LAYERS):
        depth = FRI_LAYERS - i
        fri_steps += [
            f"    let a{i}: u32 = witness::FRI_A_{i};",
            f"    let path_a{i}: {exact_path_type(depth)} = witness::FRI_PATH_A_{i};",
            f"    let b{i}: u32 = witness::FRI_B_{i};",
            f"    let path_b{i}: {exact_path_type(depth)} = witness::FRI_PATH_B_{i};",
            f"    assert!(jet::eq_32(cp, a{i}));",
            "    let (_, path_a): (bool, u32) = jet::add_32(jet::modulo_32(idx, domain_size), domain_size);",
            "    let (_, sibling_index): (bool, u32) = jet::add_32(idx, jet::divide_32(domain_size, 2));",
            "    let (_, path_b): (bool, u32) = jet::add_32(jet::modulo_32(sibling_index, domain_size), domain_size);",
            f"    merkle_verify_{depth}(sha256_32(a{i}), path_a, path_a{i}, root{i});",
            f"    merkle_verify_{depth}(sha256_32(b{i}), path_b, path_b{i}, root{i});",
            f"    let even: u32 = mul_mod(add_mod(a{i}, b{i}), 1610612737);",
            f"    let odd: u32 = mul_mod(mul_mod(sub_mod(a{i}, b{i}), 1610612737), x_inv);",
            f"    let cp: u32 = add_mod(even, mul_mod(beta{i}, odd));",
            "    let x: u32 = mul_mod(x, x);",
            "    let x_inv: u32 = mul_mod(x_inv, x_inv);",
            "    let domain_size: u32 = jet::divide_32(domain_size, 2);",
        ]
    source_text = f'''simc "0.8.0";

#include "sha256.simf"
#include "channel.simf"
#include "field.simf"

#define FIELD_MODULUS {P}
#define TRACE_SIZE {TRACE_SIZE}
#define EXTENDED_SIZE {EXTENDED_SIZE}
#define DOMAIN_ROOT {DOMAIN_ROOT}
#define EXPECTED_OUTPUTS_HASH 0x{proof["message"]}
#define FIXED_ROOT 0x{proof["fixed_root"]}

type TraceRow = {trace_row_type};
type FixedRow = {tuple_type("u32", FIXED_COLUMNS)};
type MerkleAcc = (u256, u32);

{hash_trace}

{hash_fixed}

fn merkle_step(sibling: u256, acc: MerkleAcc) -> MerkleAcc {{
    let (current, path): MerkleAcc = acc;
    let next: u256 = match jet::divides_32(2, path) {{
        false => sha256_pair(sibling, current),
        true => sha256_pair(current, sibling),
    }};
    (next, jet::divide_32(path, 2))
}}

{merkle_functions}

{constraint_function(policy_layers(policy)[-1][0])}


fn main() {{
    let trace_root: u256 = witness::TRACE_ROOT;
    let current: TraceRow = witness::TRACE_ROW;
    let next: TraceRow = witness::TRACE_NEXT_ROW;
    let fixed: FixedRow = witness::FIXED_ROW;
    let trace_path: {exact_path_type(FRI_LAYERS)} = witness::TRACE_PATH;
    let next_path: {exact_path_type(FRI_LAYERS)} = witness::TRACE_NEXT_PATH;
    let fixed_path: {exact_path_type(FRI_LAYERS)} = witness::FIXED_PATH;
    let last: u32 = witness::FRI_LAST;
    let cp: u32 = witness::FRI_COMPOSITION;
    let x_inv: u32 = witness::DOMAIN_X_INVERSE;

    let state: ChannelState = sha256(EXPECTED_OUTPUTS_HASH);
    let state: ChannelState = channel_mix_256(state, FIXED_ROOT);
    let state: ChannelState = channel_mix_256(state, trace_root);
    let (state, alpha): (ChannelState, u32) = channel_draw_32(state, FIELD_MODULUS);
{chr(10).join(commitment_steps)}
    let state: ChannelState = channel_mix_32(state, last);
    let (_, idx): (ChannelState, u32) = channel_draw_32(state, EXTENDED_SIZE);

    let (_, trace_auth): (bool, u32) = jet::add_32(idx, EXTENDED_SIZE);
    merkle_verify_{FRI_LAYERS}(hash_trace_row(current), trace_auth, trace_path, trace_root);
    let (_, next_idx): (bool, u32) = jet::add_32(idx, {BLOWUP});
    let next_idx: u32 = jet::modulo_32(next_idx, EXTENDED_SIZE);
    let (_, next_auth): (bool, u32) = jet::add_32(next_idx, EXTENDED_SIZE);
    merkle_verify_{FRI_LAYERS}(hash_trace_row(next), next_auth, next_path, trace_root);
    let (_, fixed_auth): (bool, u32) = jet::add_32(idx, EXTENDED_SIZE);
    merkle_verify_{FRI_LAYERS}(hash_fixed_row(fixed), fixed_auth, fixed_path, FIXED_ROOT);

    let numerator: u32 = composition_numerator(current, next, fixed, alpha);
    let x: u32 = mul_mod({GENERATOR}, exp_mod(DOMAIN_ROOT, idx));
    assert!(jet::eq_32(mul_mod(x, x_inv), 1));
    let denominator: u32 = sub_mod(exp_mod(x, TRACE_SIZE), 1);
    assert!(jet::eq_32(mul_mod(cp, denominator), numerator));
    let domain_size: u32 = EXTENDED_SIZE;
{chr(10).join(fri_steps)}
    assert!(jet::eq_32(cp, last));
    assert!(jet::eq_32(domain_size, 1));

    assert!(jet::eq_256(jet::outputs_hash(), EXPECTED_OUTPUTS_HASH));
}}
'''
    return source_text


def witness(proof: dict) -> dict:
    query = proof["query"]
    transcript = Transcript(bytes.fromhex(proof["message"]))
    transcript.mix(bytes.fromhex(proof["fixed_root"]))
    transcript.mix(bytes.fromhex(proof["trace_root"]))
    transcript.draw(P)
    for root in proof["fri_roots"]:
        transcript.mix(bytes.fromhex(root))
        transcript.draw(P)
    transcript.mix(proof["last"])
    index = transcript.draw(EXTENDED_SIZE)
    root_m = pow(GENERATOR, (P - 1) // EXTENDED_SIZE, P)
    x = GENERATOR * pow(root_m, index, P) % P
    result = {
        "TRACE_ROOT": {"type": "u256", "value": str(int(proof["trace_root"], 16))},
        "TRACE_ROW": {"type": tuple_type("u32", TRACE_COLUMNS), "value": tuple_value(query["trace"]["values"])},
        "TRACE_NEXT_ROW": {"type": tuple_type("u32", TRACE_COLUMNS), "value": tuple_value(query["trace_next"]["values"])},
        "FIXED_ROW": {"type": tuple_type("u32", FIXED_COLUMNS), "value": tuple_value(query["fixed"]["values"])},
        "TRACE_PATH": {"type": exact_path_type(FRI_LAYERS), "value": exact_path_value(query["trace"]["path"])},
        "TRACE_NEXT_PATH": {"type": exact_path_type(FRI_LAYERS), "value": exact_path_value(query["trace_next"]["path"])},
        "FIXED_PATH": {"type": exact_path_type(FRI_LAYERS), "value": exact_path_value(query["fixed"]["path"])},
        "FRI_LAST": {"type": "u32", "value": str(proof["last"])},
        "FRI_COMPOSITION": {"type": "u32", "value": str(query["fri"][0]["a"]["values"][0])},
        "DOMAIN_X_INVERSE": {"type": "u32", "value": str(pow(x, P - 2, P))},
    }
    for i, (root, opening) in enumerate(zip(proof["fri_roots"], query["fri"])):
        depth = FRI_LAYERS - i
        a, path_a = opening_value(opening["a"])
        b, path_b = opening_value(opening["b"])
        if len(path_a) != depth or len(path_b) != depth:
            raise ValueError(f"invalid FRI path depth at layer {i}")
        result[f"FRI_ROOT_{i}"] = {"type": "u256", "value": str(int(root, 16))}
        result[f"FRI_A_{i}"] = {"type": "u32", "value": str(a)}
        result[f"FRI_PATH_A_{i}"] = {"type": exact_path_type(depth), "value": exact_path_value(path_a)}
        result[f"FRI_B_{i}"] = {"type": "u32", "value": str(b)}
        result[f"FRI_PATH_B_{i}"] = {"type": exact_path_type(depth), "value": exact_path_value(path_b)}
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True)
    parser.add_argument("--proof", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--witness", required=True)
    args = parser.parse_args()
    policy_file = json.loads(Path(args.policy).read_text())
    proof = json.loads(Path(args.proof).read_text())
    global TRACE_SIZE, EXTENDED_SIZE, FRI_LAYERS, DOMAIN_ROOT
    TRACE_SIZE = proof["trace_size"]
    EXTENDED_SIZE = TRACE_SIZE * BLOWUP
    FRI_LAYERS = EXTENDED_SIZE.bit_length() - 1
    DOMAIN_ROOT = pow(GENERATOR, (P - 1) // EXTENDED_SIZE, P)
    Path(args.source).write_text(source(policy_file, proof))
    Path(args.witness).write_text(json.dumps(witness(proof), indent=2) + "\n")


if __name__ == "__main__":
    main()
