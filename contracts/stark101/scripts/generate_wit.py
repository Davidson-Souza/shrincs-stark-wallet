import json
import sys

with open(sys.argv[1], 'r') as f:
    proof = json.load(f)

def format_merkle_proof(proof):
    assert len(proof) <= 16
    padded = proof + [0] * (16 - len(proof))
    return f"[{', '.join(map(str, padded))}]"

def format_fri_layer(layer):
    return f"(({layer[0]}, {layer[1]}, {layer[2]}, {format_merkle_proof(layer[3])}, {layer[4]}, {format_merkle_proof(layer[5])}))"

p_evals = ", ".join(f"({x[0]}, {format_merkle_proof(x[1])})" for x in proof["evals"])
fri_layers = ", ".join(format_fri_layer(layer) for layer in proof["fri_layers"])

res = {
    "P_MT_ROOT": {
        "value": str(proof["p_mt_root"]),
        "type": "u256",
    },
    "P_EVALS": {
        "value": f"({p_evals})",
        "type":  "((u32, [u256; 16]), (u32, [u256; 16]), (u32, [u256; 16]))",
    },
    "FRI_LAYERS": {
        "value": f"list![{fri_layers}]",
        "type": "List<(u256, u32, u32, [u256; 16], u32, [u256; 16]), 16>",
    },
    "FRI_LAST_LAYER": {
        "value": str(proof["fri_last_layer"]),
        "type": "u32",
    },
}

print(json.dumps(res, indent=4))
