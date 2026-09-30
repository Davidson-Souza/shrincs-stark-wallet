# Create and spend a 2-of-3 SHRINCS multisig

This tutorial uses the experimental M31 WOTS+C/SHRINCS-L STARK verifier in this repository and publishes the resulting Simplicity transaction to the public Simplicity Signet explorer.

The onchain construction is demonstration-grade. It uses one FRI query and public signer identities. Signature chain values and preimages remain in the STARK witness. Do not use it with real funds.

## Two CLI workflows in this repository

The repository contains two related but distinct workflows:

- `ssw setup/create/sign/aggregate/verify` handles native SHA-based SHRINCS authorization bundles offchain.
- `contracts/shrincs-stark/scripts/protocol.py` creates the ZK-friendly WOTS+C keys, shares, and STARK proof consumed by the onchain verifier.

An `ssw` native quorum bundle is not an input to the current STARK verifier. The onchain walkthrough therefore uses the Python protocol CLI to create the quorum proof, then `ssw contract-address` and `ssw spend-proof` to create the Bitcoin transactions.

## 1. Connect to Simplicity Signet

Use the Bitcoin Inquisition build linked from the official instructions:

- Node setup: <https://signet.simplicity-lang.org/connect>
- Faucet: <https://signet.simplicity-lang.org/faucet>
- Explorer: <https://signet.simplicity-lang.org/explorer/>

Add this network configuration to `bitcoin.conf`:

```ini
[signet]
signet=1
signetchallenge=00147cb2a6ddb8125278166fb414ed11b9f78a33ebe6
addnode=signet.simplicity-lang.org:38333
```

Start the node and wait for synchronization:

```sh
bitcoind -signet -daemon
bitcoin-cli -signet getblockchaininfo
```

Create and fund a wallet if needed:

```sh
bitcoin-cli -signet createwallet shrincs-demo
bitcoin-cli -signet -rpcwallet=shrincs-demo getnewaddress
```

Request test coins from the faucet. Never use standard Signet or mainnet coins: this is a custom signet identified by the `signetchallenge` above.

## 2. Build the wallet CLI

From the repository root:

```sh
cargo build --release
export SSW="$PWD/target/release/ssw"
export PROTOCOL="$PWD/contracts/shrincs-stark/scripts/protocol.py"
export FAST_PROTOCOL="$PWD/contracts/shrincs-stark/scripts/large_prover.py"
export GENERATOR="$PWD/contracts/shrincs-stark/scripts/generate_contract.py"
export SIMC="$PWD/.runtime/simplicityhl/target/release/simc"
export BITCOIN_CMR="$PWD/.runtime/bitcoin-cmr"
export BITCOIN_COST="$PWD/.runtime/bitcoin-cost"
```

The last three paths are the experimental compiler and Bitcoin-jet analysis tools used by this repository. They are required when regenerating a contract. The precompiled demo under `contracts/shrincs-stark/artifacts/demo` can be spent without regenerating it.

## 3. Choose the transaction before signing

The proof commits to Bitcoin's `outputs_hash`. The output amount and script cannot be changed after shares are created.

This example funds the contract with 1,000,000 satoshis, pays a 100,000-satoshi fee, and sends the remaining 900,000 satoshis to one P2WPKH address:

```sh
export INPUT_SAT=1000000
export FEE_SAT=100000
export OUTPUT_SAT=900000
export DESTINATION=tb1q0je2dhdczff8s9n0ks2w6yde779r86lxwtrqcu
export DESTINATION_SCRIPT=00147cb2a6ddb8125278166fb414ed11b9f78a33ebe6
```

Confirm the script with your node rather than copying it blindly:

```sh
bitcoin-cli -signet validateaddress "$DESTINATION"
```

For Bitcoin Simplicity, each output script is hashed once before all script hashes are concatenated and hashed again. Compute the one-output commitment:

```sh
export OUTPUTS_HASH=$(python3 - "$OUTPUT_SAT" "$DESTINATION_SCRIPT" <<'PY'
import hashlib
import sys

value = int(sys.argv[1]).to_bytes(8, "big")
script = bytes.fromhex(sys.argv[2])
values_hash = hashlib.sha256(value).digest()
scripts_hash = hashlib.sha256(hashlib.sha256(script).digest()).digest()
print(hashlib.sha256(values_hash + scripts_hash).hexdigest())
PY
)
printf '%s\n' "$OUTPUTS_HASH"
```

For the values above, the result must be:

```text
c5bfb8fe204efe0c4c5b3317c94e74574bb67dff6a1e5020d925b7ada487706c
```

## 4. Create a fresh 2-of-3 policy

`setup` requires a directory that does not already exist:

```sh
export WORK="$PWD/run-2-of-3"
python3 "$PROTOCOL" setup --out "$WORK"
```

The command creates:

```text
run-2-of-3/
├── policy.json
├── signer-0.json
├── signer-1.json
└── signer-2.json
```

Treat every `signer-*.json` as secret key material. Give each signer only its own file. Back it up securely or use disposable keys on Signet.

## 5. Collect two signature shares

This example uses signers 0 and 2:

```sh
python3 "$PROTOCOL" sign \
  --key "$WORK/signer-0.json" \
  --message "$OUTPUTS_HASH" \
  --out "$WORK/share-0.json"

python3 "$PROTOCOL" sign \
  --key "$WORK/signer-2.json" \
  --message "$OUTPUTS_HASH" \
  --out "$WORK/share-2.json"
```

Shares may be created on separate machines. Transfer `policy.json`, the 32-byte output commitment, and the resulting public share files; do not transfer signer secret files.

## 6. Aggregate the quorum into one STARK proof

```sh
python3 "$PROTOCOL" prove \
  --policy "$WORK/policy.json" \
  --indices 0,2 \
  --shares "$WORK/share-0.json" "$WORK/share-2.json" \
  --message "$OUTPUTS_HASH" \
  --out "$WORK/proof.json"

python3 "$PROTOCOL" verify \
  --policy "$WORK/policy.json" \
  --proof "$WORK/proof.json"
```

The second command must print `valid`. The onchain witness contains this single aggregated proof, not two exposed signature blobs.

### Scale the same contract to 64-of-100

The vectorized prover requires NumPy and a C compiler with OpenSSL headers. It keeps the onchain witness to one STARK opening; the 64 WOTS+C shares are not placed directly in the transaction:

```sh
python3 -m venv .runtime/venv
.runtime/venv/bin/pip install numpy
export FAST_PYTHON="$PWD/.runtime/venv/bin/python"
export WORK="$PWD/run-64-of-100"
export INDICES=$(seq -s, 0 63)

"$FAST_PYTHON" "$FAST_PROTOCOL" setup \
  --participants 100 \
  --threshold 64 \
  --out "$WORK"

"$FAST_PYTHON" "$FAST_PROTOCOL" sign-selected \
  --directory "$WORK" \
  --indices "$INDICES" \
  --message "$OUTPUTS_HASH"

"$FAST_PYTHON" "$FAST_PROTOCOL" prove \
  --directory "$WORK" \
  --indices "$INDICES" \
  --message "$OUTPUTS_HASH" \
  --out "$WORK/proof.json"

"$FAST_PYTHON" "$FAST_PROTOCOL" verify \
  --policy "$WORK/policy.json" \
  --proof "$WORK/proof.json"
```

For this larger proof, run the generator in the same virtual environment by replacing `python3 "$GENERATOR"` below with `"$FAST_PYTHON" "$GENERATOR"`.

## 7. Generate and compile the Simplicity verifier

Generate specialized SimplicityHL source and its witness description:

```sh
python3 "$GENERATOR" \
  --policy "$WORK/policy.json" \
  --proof "$WORK/proof.json" \
  --source "$WORK/verifier.main.simf" \
  --witness "$WORK/proof.wit"

cpp -P -I contracts/stark101/src \
  "$WORK/verifier.main.simf" \
  "$WORK/verifier.simf"
```

First validate the proof-only program without transaction introspection:

```sh
sed '/jet::outputs_hash()/d' "$WORK/verifier.simf" > "$WORK/verifier.noenv.simf"
"$SIMC" "$WORK/verifier.noenv.simf" \
  --wit "$WORK/proof.wit" --prune --json \
  > "$WORK/noenv.json"
```

Then compile the transaction-bound program:

```sh
"$SIMC" "$WORK/verifier.simf" \
  --wit "$WORK/proof.wit" --prune --json \
  > "$WORK/compiled.json"

python3 - "$WORK/compiled.json" "$WORK/verifier.program.bin" "$WORK/verifier.witness.bin" <<'PY'
import base64
import json
import pathlib
import sys

compiled = json.loads(pathlib.Path(sys.argv[1]).read_text())
pathlib.Path(sys.argv[2]).write_bytes(base64.b64decode(compiled["program"]))
pathlib.Path(sys.argv[3]).write_bytes(base64.b64decode(compiled["witness"]))
PY
```

The local `simc` used by this experiment permits pruning after the proof-only execution has succeeded even though its dummy Elements environment cannot satisfy Bitcoin's `outputs_hash` jet. A stock SimplicityHL compiler may stop at that environment-dependent assertion. The public Bitcoin node remains the final execution check.

Compute the Bitcoin-compatible CMR. Do not use the compiler's Elements CMR for a Bitcoin contract:

```sh
"$BITCOIN_CMR" "$WORK/verifier.program.bin" > "$WORK/verifier.cmr"
"$BITCOIN_COST" "$WORK/verifier.program.bin"
```

The cost analyzer must finish with `error=0`. Record its `exact_cost_WU` value.

## 8. Derive and fund the contract address

```sh
export CONTRACT_ADDRESS=$(
  "$SSW" contract-address \
    --cmr "$WORK/verifier.cmr" \
    --network signet
)
printf '%s\n' "$CONTRACT_ADDRESS"
```

Fund it with exactly 0.01 signet BTC:

```sh
export FUNDING_TXID=$(
  bitcoin-cli -signet -rpcwallet=shrincs-demo \
    sendtoaddress "$CONTRACT_ADDRESS" 0.01
)
bitcoin-cli -signet getrawtransaction "$FUNDING_TXID" true
```

Find the `vout` whose address equals `$CONTRACT_ADDRESS` and record it:

```sh
export FUNDING_VOUT=1
export OUTPOINT="$FUNDING_TXID:$FUNDING_VOUT"
```

Do not assume the output index is always `1`; inspect the transaction.

## 9. Calculate the required Simplicity padding

Simplicity's execution budget is the serialized size of the current input's witness stack plus 50. If the verifier costs more than its natural witness budget, one leading all-zero padding element must supply the exact deficit.

Use the `exact_cost_WU` printed by `bitcoin-cost`:

```sh
export EXECUTION_COST=88853
export PADDING_BYTES=$(python3 - \
  "$EXECUTION_COST" \
  "$WORK/verifier.program.bin" \
  "$WORK/verifier.witness.bin" <<'PY'
import pathlib
import sys

cost = int(sys.argv[1])
program = pathlib.Path(sys.argv[2]).stat().st_size
witness = pathlib.Path(sys.argv[3]).stat().st_size

def compact_size(n):
    if n < 253:
        return 1
    if n <= 0xffff:
        return 3
    if n <= 0xffffffff:
        return 5
    return 9

# Four natural stack elements: witness, program, 32-byte CMR, 33-byte control block.
base = (
    1
    + compact_size(witness) + witness
    + compact_size(program) + program
    + 1 + 32
    + 1 + 33
    + 50
)

if base >= cost:
    print(0)
else:
    for padding in range(1, cost - base + 10):
        if base + compact_size(padding) + padding >= cost:
            print(padding)
            break
PY
)
printf '%s\n' "$PADDING_BYTES"
```

For the published signers-0-and-2 demo, the exact padding is `36944` bytes. Padding is a protocol-defined leading zero stack element—not a Taproot annex. The public node rejects annex-based padding as nonstandard.

## 10. Build, validate, and publish the spend

The chosen input, fee, destination, and output amount must reproduce the output commitment from step 3:

```sh
"$SSW" spend-proof \
  --cmr "$WORK/verifier.cmr" \
  --program "$WORK/verifier.program.bin" \
  --witness "$WORK/verifier.witness.bin" \
  --outpoint "$OUTPOINT" \
  --input-value-sat "$INPUT_SAT" \
  --destination "$DESTINATION" \
  --fee-sat "$FEE_SAT" \
  --network signet \
  --padding-bytes "$PADDING_BYTES" \
  --out "$WORK/spend.hex"
```

Validate against your node:

```sh
bitcoin-cli -signet testmempoolaccept \
  "[\"$(cat "$WORK/spend.hex")\"]"
```

Require `"allowed": true`. A local node configured with `acceptnonstdtxn=1` is not sufficient evidence of public relay acceptance. Submit to the public Simplicity Signet backend as the final policy check:

```sh
export SPEND_TXID=$(
  curl --fail --show-error \
    --header 'Content-Type: text/plain' \
    --data-binary @"$WORK/spend.hex" \
    https://signet.simplicity-lang.org/explorer/api/tx
)
printf '%s\n' "$SPEND_TXID"
```

Open:

```text
https://signet.simplicity-lang.org/explorer/tx/<SPEND_TXID>
```

The confirmed reference transaction for this workflow is:

<https://signet.simplicity-lang.org/explorer/tx/5f61c51a3db0c27300727772b00769d64f919e3797d43f21b9b248c10a956a6b>

The confirmed 64-of-100 transaction produced by the accelerated path is:

<https://signet.simplicity-lang.org/explorer/tx/8d15cf2a2d6d5943c7caec5dc4dfb9b179929374704ce94faf53dffd00af9d0d>

## Native SHRINCS authorization bundles

The Rust CLI can independently create and verify a conventional offchain 2-of-3 authorization bundle:

```sh
"$SSW" setup \
  --participants 3 \
  --threshold 2 \
  --out native-2-of-3

"$SSW" create \
  --policy native-2-of-3/policy.json \
  --network signet \
  --unsigned-tx unsigned.hex \
  --sighash <32-byte-hex-sighash> \
  --input-index 0 \
  --out native-2-of-3/request.json

"$SSW" sign \
  --policy native-2-of-3/policy.json \
  --request native-2-of-3/request.json \
  --key native-2-of-3/signer-1.json \
  --mode stateful \
  --out native-2-of-3/share-1.json

"$SSW" sign \
  --policy native-2-of-3/policy.json \
  --request native-2-of-3/request.json \
  --key native-2-of-3/signer-3.json \
  --mode stateful \
  --out native-2-of-3/share-3.json

"$SSW" aggregate \
  --policy native-2-of-3/policy.json \
  --request native-2-of-3/request.json \
  --shares native-2-of-3/share-1.json native-2-of-3/share-3.json \
  --out native-2-of-3/quorum.json

"$SSW" verify \
  --policy native-2-of-3/policy.json \
  --request native-2-of-3/request.json \
  --quorum native-2-of-3/quorum.json
```

Stateful signing updates the signer key file before releasing the share so one-time state is not accidentally reused. This native quorum is useful for application authorization and testing, but the current onchain STARK generator does not yet consume `quorum.json`.

## Common failures

- `bad-witness-nonstandard`: padding was encoded as an annex or another oversized generic witness element. Rebuild with the current `ssw spend-proof`.
- `Program's execution cost could exceed budget`: padding is too short or absent.
- `Simplicity padding is non-minimal`: padding is too long. Recalculate it from `exact_cost_WU` and the compiled file sizes.
- `Assertion failed inside jet`: the proof, policy constants, or transaction output does not match the compiled contract.
- `Witness program hash mismatch`: the CMR, program, or Taproot control block belongs to a different contract.
- Explorer returns `404`: the public node has not accepted the transaction. POST it to `/explorer/api/tx` and read the returned policy error.
