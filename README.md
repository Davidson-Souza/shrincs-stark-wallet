# SHRINCS STARK Wallet

Experimental threshold authorization for Bitcoin Simplicity. The repository combines:

- a Rust CLI (`ssw`) for offchain SHRINCS quorum bundles and Simplicity transaction construction;
- an M31 WOTS+C/STARK protocol whose verifier is compiled to Simplicity;
- public Simplicity Signet deployments, including a confirmed 64-of-100 spend.

> **Research software only.** The STARK currently uses one FRI query and is demonstration-grade. Signer identities are public, secret-key JSON files are sensitive, and none of this code should secure real funds.

## Confirmed demonstrations

| Policy | Transaction | Status |
| --- | --- | --- |
| 2-of-3 | [`5f61c51a3db0c27300727772b00769d64f919e3797d43f21b9b248c10a956a6b`](https://signet.simplicity-lang.org/explorer/tx/5f61c51a3db0c27300727772b00769d64f919e3797d43f21b9b248c10a956a6b) | Confirmed |
| 64-of-100 | [`8d15cf2a2d6d5943c7caec5dc4dfb9b179929374704ce94faf53dffd00af9d0d`](https://signet.simplicity-lang.org/explorer/tx/8d15cf2a2d6d5943c7caec5dc4dfb9b179929374704ce94faf53dffd00af9d0d) | Confirmed in block 2215 |

The 64-of-100 transaction spends from:

```text
Contract address: tb1pz67ec2ufufp6y7kku79j6l063l4zppp3v3snn389uhr39t9czqpswnxfk0
CMR:              d2b1dd409216c7d81df79cd38ac07f998b0a54c75e7f919ea66e19121b9fe736
Funding txid:     2aeae7b61cdb437455307ffbc5a04a9158714f93d0dc36ae70753db2839d029e
```

## How it works

The onchain workflow commits to the transaction outputs before signing:

1. Each selected member produces a WOTS+C share over Bitcoin's `outputs_hash`.
2. The prover constructs a trace that verifies every WOTS+C chain.
3. Seven-level Merkle paths prove that each WOTS+C public key belongs to the 100-member policy.
4. Index transition constraints require 64 strictly ascending, distinct policy members.
5. A STARK compresses the complete trace into one queried opening.
6. The Simplicity program verifies the AIR composition, Merkle openings, FRI folds, policy root, threshold-specific fixed commitment, and `jet::outputs_hash()`.
7. `ssw spend-proof` builds the Taproot script-path spend with protocol-defined leading zero padding for the Simplicity execution budget.

The policy root is compiled into the program. The trace commitment is witness data, so the verifier is not specialized to the particular 64-member subset used to produce a proof.

## Two separate quorum workflows

The repository intentionally contains two related but incompatible formats:

### Native offchain bundles

`ssw setup/create/sign/aggregate/verify` creates and verifies conventional SHA-based SHRINCS quorum bundles. These bundles are useful independently, but they are **not** inputs to the STARK verifier.

### Onchain STARK authorization

`contracts/shrincs-stark/scripts/protocol.py` and `large_prover.py` implement the ZK-friendly M31 WOTS+C protocol consumed by the generated Simplicity verifier.

## Build the CLI

Requirements:

- Rust toolchain with Cargo;
- Python 3 for the STARK scripts;
- NumPy, a C compiler, and OpenSSL development headers for the accelerated large-quorum prover;
- a Bitcoin Inquisition node connected to Simplicity Signet for transaction validation and relay;
- the experimental SimplicityHL compiler and Bitcoin CMR/cost tools when regenerating contracts.

Build and inspect the CLI:

```sh
cargo build --release
./target/release/ssw --help
```

Run the test suite:

```sh
cargo test
```

## Native quorum example

Set `UNSIGNED_TX` to the transaction file and `SIGHASH` to its 32-byte hexadecimal signing digest:

```sh
./target/release/ssw setup \
  --participants 3 \
  --threshold 2 \
  --out native-2-of-3

./target/release/ssw create \
  --policy native-2-of-3/policy.json \
  --network signet \
  --unsigned-tx "$UNSIGNED_TX" \
  --sighash "$SIGHASH" \
  --input-index 0 \
  --out native-2-of-3/request.json
```

Continue with `ssw sign`, `ssw aggregate`, and `ssw verify`. Stateful signing is the default; `--mode stateless` selects recovery signing.

## Accelerated 64-of-100 proof

Create an isolated Python environment:

```sh
python3 -m venv .runtime/venv
.runtime/venv/bin/pip install numpy
export PYTHON="$PWD/.runtime/venv/bin/python"
export PROVER="$PWD/contracts/shrincs-stark/scripts/large_prover.py"
export WORK="$PWD/run-64-of-100"
export INDICES=$(seq -s, 0 63)
export OUTPUTS_HASH=c5bfb8fe204efe0c4c5b3317c94e74574bb67dff6a1e5020d925b7ada487706c
```

Generate the policy and selected shares:

```sh
"$PYTHON" "$PROVER" setup \
  --participants 100 \
  --threshold 64 \
  --out "$WORK"

"$PYTHON" "$PROVER" sign-selected \
  --directory "$WORK" \
  --indices "$INDICES" \
  --message "$OUTPUTS_HASH"
```

Generate and independently verify the proof:

```sh
"$PYTHON" "$PROVER" prove \
  --directory "$WORK" \
  --indices "$INDICES" \
  --message "$OUTPUTS_HASH" \
  --out "$WORK/proof.json"

"$PYTHON" "$PROVER" verify \
  --policy "$WORK/policy.json" \
  --proof "$WORK/proof.json"
```

The verifier must print `valid`. Contract generation, compilation, exact padding calculation, node validation, and public relay are documented in [`TUTORIAL.md`](TUTORIAL.md).

## Repository layout

```text
src/
  main.rs                         ssw command-line interface
  shrincs.rs                      native SHRINCS signing logic
  bitcoin_simplicity.rs           Taproot address and proof-spend construction
contracts/
  shrincs-stark/scripts/
    protocol.py                   reference prover/verifier and AIR
    large_prover.py               vectorized large-quorum prover
    large_accel.c                 SHA/Merkle and field-power accelerator
    generate_contract.py          specialized Simplicity verifier generator
  shrincs-stark/artifacts/        generated policies, proofs, and verifier artifacts
  stark101/src/                   reusable Simplicity field/channel/hash functions
formal/Main.lean                  formal model
TUTORIAL.md                       end-to-end public Signet walkthrough
```

## 64-of-100 verification facts

The confirmed deployment was checked at every layer:

- STARK verifier output: `valid`
- trace size: `524288`; extended domain: `4194304`
- Simplicity program: `139579` bytes
- Simplicity witness: `19576` bytes
- analyzer cost: `204171 WU`, `error=0`
- leading zero padding: `44887` bytes
- local `testmempoolaccept`: `allowed: true`
- public relay accepted the transaction before it was confirmed

## Simplicity Signet

This project targets the custom Simplicity Signet, not standard Bitcoin Signet:

```ini
[signet]
signet=1
signetchallenge=00147cb2a6ddb8125278166fb414ed11b9f78a33ebe6
addnode=signet.simplicity-lang.org:38333
```

Resources:

- [Connect a node](https://signet.simplicity-lang.org/connect)
- [Faucet](https://signet.simplicity-lang.org/faucet)
- [Explorer](https://signet.simplicity-lang.org/explorer/)

## License

MIT

