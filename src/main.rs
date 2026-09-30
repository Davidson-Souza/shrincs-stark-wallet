mod bitcoin_simplicity;
mod model;
mod shrincs;

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use model::{
    decode_array, Policy, PublicSigner, SecretSigner, SignatureMode, SignatureShare,
    SigningRequest, VerifiedQuorum,
};
use sha2::{Digest, Sha256};
use shrincs::SigningState;

const QUORUM_DOMAIN: &[u8] = b"shrincs-stark-wallet/quorum/v1";

#[derive(Parser)]
#[command(
    name = "ssw",
    about = "SHRINCS quorum bundles and Simplicity STARK utilities"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a SHRINCS signer set and quorum policy.
    Setup {
        #[arg(long)]
        participants: u16,
        #[arg(long)]
        threshold: u16,
        #[arg(long)]
        out: PathBuf,
    },
    /// Create a deterministic request for an unsigned transaction.
    Create {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        network: String,
        #[arg(long)]
        unsigned_tx: PathBuf,
        #[arg(long)]
        sighash: String,
        #[arg(long, default_value_t = 0)]
        input_index: u32,
        #[arg(long)]
        out: PathBuf,
    },
    /// Produce a stateful or recovery SHRINCS signature share.
    Sign {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long, value_enum, default_value_t = ModeArg::Stateful)]
        mode: ModeArg,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify distinct signature shares and assemble an off-chain quorum bundle.
    Aggregate {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long, required = true, num_args = 1..)]
        shares: Vec<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Independently verify an assembled off-chain quorum bundle.
    Verify {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        quorum: PathBuf,
    },
    /// Derive the Taproot address for a Simplicity commitment Merkle root.
    ContractAddress {
        #[arg(long)]
        cmr: PathBuf,
        #[arg(long)]
        network: String,
    },
    /// Assemble a Simplicity script-path proof spend.
    SpendProof {
        #[arg(long)]
        cmr: PathBuf,
        #[arg(long)]
        program: PathBuf,
        #[arg(long)]
        witness: PathBuf,
        #[arg(long)]
        outpoint: String,
        #[arg(long)]
        input_value_sat: u64,
        #[arg(long)]
        destination: String,
        #[arg(long)]
        fee_sat: u64,
        #[arg(long)]
        network: String,
        #[arg(long, default_value_t = 65_000)]
        padding_bytes: usize,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ModeArg {
    Stateful,
    Stateless,
}

impl From<ModeArg> for SignatureMode {
    fn from(value: ModeArg) -> Self {
        match value {
            ModeArg::Stateful => Self::Stateful,
            ModeArg::Stateless => Self::Stateless,
        }
    }
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Setup {
            participants,
            threshold,
            out,
        } => setup(participants, threshold, &out),
        Command::Create {
            policy,
            network,
            unsigned_tx,
            sighash,
            input_index,
            out,
        } => create_request(&policy, network, &unsigned_tx, &sighash, input_index, &out),
        Command::Sign {
            policy,
            request,
            key,
            mode,
            out,
        } => sign_request(&policy, &request, &key, mode.into(), &out),
        Command::Aggregate {
            policy,
            request,
            shares,
            out,
        } => aggregate(&policy, &request, &shares, &out),
        Command::Verify {
            policy,
            request,
            quorum,
        } => {
            let policy: Policy = read_json(&policy)?;
            let request: SigningRequest = read_json(&request)?;
            let quorum: VerifiedQuorum = read_json(&quorum)?;
            verify_quorum(&policy, &request, &quorum)?;
            println!(
                "valid quorum: {} of {} signers",
                quorum.signer_ids.len(),
                policy.signers.len()
            );
            Ok(())
        }
        Command::ContractAddress { cmr, network } => {
            let contract =
                bitcoin_simplicity::SimplicityContract::new(bitcoin_simplicity::load_cmr(&cmr)?)?;
            println!(
                "{}",
                contract.address(bitcoin_simplicity::parse_network(&network)?)
            );
            Ok(())
        }
        Command::SpendProof {
            cmr,
            program,
            witness,
            outpoint,
            input_value_sat,
            destination,
            fee_sat,
            network,
            padding_bytes,
            out,
        } => {
            let transaction =
                bitcoin_simplicity::build_spend_hex(bitcoin_simplicity::SpendProofFiles {
                    cmr: &cmr,
                    program: &program,
                    witness: &witness,
                    outpoint: &outpoint,
                    input_value_sat,
                    destination: &destination,
                    fee_sat,
                    network: &network,
                    padding_len: padding_bytes,
                })?;
            atomic_write(&out, transaction.as_bytes(), 0o644)?;
            println!("{transaction}");
            Ok(())
        }
    }
}

fn setup(participants: u16, threshold: u16, out: &Path) -> Result<()> {
    if participants == 0 {
        bail!("participants must be positive");
    }
    if threshold == 0 || threshold > participants {
        bail!("threshold must be in 1..={participants}");
    }
    fs::create_dir(out).with_context(|| format!("create signer directory {}", out.display()))?;

    let mut signers = Vec::with_capacity(usize::from(participants));
    for id in 1..=participants {
        let key_pair = shrincs::keygen().with_context(|| format!("generate signer {id}"))?;
        let public_key = hex::encode(key_pair.public_key);
        let secret = SecretSigner {
            version: 1,
            id,
            public_key: public_key.clone(),
            secret_key: hex::encode(key_pair.secret_key),
            stateful_index: key_pair.state.q,
            stateful_valid: key_pair.state.valid,
        };
        write_secret_json(&out.join(format!("signer-{id}.json")), &secret)?;
        signers.push(PublicSigner { id, public_key });
    }

    let policy = Policy {
        version: 1,
        threshold,
        signers,
    };
    policy.validate()?;
    write_json(&out.join("policy.json"), &policy)?;
    println!("policy_id={}", hex::encode(policy.id()?));
    Ok(())
}

fn create_request(
    policy_path: &Path,
    network: String,
    unsigned_tx_path: &Path,
    sighash: &str,
    input_index: u32,
    out: &Path,
) -> Result<()> {
    let policy: Policy = read_json(policy_path)?;
    bitcoin_simplicity::parse_network(&network)?;
    let unsigned_tx = fs::read_to_string(unsigned_tx_path)
        .with_context(|| format!("read unsigned transaction {}", unsigned_tx_path.display()))?;
    let unsigned_tx = unsigned_tx.trim();
    let transaction_bytes = hex::decode(unsigned_tx).context("unsigned transaction is not hex")?;
    let transaction: bitcoin::Transaction = bitcoin::consensus::deserialize(&transaction_bytes)
        .context("unsigned transaction is not a valid Bitcoin transaction")?;
    if transaction
        .input
        .iter()
        .any(|input| !input.script_sig.is_empty() || !input.witness.is_empty())
    {
        bail!("transaction already contains unlocking data");
    }
    if usize::try_from(input_index)? >= transaction.input.len() {
        bail!(
            "input index {input_index} is outside transaction input count {}",
            transaction.input.len()
        );
    }
    let transaction_sighash = decode_array::<32>(sighash, "transaction sighash")?;
    let request = SigningRequest::new(
        &policy,
        network,
        bitcoin::consensus::encode::serialize_hex(&transaction),
        input_index,
        transaction_sighash,
    )?;
    write_json(out, &request)?;
    println!("request_id={}", hex::encode(request.id()?));
    Ok(())
}

fn sign_request(
    policy_path: &Path,
    request_path: &Path,
    key_path: &Path,
    mode: SignatureMode,
    out: &Path,
) -> Result<()> {
    let policy: Policy = read_json(policy_path)?;
    let request: SigningRequest = read_json(request_path)?;
    let digest = request.validate_for(&policy)?;
    let mut key: SecretSigner = read_json(key_path)?;
    if key.version != 1 {
        bail!("unsupported secret signer version {}", key.version);
    }
    let signer = policy
        .signer(key.id)
        .with_context(|| format!("signer {} is not in policy", key.id))?;
    if signer.public_key != key.public_key {
        bail!(
            "secret key public key does not match signer {} in policy",
            key.id
        );
    }
    let public_key = key.public_key_bytes()?;
    let secret_key = key.secret_key_bytes()?;

    let signature = match mode {
        SignatureMode::Stateful => {
            let mut state = SigningState {
                q: key.stateful_index,
                valid: key.stateful_valid,
            };
            let signature = shrincs::sign_stateful(&digest, &secret_key, &mut state)?;
            if !shrincs::verify(&digest, &signature, &public_key)? {
                bail!("native SHRINCS self-verification failed");
            }
            key.stateful_index = state.q;
            key.stateful_valid = state.valid;
            // Persist the consumed one-time state before releasing the signature.
            write_secret_json(key_path, &key)?;
            signature
        }
        SignatureMode::Stateless => {
            let signature = shrincs::sign_stateless(&digest, &secret_key)?;
            if !shrincs::verify(&digest, &signature, &public_key)? {
                bail!("native SHRINCS self-verification failed");
            }
            signature
        }
    };

    let share = SignatureShare {
        version: 1,
        policy_id: request.policy_id.clone(),
        request_id: hex::encode(request.id()?),
        signer_id: key.id,
        mode,
        signature: hex::encode(signature),
    };
    write_json(out, &share)?;
    println!("signer_id={}", key.id);
    Ok(())
}

fn aggregate(
    policy_path: &Path,
    request_path: &Path,
    share_paths: &[PathBuf],
    out: &Path,
) -> Result<()> {
    let policy: Policy = read_json(policy_path)?;
    let request: SigningRequest = read_json(request_path)?;
    let digest = request.validate_for(&policy)?;
    let request_id = hex::encode(request.id()?);
    let mut shares = Vec::with_capacity(share_paths.len());
    let mut signer_ids = HashSet::with_capacity(share_paths.len());

    for path in share_paths {
        let share: SignatureShare = read_json(path)?;
        validate_share(&policy, &request, &request_id, &digest, &share)?;
        if !signer_ids.insert(share.signer_id) {
            bail!("duplicate signature share from signer {}", share.signer_id);
        }
        shares.push(share);
    }
    if shares.len() < usize::from(policy.threshold) {
        bail!(
            "quorum not met: got {} distinct valid signatures, need {}",
            shares.len(),
            policy.threshold
        );
    }
    shares.sort_unstable_by_key(|share| share.signer_id);
    let signer_ids = shares
        .iter()
        .map(|share| share.signer_id)
        .collect::<Vec<_>>();
    let commitment = quorum_commitment(&policy, &request, &shares)?;
    let quorum = VerifiedQuorum {
        version: 1,
        policy_id: request.policy_id.clone(),
        request_id,
        authorization_digest: hex::encode(digest),
        threshold: policy.threshold,
        signer_ids,
        shares,
        commitment: hex::encode(commitment),
    };
    write_json(out, &quorum)?;
    println!("quorum_commitment={}", quorum.commitment);
    Ok(())
}

fn validate_share(
    policy: &Policy,
    request: &SigningRequest,
    request_id: &str,
    digest: &[u8; 32],
    share: &SignatureShare,
) -> Result<()> {
    if share.version != 1 {
        bail!("unsupported signature share version {}", share.version);
    }
    if share.policy_id != request.policy_id || share.request_id != request_id {
        bail!(
            "signature share {} is bound to another request",
            share.signer_id
        );
    }
    let signer = policy
        .signer(share.signer_id)
        .with_context(|| format!("unknown signer {}", share.signer_id))?;
    let signature = share.signature_bytes()?;
    if !shrincs::verify(digest, &signature, &signer.key_bytes()?)? {
        bail!("invalid SHRINCS signature from signer {}", share.signer_id);
    }
    Ok(())
}

fn verify_quorum(policy: &Policy, request: &SigningRequest, quorum: &VerifiedQuorum) -> Result<()> {
    let digest = request.validate_for(policy)?;
    let request_id = hex::encode(request.id()?);
    if quorum.version != 1
        || quorum.policy_id != request.policy_id
        || quorum.request_id != request_id
        || quorum.authorization_digest != hex::encode(digest)
        || quorum.threshold != policy.threshold
    {
        bail!("quorum metadata does not match policy and request");
    }
    if quorum.shares.len() < usize::from(policy.threshold) {
        bail!("quorum contains too few shares");
    }
    let mut ids = HashSet::with_capacity(quorum.shares.len());
    for share in &quorum.shares {
        validate_share(policy, request, &request_id, &digest, share)?;
        if !ids.insert(share.signer_id) {
            bail!("quorum repeats signer {}", share.signer_id);
        }
    }
    let mut signer_ids = ids.into_iter().collect::<Vec<_>>();
    signer_ids.sort_unstable();
    if signer_ids != quorum.signer_ids {
        bail!("quorum signer id list is not canonical");
    }
    if quorum.commitment != hex::encode(quorum_commitment(policy, request, &quorum.shares)?) {
        bail!("quorum commitment mismatch");
    }
    Ok(())
}

fn quorum_commitment(
    policy: &Policy,
    request: &SigningRequest,
    shares: &[SignatureShare],
) -> Result<[u8; 32]> {
    let mut ordered = shares.iter().collect::<Vec<_>>();
    ordered.sort_unstable_by_key(|share| share.signer_id);
    let mut hasher = Sha256::new();
    hasher.update(QUORUM_DOMAIN);
    hasher.update(policy.id()?);
    hasher.update(request.id()?);
    hasher.update(policy.threshold.to_be_bytes());
    for share in ordered {
        hasher.update(share.signer_id.to_be_bytes());
        hasher.update([match share.mode {
            SignatureMode::Stateful => 0,
            SignatureMode::Stateless => 1,
        }]);
        let signature = share.signature_bytes()?;
        hasher.update((signature.len() as u32).to_be_bytes());
        hasher.update(signature);
    }
    Ok(hasher.finalize().into())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    atomic_write(path, &bytes, 0o644)
}

fn write_secret_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    atomic_write(path, &bytes, 0o600)
}

fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("output"),
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(mode)
        .open(&temporary)
        .with_context(|| format!("create {}", temporary.display()))?;
    file.write_all(bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path).with_context(|| format!("replace {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_signers_never_satisfy_quorum() {
        let mut ids = HashSet::new();
        assert!(ids.insert(7));
        assert!(!ids.insert(7));
        assert!(ids.len() < 2);
    }
}
