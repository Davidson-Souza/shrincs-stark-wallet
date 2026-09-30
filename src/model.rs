use std::collections::HashSet;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::shrincs::{PUBLIC_KEY_LEN, SECRET_KEY_LEN};

const POLICY_DOMAIN: &[u8] = b"shrincs-stark-wallet/policy/v1";
const REQUEST_DOMAIN: &[u8] = b"shrincs-stark-wallet/request/v1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicSigner {
    pub id: u16,
    pub public_key: String,
}

impl PublicSigner {
    pub fn key_bytes(&self) -> Result<[u8; PUBLIC_KEY_LEN]> {
        decode_array(&self.public_key, "public key")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Policy {
    pub version: u8,
    pub threshold: u16,
    pub signers: Vec<PublicSigner>,
}

impl Policy {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            bail!("unsupported policy version {}", self.version);
        }
        if self.signers.is_empty() {
            bail!("policy must contain at least one signer");
        }
        if self.threshold == 0 || usize::from(self.threshold) > self.signers.len() {
            bail!(
                "threshold {} is outside 1..={}",
                self.threshold,
                self.signers.len()
            );
        }
        let mut ids = HashSet::with_capacity(self.signers.len());
        let mut keys = HashSet::with_capacity(self.signers.len());
        for signer in &self.signers {
            if !ids.insert(signer.id) {
                bail!("duplicate signer id {}", signer.id);
            }
            let key = signer.key_bytes()?;
            if !keys.insert(key) {
                bail!("duplicate SHRINCS public key for signer {}", signer.id);
            }
        }
        Ok(())
    }

    pub fn id(&self) -> Result<[u8; 32]> {
        self.validate()?;
        let mut signers = self.signers.iter().collect::<Vec<_>>();
        signers.sort_unstable_by_key(|signer| signer.id);
        let mut hasher = Sha256::new();
        hasher.update(POLICY_DOMAIN);
        hasher.update(self.threshold.to_be_bytes());
        hasher.update((signers.len() as u32).to_be_bytes());
        for signer in signers {
            hasher.update(signer.id.to_be_bytes());
            hasher.update(signer.key_bytes()?);
        }
        Ok(hasher.finalize().into())
    }

    pub fn signer(&self, id: u16) -> Option<&PublicSigner> {
        self.signers.iter().find(|signer| signer.id == id)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretSigner {
    pub version: u8,
    pub id: u16,
    pub public_key: String,
    pub secret_key: String,
    pub stateful_index: u32,
    pub stateful_valid: bool,
}

impl SecretSigner {
    pub fn secret_key_bytes(&self) -> Result<[u8; SECRET_KEY_LEN]> {
        decode_array(&self.secret_key, "secret key")
    }

    pub fn public_key_bytes(&self) -> Result<[u8; PUBLIC_KEY_LEN]> {
        decode_array(&self.public_key, "public key")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SigningRequest {
    pub version: u8,
    pub policy_id: String,
    pub network: String,
    pub unsigned_tx: String,
    pub input_index: u32,
    pub authorization_digest: String,
    pub transaction_sighash: String,
}

impl SigningRequest {
    pub fn new(
        policy: &Policy,
        network: String,
        unsigned_tx: String,
        input_index: u32,
        transaction_sighash: [u8; 32],
    ) -> Result<Self> {
        let policy_id = policy.id()?;
        let authorization_digest = compute_authorization_digest(
            policy_id,
            &network,
            &unsigned_tx,
            input_index,
            transaction_sighash,
        );
        Ok(Self {
            version: 1,
            policy_id: hex::encode(policy_id),
            network,
            unsigned_tx,
            input_index,
            transaction_sighash: hex::encode(transaction_sighash),
            authorization_digest: hex::encode(authorization_digest),
        })
    }

    pub fn validate_for(&self, policy: &Policy) -> Result<[u8; 32]> {
        if self.version != 1 {
            bail!("unsupported signing request version {}", self.version);
        }
        let policy_id = policy.id()?;
        if self.policy_id != hex::encode(policy_id) {
            bail!("signing request policy id does not match policy");
        }
        let transaction_sighash = decode_array(&self.transaction_sighash, "transaction sighash")?;
        let expected = compute_authorization_digest(
            policy_id,
            &self.network,
            &self.unsigned_tx,
            self.input_index,
            transaction_sighash,
        );
        let actual = decode_array(&self.authorization_digest, "authorization digest")?;
        if actual != expected {
            bail!("signing request authorization digest does not match its transaction");
        }
        Ok(actual)
    }

    pub fn id(&self) -> Result<[u8; 32]> {
        let digest: [u8; 32] = decode_array(&self.authorization_digest, "authorization digest")?;
        let mut hasher = Sha256::new();
        hasher.update(REQUEST_DOMAIN);
        hasher.update(decode_array::<32>(&self.policy_id, "policy id")?);
        hasher.update(self.network.as_bytes());
        hasher.update(self.input_index.to_be_bytes());
        hasher.update(Sha256::digest(self.unsigned_tx.as_bytes()));
        hasher.update(digest);
        Ok(hasher.finalize().into())
    }
}

fn compute_authorization_digest(
    policy_id: [u8; 32],
    network: &str,
    unsigned_tx: &str,
    input_index: u32,
    transaction_sighash: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_DOMAIN);
    hasher.update(policy_id);
    hasher.update((network.len() as u32).to_be_bytes());
    hasher.update(network.as_bytes());
    hasher.update(input_index.to_be_bytes());
    hasher.update(Sha256::digest(unsigned_tx.as_bytes()));
    hasher.update(transaction_sighash);
    hasher.finalize().into()
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignatureMode {
    Stateful,
    Stateless,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureShare {
    pub version: u8,
    pub policy_id: String,
    pub request_id: String,
    pub signer_id: u16,
    pub mode: SignatureMode,
    pub signature: String,
}

impl SignatureShare {
    pub fn signature_bytes(&self) -> Result<Vec<u8>> {
        hex::decode(&self.signature).context("signature is not valid hex")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedQuorum {
    pub version: u8,
    pub policy_id: String,
    pub request_id: String,
    pub authorization_digest: String,
    pub threshold: u16,
    pub signer_ids: Vec<u16>,
    pub shares: Vec<SignatureShare>,
    pub commitment: String,
}

pub fn decode_array<const N: usize>(value: &str, name: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(value).with_context(|| format!("{name} is not valid hex"))?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow::anyhow!("{name} must be {N} bytes, got {}", bytes.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            version: 1,
            threshold: 1,
            signers: vec![PublicSigner {
                id: 1,
                public_key: hex::encode([7_u8; PUBLIC_KEY_LEN]),
            }],
        }
    }

    #[test]
    fn authorization_digest_binds_complete_request() {
        let policy = policy();
        let request = SigningRequest::new(
            &policy,
            "signet".to_owned(),
            "020000000001".to_owned(),
            3,
            [9_u8; 32],
        )
        .unwrap();
        assert!(request.validate_for(&policy).is_ok());

        let mut changed = request.clone();
        changed.network = "regtest".to_owned();
        assert!(changed.validate_for(&policy).is_err());

        let mut changed = request.clone();
        changed.unsigned_tx.push_str("00");
        assert!(changed.validate_for(&policy).is_err());

        let mut changed = request.clone();
        changed.input_index += 1;
        assert!(changed.validate_for(&policy).is_err());

        let mut changed = request;
        changed.transaction_sighash = hex::encode([8_u8; 32]);
        assert!(changed.validate_for(&policy).is_err());
    }
}
