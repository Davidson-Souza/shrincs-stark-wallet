use std::fs;
use std::path::Path;
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use bitcoin::absolute::LockTime;
use bitcoin::address::NetworkUnchecked;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::key::UntweakedPublicKey;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo};
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};

pub const SIMPLICITY_LEAF_VERSION: u8 = 0xbe;
pub const NUMS_INTERNAL_KEY: &str =
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

pub struct SimplicityContract {
    cmr: [u8; 32],
    script: ScriptBuf,
    leaf_version: LeafVersion,
    spend_info: TaprootSpendInfo,
}

pub struct SimplicitySpend {
    pub outpoint: OutPoint,
    pub input_value: Amount,
    pub destination: Address,
    pub fee: Amount,
    pub program: Vec<u8>,
    pub witness: Vec<u8>,
    pub padding_len: usize,
}

pub struct SpendProofFiles<'a> {
    pub cmr: &'a Path,
    pub program: &'a Path,
    pub witness: &'a Path,
    pub outpoint: &'a str,
    pub input_value_sat: u64,
    pub destination: &'a str,
    pub fee_sat: u64,
    pub network: &'a str,
    pub padding_len: usize,
}

impl SimplicityContract {
    pub fn new(cmr: [u8; 32]) -> Result<Self> {
        let secp = Secp256k1::verification_only();
        let internal_key = UntweakedPublicKey::from_str(NUMS_INTERNAL_KEY)?;
        let leaf_version = LeafVersion::from_consensus(SIMPLICITY_LEAF_VERSION)?;
        let script = ScriptBuf::from_bytes(cmr.to_vec());
        let spend_info = TaprootBuilder::new()
            .add_leaf_with_ver(0, script.clone(), leaf_version)?
            .finalize(&secp, internal_key)
            .map_err(|_| anyhow::anyhow!("failed to finalize one-leaf Simplicity taproot tree"))?;
        Ok(Self {
            cmr,
            script,
            leaf_version,
            spend_info,
        })
    }

    pub fn address(&self, network: Network) -> Address {
        Address::p2tr_tweaked(self.spend_info.output_key(), network)
    }

    pub fn control_block(&self) -> Result<Vec<u8>> {
        self.spend_info
            .control_block(&(self.script.clone(), self.leaf_version))
            .context("Simplicity leaf missing from taproot tree")
            .map(|block| block.serialize())
    }

    pub fn spending_transaction(&self, spend: SimplicitySpend) -> Result<Transaction> {
        let SimplicitySpend {
            outpoint,
            input_value,
            destination,
            fee,
            program,
            witness,
            padding_len,
        } = spend;
        let output_value = input_value
            .checked_sub(fee)
            .context("fee exceeds input value")?;
        let destination_script = destination.script_pubkey();
        if output_value < destination_script.minimal_non_dust() {
            bail!("output would be dust");
        }
        let mut stack = Vec::with_capacity(if padding_len > 0 { 5 } else { 4 });
        if padding_len > 0 {
            stack.push(vec![0_u8; padding_len]);
        }
        stack.extend([witness, program, self.cmr.to_vec(), self.control_block()?]);
        Ok(Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&stack),
            }],
            output: vec![TxOut {
                value: output_value,
                script_pubkey: destination_script,
            }],
        })
    }
}

pub fn parse_network(value: &str) -> Result<Network> {
    Network::from_str(value).with_context(|| format!("unknown Bitcoin network {value}"))
}

pub fn parse_address(value: &str, network: Network) -> Result<Address> {
    value
        .parse::<Address<NetworkUnchecked>>()?
        .require_network(network)
        .with_context(|| format!("address is not for {network}"))
}

pub fn load_cmr(path: &Path) -> Result<[u8; 32]> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    crate::model::decode_array(text.trim(), "commitment Merkle root")
}

pub fn build_spend_hex(files: SpendProofFiles<'_>) -> Result<String> {
    let network = parse_network(files.network)?;
    let contract = SimplicityContract::new(load_cmr(files.cmr)?)?;
    let transaction = contract.spending_transaction(SimplicitySpend {
        outpoint: OutPoint::from_str(files.outpoint).context("invalid outpoint")?,
        input_value: Amount::from_sat(files.input_value_sat),
        destination: parse_address(files.destination, network)?,
        fee: Amount::from_sat(files.fee_sat),
        program: fs::read(files.program)
            .with_context(|| format!("read {}", files.program.display()))?,
        witness: fs::read(files.witness)
            .with_context(|| format!("read {}", files.witness.display()))?,
        padding_len: files.padding_len,
    })?;
    Ok(serialize_hex(&transaction))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anyone_can_spend_vector_matches_inquisition_test() {
        let cmr = hex::decode("c40a10263f7436b4160acbef1c36fba4be4d95df181a968afeab5eac247adff7")
            .unwrap()
            .try_into()
            .unwrap();
        let contract = SimplicityContract::new(cmr).unwrap();
        assert_eq!(
            contract.address(Network::Regtest).to_string(),
            "bcrt1pzjehfs3vskwj6022c255hyh948ecjsqzv25fkm29w7gwzazyccfqt8ksnv"
        );
        assert_eq!(
            hex::encode(contract.control_block().unwrap()),
            "be50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
        );
    }

    #[test]
    fn simplicity_padding_is_a_leading_zero_stack_item() {
        let cmr = [7_u8; 32];
        let contract = SimplicityContract::new(cmr).unwrap();
        let transaction = contract
            .spending_transaction(SimplicitySpend {
                outpoint: OutPoint::null(),
                input_value: Amount::from_sat(10_000),
                destination: contract.address(Network::Regtest),
                fee: Amount::from_sat(1_000),
                program: vec![1, 2],
                witness: vec![3, 4],
                padding_len: 3,
            })
            .unwrap();
        let stack: Vec<&[u8]> = transaction.input[0].witness.iter().collect();
        assert_eq!(stack.len(), 5);
        assert_eq!(stack[0], [0, 0, 0]);
        assert_eq!(stack[1], [3, 4]);
        assert_eq!(stack[2], [1, 2]);
        assert_eq!(stack[3], cmr);
        assert_ne!(stack[4].first(), Some(&0x50));
    }
}
