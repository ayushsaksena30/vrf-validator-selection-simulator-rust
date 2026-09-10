mod node;

use std::println;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use node::{Node};
use hex::encode;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const THRESHOLD:u64 = (u64::MAX as f64 * 0.2) as u64;
fn main() {

    let mut rng= OsRng{};
    let mut nodes = Vec::new();
    for n in 1..=10{
        let node = Node{
            id: n as u32,
            signing_key: SigningKey::generate(&mut rng),
            is_malicious: false,
        };

        println!("Node id- {}, Public Key- {}",
            node.id, encode(node.signing_key.verifying_key().to_bytes()));
        nodes.push(node);
    }

    let mut validators = Vec::new();
    for node in nodes.iter() {
       let vrf_output = compute_vrf(&node, 1);
        let is_validator = validator_selection(vrf_output);
        println!("Node id- {}, VRF- {}, Is Validator- {}",
            node.id, vrf_output, is_validator);

        if is_validator {
            validators.push(node.id);
        }
    }

    println!("Validators for round 1: {:?}", validators);
}

fn compute_vrf(node: &Node, round: u32) -> u64{
    let key = node.signing_key.to_bytes();
    let mut mac=HmacSha256::new_from_slice(&key).unwrap();
    mac.update(&round.to_be_bytes());
    let res=mac.finalize().into_bytes();

    u64::from_be_bytes(res[0..8].try_into().unwrap())
}

fn validator_selection(vrf_output: u64) -> bool {
    vrf_output < THRESHOLD
}