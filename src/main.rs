mod node;

use std::println;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use node::{Node};
use hex::encode;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const THRESHOLD:u64 = (u64::MAX as f64 * 0.2) as u64;
fn main() {

    let mut rng= OsRng{};
    let mut nodes = Vec::new();

    let mut node_index: Vec<u32> = (1..=20).collect();
    node_index.shuffle(&mut rng);

    let malicious_nodes: Vec<u32> = node_index.iter().take(6).cloned().collect();

    for n in 1..=20{
        let node = Node{
            id: n as u32,
            signing_key: SigningKey::generate(&mut rng),
            is_malicious: malicious_nodes.iter().any(|x| x == &n),
        };

        println!("Node id- {}, Public Key- {}",
            node.id, encode(node.signing_key.verifying_key().to_bytes()));
        nodes.push(node);
    }

    let mut number_of_times_malicious_validator=0;

    for round in 1..=1000{

        let mut validators = Vec::new();

        for node in nodes.iter() {
            let vrf_output = compute_vrf(&node, round);
            let is_validator = validator_selection(vrf_output);
            // println!("Node id- {}, VRF- {}, Is Validator- {}",
                // node.id, vrf_output, is_validator);

            if is_validator {
                validators.push(node.id);
            }
        }

        let malicious_validators = validators.iter().any(|node| malicious_nodes.contains(node));
    
        // println!("Validators for round 1: {:?}", validators);
        // println!("Malicious Validators for round 1: {:?}", malicious_validators);
        if(malicious_validators){
            number_of_times_malicious_validator+=1;
        }
    }

    println!("Number of times malicious validator was selected: {}", number_of_times_malicious_validator);
    println!("Probability of malicious node selected as validator: {}", number_of_times_malicious_validator as f64 / 1000.0);
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