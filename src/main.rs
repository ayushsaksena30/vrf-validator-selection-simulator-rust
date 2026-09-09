mod node;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use node::{Node};
use hex::encode;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn main() {

    let mut rng= OsRng{};

    for n in 1..=10{
        let node = Node{
            id: n as u32,
            signing_key: SigningKey::generate(&mut rng),
            is_malicious: false,
        };

        println!("Node id- {}, Public Key- {}, VRF- {}",node.id, encode(node.signing_key.verifying_key().to_bytes()), compute_vrf(&node, 1));
    }
}

fn compute_vrf(node: &Node, round: u32) -> u64{
    let key = node.signing_key.to_bytes();
    let mut mac=HmacSha256::new_from_slice(&key).unwrap();
    mac.update(&round.to_be_bytes());
    let res=mac.finalize().into_bytes();

    u64::from_be_bytes(res[0..8].try_into().unwrap())
}