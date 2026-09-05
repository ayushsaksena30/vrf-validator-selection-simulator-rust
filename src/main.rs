mod node;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use node::{Node};
use hex::encode;

fn main() {

    let mut rng= OsRng{};
    for n in 1..=10{
        let node = Node{
            id: n as u32,
            signing_key: SigningKey::generate(&mut rng),
            is_malicious: false,
        };

        println!("Node id- {}, Public Key- {}",node.id, encode(node.signing_key.verifying_key().to_bytes()));
    }
}
