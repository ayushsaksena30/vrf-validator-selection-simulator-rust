mod node;

use node::{Node, Keypair};

fn main() {
    for n in 1..=10{
        let key= Keypair{
            public_key: 0,
            private_key: 0,
        };
        let node = Node{
            id: n,
            keypair: key,
            is_malicious: false,
        };

        println!("Node id- {}",node.id);
    }
}
