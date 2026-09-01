pub struct Node{
    pub id: u32,
    pub keypair: Keypair,
    pub is_malicious: bool,
}

pub struct Keypair{
    pub public_key: u32,
    pub private_key: u64,
}