use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::io::Write; 
use std::fs;
use ed25519_dalek::Keypair;

// Re-use HashType and HASH_SIZE from the main file, or define here.
const HASH_SIZE: usize = 32;
pub type HashType = [u8; HASH_SIZE];

// --- PUBLIC DATA STRUCTURES ---

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Transaction {
    pub from_did: String,
    pub to_did: String,
    pub amount: u64,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub index: u32,
    pub timestamp: u64,
    pub merkle_root: String,
    pub previous_hash: String,
    pub nonce: u64,
    pub difficulty: u32,
    pub transactions_count: usize,
    pub transactions: Vec<Transaction>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Blockchain {
    pub chain: Vec<Block>,
    pub difficulty: u32,
    pub transactions_pool: Vec<Transaction>,
}

// --- CORE UTILITY FUNCTIONS (used by Blockchain methods) ---

/// Calculates the block's unique SHA-256 hash.
fn calculate_block_hash(block: &Block) -> HashType {
    let block_bytes = serde_json::to_vec(block)
        .expect("Failed to serialize block");
    
    let mut hasher = Sha256::new();
    hasher.update(&block_bytes);
    
    hasher.finalize().as_slice().try_into().expect("Wrong hash length")
}

/// Hashes a single item, enforcing canonical order.
fn hash_item(a: &[u8], b: Option<&[u8]>) -> HashType {
    let mut hasher = Sha256::new();
    
    if let Some(b_hash) = b {
        if a < b_hash {
            hasher.update(a);
            hasher.update(b_hash);
        } else {
            hasher.update(b_hash);
            hasher.update(a);
        }
    } else {
        hasher.update(a);
        hasher.update(a); 
    }
    hasher.finalize().as_slice().try_into().expect("Wrong hash length")
}

/// Computes the full Merkle tree structure.
fn compute_merkle_tree(mut leaves: Vec<HashType>) -> Vec<Vec<HashType>> {
    let mut tree = vec![leaves.clone()];
    
    while leaves.len() > 1 {
        let mut next_level = Vec::new();
        let mut i = 0;
        
        while i < leaves.len() {
            let left = &leaves[i];
            let right = leaves.get(i + 1); 
            
            let new_hash = hash_item(left, right.map(|r| r.as_ref()));
            next_level.push(new_hash);
            
            i += 2; 
        }
        
        tree.push(next_level.clone());
        leaves = next_level;
    }
    tree
}

/// Creates a fixed-size SHA-256 hash of a transaction's signature for the Merkle Tree.
pub fn create_transaction_hash(transaction: &Transaction, signature_bytes: &[u8]) -> HashType {
    let mut hasher = Sha256::new();
    let tx_bytes = serde_json::to_vec(transaction).expect("Failed to serialize tx");
    
    hasher.update(&tx_bytes);
    hasher.update(signature_bytes);
    
    hasher.finalize().as_slice().try_into().expect("Wrong hash length")
}


/// Implements the Proof-of-Work mining algorithm.
pub fn mine_block(mut block: Block) -> (Block, String) {
    let target_prefix = "0".repeat(block.difficulty as usize);
    println!("\n⛏️ Starting Proof-of-Work... Target prefix: {}", target_prefix);

    let mut nonce = 0;
    loop {
        block.nonce = nonce;
        let hash_bytes = calculate_block_hash(&block);
        let hash_str = hex::encode(hash_bytes);

        if hash_str.starts_with(&target_prefix) {
            println!("\n✅ Block Mined! Nonce found: {}", nonce);
            return (block, hash_str);
        }

        nonce += 1;
        if nonce % 100000 == 0 {
            print!(".");
            std::io::stdout().flush().unwrap();
        }
    }
}


// --- BLOCKCHAIN IMPLEMENTATION ---

impl Blockchain {
    /// Creates a new Blockchain and initializes it with the Genesis Block.
    pub fn new(difficulty: u32) -> Self {
        let genesis_block = Block {
            index: 0,
            timestamp: 1730908800,
            merkle_root: "".to_string(),
            previous_hash: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            nonce: 0,
            difficulty,
            transactions_count: 0,
            transactions: Vec::new(),
        };

        let (mined_genesis, _) = mine_block(genesis_block);

        Blockchain {
            chain: vec![mined_genesis],
            difficulty,
            transactions_pool: Vec::new(),
        }
    }

    /// Validates the integrity of the entire blockchain.
    pub fn is_chain_valid(&self) -> bool {
        let target_prefix = "0".repeat(self.difficulty as usize);
        println!("\n⚖️ Starting Chain Validation...");

        for i in 1..self.chain.len() {
            let current_block = &self.chain[i];
            let previous_block = &self.chain[i - 1];

            let current_hash_bytes = calculate_block_hash(current_block);
            let current_hash_str = hex::encode(current_hash_bytes);

            if !current_hash_str.starts_with(&target_prefix) {
                println!("❌ Block {} FAILED: Hash does not meet difficulty target.", current_block.index);
                return false;
            }

            let expected_previous_hash_bytes = calculate_block_hash(previous_block);
            let expected_previous_hash_str = hex::encode(expected_previous_hash_bytes);

            if current_block.previous_hash != expected_previous_hash_str {
                println!("❌ Block {} FAILED: Invalid chain link.", current_block.index);
                return false;
            }
        }
        
        println!("✅ Chain Validation SUCCESS! All blocks are correctly linked and mined.");
        true
    }

    /// Adds a transaction to the transaction pool.
    pub fn add_transaction(&mut self, transaction: Transaction) {
        self.transactions_pool.push(transaction);
    }

    /// Processes all transactions, mines a new block, and adds it to the chain.
    pub fn mine_pending_transactions(&mut self, sign_tx_fn: fn(&Keypair, &Transaction) -> Vec<u8>, keypair: &Keypair) -> Result<String, String> {
        if self.transactions_pool.is_empty() {
            return Err("No pending transactions to mine.".to_string());
        }

        let last_block = self.chain.last().unwrap();
        let previous_hash_bytes = calculate_block_hash(last_block);
        let previous_hash = hex::encode(previous_hash_bytes);
        
        println!("\n--- Mining Block {} ---", last_block.index + 1);
        
        // Use a clone to mine the transactions while keeping the pool safe during the process.
        let transactions_to_mine = self.transactions_pool.clone(); 
        
        let mut transaction_hashes: Vec<HashType> = Vec::new();
        for tx in transactions_to_mine.iter() {
            // NOTE: We pass the signing function reference from main to avoid crypto dependencies here.
            let signature = sign_tx_fn(keypair, tx); 
            let tx_hash_bytes = create_transaction_hash(tx, &signature);
            transaction_hashes.push(tx_hash_bytes);
        }
        
        let full_merkle_tree = compute_merkle_tree(transaction_hashes); 
        let final_root_bytes = full_merkle_tree.last().unwrap()[0];
        let merkle_root_str = hex::encode(final_root_bytes);
        
        let new_block_template = Block {
            index: last_block.index + 1,
            timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            merkle_root: merkle_root_str,
            previous_hash, 
            nonce: 0, 
            difficulty: self.difficulty,
            transactions_count: transactions_to_mine.len(),
            transactions: transactions_to_mine,
        };

        let (mined_block, block_hash) = mine_block(new_block_template);
        self.chain.push(mined_block);
        
        self.transactions_pool.clear();

        Ok(block_hash)
    }
    
    /// Saves the entire Blockchain state to a specified file.
    pub fn save_to_file(&self, filename: &str) -> Result<(), String> {
        let json_data = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Serialization error: {}", e))?;

        fs::write(filename, json_data)
            .map_err(|e| format!("File write error to {}: {}", filename, e))?;

        Ok(())
    }

    /// Loads and deserializes a Blockchain from a specified file.
    pub fn load_from_file(filename: &str) -> Result<Self, String> {
        let json_data = fs::read_to_string(filename)
            .map_err(|e| format!("File read error for {}: {}", filename, e))?;
        let ledger: Blockchain = serde_json::from_str(&json_data)
            .map_err(|e| format!("Deserialization error for {}: {}", filename, e))?;

        Ok(ledger)
    }

    /// Calculates the current balance for a given Decentralized Identifier (DID).
    pub fn get_balance_of_did(&self, did: &str) -> i64 {
        let mut balance: i64 = 0;

        for block in self.chain.iter() {
            for tx in block.transactions.iter() {
                if tx.from_did == did {
                    balance -= tx.amount as i64;
                }
                
                if tx.to_did == did {
                    balance += tx.amount as i64;
                }
            }
        }

        balance
    }
}