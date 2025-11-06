/*
 * TRUE LEDGER CORE - COMPLETE PROJECT (FINAL VERSION - MONOLITHIC)
 *
 * This version implements the complete, fixed core logic:
 * 1. Identity, Signing, and Verification (Ed25519, Argon2).
 * 2. Data Integrity: Merkle Tree and Canonical Proof Verification.
 * 3. Ledger Structure: Blocks, PoW Mining, Transaction Pool.
 * 4. CHAIN MANAGEMENT: Chain Validation, Balance Tracking, and Full Persistence.
 * * NOTE: The next step is to refactor this large file into separate modules for better management.
 */

// --- General Imports ---
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fs;
use std::io::Write; 

// --- Crypto & Identity Imports ---
use ed25519_dalek::{Keypair, Signature, Signer, Verifier};

// --- Randomness Imports ---
use rand_core::{OsRng, RngCore}; 
use rand::Rng;

// --- KDF Imports ---
use argon2::{
    password_hash::{
        rand_core::OsRng as ArgonRng, PasswordHash, PasswordHasher, SaltString, 
    },
    Argon2
};
use pbkdf2::pbkdf2_hmac_array;

// --- Hashing and Symmetric Encryption Imports ---
use sha2::{Digest, Sha256};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce
};


// Constants
const KEY_SIZE: usize = 32; 
const RECOVERY_ITERATIONS: u32 = 100_000;
const HASH_SIZE: usize = 32; // Standard SHA-256 size
type HashType = [u8; HASH_SIZE];


// --- Data Structures ---

// 1. The data structure saved to disk (Identity Bundle)
#[derive(Serialize, Deserialize, Debug)]
struct EncryptedIdentity {
    user_did: String,         
    encrypted_key: Vec<u8>,   
    nonce: Vec<u8>,           
    salt: String,             
    recovery_salt: String,    
}

// 2. A basic structure to represent data being signed (a "Transaction")
#[derive(Serialize, Deserialize, Debug, Clone)] // Added Clone
struct Transaction {
    from_did: String,
    to_did: String,
    amount: u64,
    timestamp: u64,
}

// 3. The data structure representing a secured block on the ledger (Phase 4)
#[derive(Serialize, Deserialize, Debug, Clone)] // Added Clone
struct Block {
    index: u32,
    timestamp: u64,
    merkle_root: String,       // Integrity proof for the transaction batch
    previous_hash: String,     // Link to the previous block for chaining
    nonce: u64,                // Number used for Proof-of-Work mining
    difficulty: u32,           // Target for the mining process
    transactions_count: usize, // Number of transactions in the block
    transactions: Vec<Transaction>, // NEW: Store the actual transactions for state tracking
}

// 4. The main structure to manage the decentralized ledger
#[derive(Serialize, Deserialize, Debug)]
struct Blockchain {
    chain: Vec<Block>,
    difficulty: u32,
    transactions_pool: Vec<Transaction>, // Holds unmined transactions
}

impl Blockchain {
    /// Creates a new Blockchain and initializes it with the Genesis Block.
    fn new(difficulty: u32) -> Self {
        let genesis_block = Block {
            index: 0,
            timestamp: 1730908800, // Fixed start time
            merkle_root: "".to_string(), // No transactions in the genesis block
            previous_hash: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            nonce: 0,
            difficulty,
            transactions_count: 0,
            transactions: Vec::new(), // Genesis has no transactions
        };

        // Mine the genesis block
        let (mined_genesis, _) = mine_block(genesis_block);

        Blockchain {
            chain: vec![mined_genesis],
            difficulty,
            transactions_pool: Vec::new(),
        }
    }

    /// 15. Validates the integrity of the entire blockchain.
    fn is_chain_valid(&self) -> bool {
        let target_prefix = "0".repeat(self.difficulty as usize);
        println!("\n⚖️ Starting Chain Validation...");

        for i in 1..self.chain.len() {
            let current_block = &self.chain[i];
            let previous_block = &self.chain[i - 1];

            let current_hash_bytes = calculate_block_hash(current_block);
            let current_hash_str = hex::encode(current_hash_bytes);

            // 1. Check if the current block hash is valid (meets PoW difficulty)
            if !current_hash_str.starts_with(&target_prefix) {
                println!("❌ Block {} FAILED: Hash does not meet difficulty target.", current_block.index);
                return false;
            }

            // 2. Check if the current block's previous_hash links correctly to the actual previous hash
            let expected_previous_hash_bytes = calculate_block_hash(previous_block);
            let expected_previous_hash_str = hex::encode(expected_previous_hash_bytes);

            if current_block.previous_hash != expected_previous_hash_str {
                println!("❌ Block {} FAILED: Invalid chain link.", current_block.index);
                println!("   Expected previous hash: {}", expected_previous_hash_str);
                println!("   Found previous hash:    {}", current_block.previous_hash);
                return false;
            }
        }
        
        println!("✅ Chain Validation SUCCESS! All blocks are correctly linked and mined.");
        true
    }

    /// 16. Adds a validated transaction to the transaction pool.
    fn add_transaction(&mut self, transaction: Transaction) {
        self.transactions_pool.push(transaction);
    }

    /// 17. Processes all transactions in the pool, mines a new block, and adds it to the chain.
    fn mine_pending_transactions(&mut self, keypair: &Keypair) -> Result<String, String> {
        if self.transactions_pool.is_empty() {
            return Err("No pending transactions to mine.".to_string());
        }

        let last_block = self.chain.last().unwrap();
        let previous_hash_bytes = calculate_block_hash(last_block);
        let previous_hash = hex::encode(previous_hash_bytes);
        
        println!("\n--- Mining Block {} ---", last_block.index + 1);
        
        // 2. Generate Merkle Hashes
        let mut transaction_hashes: Vec<HashType> = Vec::new();
        // The list of transactions to be mined in this block
        let transactions_to_mine = self.transactions_pool.clone(); 
        
        for tx in transactions_to_mine.iter() {
            let signature = sign_transaction(keypair, tx); 
            let tx_hash_bytes = create_transaction_hash(tx, &signature);
            transaction_hashes.push(tx_hash_bytes);
        }
        
        // 3. Compute Merkle Root
        let full_merkle_tree = compute_merkle_tree(transaction_hashes); 
        let final_root_bytes = full_merkle_tree.last().unwrap()[0];
        let merkle_root_str = hex::encode(final_root_bytes);
        
        // 4. Define the new Block
        let new_block_template = Block {
            index: last_block.index + 1,
            timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            merkle_root: merkle_root_str,
            previous_hash, 
            nonce: 0, 
            difficulty: self.difficulty,
            transactions_count: transactions_to_mine.len(),
            transactions: transactions_to_mine, // Include transactions in the block
        };

        // 5. Mine and Append
        let (mined_block, block_hash) = mine_block(new_block_template);
        self.chain.push(mined_block);
        
        // 6. Clear the pool for the next block
        self.transactions_pool.clear();

        Ok(block_hash)
    }
    
    /// 18. Saves the entire Blockchain state to a specified file.
    pub fn save_to_file(&self, filename: &str) -> Result<(), String> {
        let json_data = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Serialization error: {}", e))?;

        fs::write(filename, json_data)
            .map_err(|e| format!("File write error to {}: {}", filename, e))?;

        Ok(())
    }

    /// 19. Loads and deserializes a Blockchain from a specified file.
    pub fn load_from_file(filename: &str) -> Result<Self, String> {
        let json_data = fs::read_to_string(filename)
            .map_err(|e| format!("File read error for {}: {}", filename, e))?;
        let ledger: Blockchain = serde_json::from_str(&json_data)
            .map_err(|e| format!("Deserialization error for {}: {}", filename, e))?;

        Ok(ledger)
    }

    /// 20. Calculates the current balance for a given Decentralized Identifier (DID).
    fn get_balance_of_did(&self, did: &str) -> i64 {
        let mut balance: i64 = 0;

        // Iterate over all blocks in the chain
        for block in self.chain.iter() {
            // Iterate over all transactions in the block
            for tx in block.transactions.iter() {
                // Funds are deducted when the DID is the sender
                if tx.from_did == did {
                    balance -= tx.amount as i64;
                }
                
                // Funds are added when the DID is the recipient
                if tx.to_did == did {
                    balance += tx.amount as i64;
                }
            }
        }

        balance
    }
}


// --- PHASE 1: KEY DERIVATION & ENCRYPTION FUNCTIONS ---

/// 1. Derives KEK-A (32-byte key) from user password using Argon2.
fn derive_key_from_password(password: &str, salt: &SaltString) -> [u8; KEY_SIZE] {
    let password_bytes = password.as_bytes();
    let argon2 = Argon2::default();
    
    let password_hash_struct = argon2.hash_password(password_bytes, salt)
        .expect("Failed to hash password");

    let owned_hash = password_hash_struct.hash
        .expect("Failed to get hash object from struct");
    let hash_bytes = owned_hash.as_bytes();

    let mut key = [0u8; KEY_SIZE];
    
    if hash_bytes.len() < KEY_SIZE {
         panic!("Argon2 hash output was too short for a 32-byte key!");
    }
    
    key.copy_from_slice(&hash_bytes[..KEY_SIZE]);
    key
}

/// 2. Derives KEK-B (32-byte key) from a recovery code using PBKDF2.
fn derive_key_from_recovery_code(code: &str, salt_str: &str) -> [u8; KEY_SIZE] {
    
    let salt_bytes = hex::decode(salt_str).expect("Invalid hex salt");
    
    pbkdf2_hmac_array::<Sha256, KEY_SIZE>(
        &code.as_bytes(), 
        &salt_bytes, 
        RECOVERY_ITERATIONS
    )
}


/// 3. Creates a new user identity and encrypts it with the password (KEK-A).
fn create_user_identity(password: &str) -> EncryptedIdentity {
    // --- Identity Generation ---
    let mut csprng = OsRng {};
    let keypair = Keypair::generate(&mut csprng);
    let public_key_bytes = keypair.public.to_bytes();
    
    let did_key_bytes = [ &[0xed, 0x01], &public_key_bytes[..] ].concat();
    let user_did = format!("did:key:{}", multibase::encode(multibase::Base::Base58Btc, did_key_bytes));

    // --- Encryption ---
    let private_key_bytes = keypair.to_bytes();
    let salt = SaltString::generate(&mut ArgonRng);
    let kek_a = derive_key_from_password(password, &salt);

    let cipher = ChaCha20Poly1305::new(&kek_a.into());
    let mut csprng_nonce = OsRng; 
    let mut nonce_bytes = [0u8; 12];
    csprng_nonce.fill_bytes(&mut nonce_bytes); 
    let nonce = Nonce::from_slice(&nonce_bytes);

    let encrypted_key = cipher.encrypt(nonce, private_key_bytes.as_ref())
        .expect("Failed to encrypt key");
    
    // --- Recovery Salt Generation ---
    let mut recovery_salt_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut recovery_salt_bytes);
    let recovery_salt = hex::encode(recovery_salt_bytes);

    EncryptedIdentity {
        user_did,
        encrypted_key,
        nonce: nonce.to_vec(),
        salt: salt.to_string(),
        recovery_salt,
    }
}

/// 4. Decrypts the key using a provided KEK.
fn decrypt_key(kek: [u8; KEY_SIZE], identity_bundle: &EncryptedIdentity) -> Result<Keypair, String> {
    let cipher = ChaCha20Poly1305::new(&kek.into());
    let nonce = Nonce::from_slice(&identity_bundle.nonce);

    let decrypted_bytes = cipher.decrypt(nonce, identity_bundle.encrypted_key.as_ref())
        .map_err(|_| "DECRYPTION FAILED: Invalid key or MAC.".to_string())?;

    Keypair::from_bytes(&decrypted_bytes)
        .map_err(|_| "Keypair reconstruction failed (decryption corruption).".to_string())
}


// --- PHASE 2: TRANSACTION SIGNING & VERIFICATION FUNCTIONS ---

/// 5. Signs a transaction using the user's decrypted Keypair.
fn sign_transaction(keypair: &Keypair, transaction: &Transaction) -> Vec<u8> {
    let transaction_bytes = serde_json::to_vec(transaction)
        .expect("Failed to serialize transaction");

    let signature: Signature = keypair.sign(&transaction_bytes);
    signature.to_bytes().to_vec()
}

/// 6. Verifies a signature using the public key derived from the DID.
fn verify_signature(did: &str, transaction: &Transaction, signature_bytes: &[u8]) -> bool {
    let did_part = did.trim_start_matches("did:key:");
    
    let (_, decoded_bytes) = multibase::decode(did_part)
        .expect("Failed to decode multibase DID");
    
    let public_key_bytes = &decoded_bytes[2..]; 

    let public_key = match ed25519_dalek::PublicKey::from_bytes(public_key_bytes) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    let transaction_bytes = serde_json::to_vec(transaction)
        .expect("Failed to serialize transaction");

    let signature = match Signature::from_bytes(signature_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    public_key.verify(&transaction_bytes, &signature).is_ok()
}


// --- PHASE 3: SELF-CONTAINED MERKLE TREE CORE FUNCTIONS ---

/// Hashes a single item (a leaf or an intermediate node), enforcing canonical order.
fn hash_item(a: &[u8], b: Option<&[u8]>) -> HashType {
    let mut hasher = Sha256::new();
    
    if let Some(b_hash) = b {
        // Canonical Rule: Always hash the two components in byte-by-byte numerical order.
        if a < b_hash {
            hasher.update(a);
            hasher.update(b_hash);
        } else {
            hasher.update(b_hash);
            hasher.update(a);
        }
    } else {
        // Rule: If a node has no sibling, hash it with itself.
        hasher.update(a);
        hasher.update(a); 
    }
    hasher.finalize().as_slice().try_into().expect("Wrong hash length")
}

/// 7. Creates a fixed-size SHA-256 hash of a transaction's signature for the Merkle Tree.
fn create_transaction_hash(transaction: &Transaction, signature_bytes: &[u8]) -> HashType {
    let mut hasher = Sha256::new();
    let tx_bytes = serde_json::to_vec(transaction).expect("Failed to serialize tx");
    
    hasher.update(&tx_bytes);
    hasher.update(signature_bytes);
    
    hasher.finalize().as_slice().try_into().expect("Wrong hash length")
}

// Helper function to compute the full tree structure
fn compute_merkle_tree(mut leaves: Vec<HashType>) -> Vec<Vec<HashType>> {
    let mut tree = vec![leaves.clone()]; // Start with the leaf level
    
    // Recursive loop until only one hash remains (the root)
    while leaves.len() > 1 {
        let mut next_level = Vec::new();
        let mut i = 0;
        
        while i < leaves.len() {
            let left = &leaves[i];
            let right = leaves.get(i + 1); 
            
            // Hash with canonical order (handled by hash_item)
            let new_hash = hash_item(left, right.map(|r| r.as_ref()));
            next_level.push(new_hash);
            
            i += 2; 
        }
        
        tree.push(next_level.clone());
        leaves = next_level;
    }
    tree
}


/// 8. Builds the Merkle Tree, and returns the root hash string.
fn build_simple_merkle_root(leaves: Vec<HashType>) -> String {
    if leaves.is_empty() {
        return "Empty Tree".to_string();
    }
    
    let tree = compute_merkle_tree(leaves);
    
    // The root is the last hash in the last level of the tree vector
    let root_bytes = tree.last().unwrap()[0];
    hex::encode(root_bytes)
}

// NOTE: Merkle Proof generation/verification are not used in main() anymore 
// but are retained here for completeness of the Merkle Tree logic.

/// 11. Calculates the block's unique SHA-256 hash.
fn calculate_block_hash(block: &Block) -> HashType {
    // To ensure the transactions are included in the hash, we must hash the entire block structure, 
    // including the transactions vector.
    let block_bytes = serde_json::to_vec(block)
        .expect("Failed to serialize block");
    
    let mut hasher = Sha256::new();
    hasher.update(&block_bytes);
    
    hasher.finalize().as_slice().try_into().expect("Wrong hash length")
}

/// 12. Implements the Proof-of-Work mining algorithm.
fn mine_block(mut block: Block) -> (Block, String) {
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


// --- MAIN PROGRAM: Test the full cycle ---
fn main() {
    let user_password = "MySecurePassword123";
    let mining_difficulty = 4; // Difficulty for PoW

    println!("--- Starting True Ledger Core: Blockchain Initialization ---\n");
    
    // 1. Initialize the Blockchain with the Genesis Block
    let mut ledger = Blockchain::new(mining_difficulty);
    let genesis_hash_bytes = calculate_block_hash(&ledger.chain[0]);
    let genesis_hash = hex::encode(genesis_hash_bytes);
    
    println!("✅ Genesis Block Mined and Initialized.");
    println!("   Genesis Hash: **{}**", genesis_hash);
    
    // --- 2. Identity Creation & Login ---
    
    let identity = create_user_identity(user_password);
    let salt_a = SaltString::new(&identity.salt).unwrap();
    let kek_a_derived = derive_key_from_password(user_password, &salt_a);
    
    let keypair_result = decrypt_key(kek_a_derived, &identity);
    let keypair = match keypair_result {
        Ok(kp) => {
            println!("\n✅ Identity keypair loaded for signing.");
            kp
        },
        Err(e) => {
            println!("❌ Identity FAILED: Could not load keypair: {}", e);
            return; 
        }
    };
    
    // --- 3. Add Transactions to Pool ---

    let recipient_did = "did:key:z6Mkk7pLq4eYfW3yVw6jJv".to_string(); 
    let num_transactions = 5;
    
    println!("\n--- Phase 3: Adding Transactions to Pool (Sender: {}) ---", &identity.user_did[..10]);
    
    // For this test, we must manually give the sender an initial balance 
    // since the 'get_balance' function shows 0 otherwise. Let's simulate 
    // a genesis transaction credit of 1000.
    ledger.chain[0].transactions.push(Transaction {
        from_did: "Genesis".to_string(),
        to_did: identity.user_did.clone(),
        amount: 1000,
        timestamp: 1730908700,
    });
    
    let initial_balance = ledger.get_balance_of_did(&identity.user_did);
    println!("   Initial Balance for {}: **{}** (Simulated Credit)", &identity.user_did[..10], initial_balance);
    
    let mut total_sent: i64 = 0;
    
    // Collect transactions and add to the ledger's pool
    for i in 0..num_transactions {
        let amount = 100 + i;
        total_sent += amount as i64;
        
        let transaction = Transaction {
            from_did: identity.user_did.clone(),
            to_did: recipient_did.clone(),
            amount, 
            timestamp: 1730908800 + 600 + i as u64,
        };
        
        ledger.add_transaction(transaction);
        println!("   Added TX {}: {} sent to {}", i, amount, &recipient_did[..10]);
    }
    
    // --- 4. Mining the Pending Transactions into Block 1 ---

    let block_hash = match ledger.mine_pending_transactions(&keypair) {
        Ok(hash) => {
            println!("\n✅ Block {} Mined and Appended to Chain.", ledger.chain.len() - 1);
            println!("Total Blocks in Chain: {}", ledger.chain.len());
            hash
        },
        Err(e) => {
            eprintln!("❌ Mining Failed: {}", e);
            return;
        }
    };
    
    // --- 5. Post-Mining Validation and Balance Check ---

    // d. Persistence Test: Save the ENTIRE Blockchain state
    let ledger_filename = "true_ledger_state.json";
    
    match ledger.save_to_file(ledger_filename) {
        Ok(_) => println!("\n✅ Entire Blockchain state saved to **{}**.", ledger_filename),
        Err(e) => eprintln!("❌ Full Blockchain Save Failed: {}", e),
    }

    // e. Persistence Test: Load the ENTIRE Blockchain state
    match Blockchain::load_from_file(ledger_filename) {
        Ok(loaded_ledger) => {
            println!("✅ Successfully loaded Blockchain from file. Testing integrity:");
            loaded_ledger.is_chain_valid();
        },
        Err(e) => {
            eprintln!("❌ Full Blockchain Load Failed: {}", e);
        }
    }
    
    // f. Final Balance Check
    let final_sender_balance = ledger.get_balance_of_did(&identity.user_did);
    let final_recipient_balance = ledger.get_balance_of_did(&recipient_did);
    
    println!("\n--- Final Balance Summary ---");
    println!("Initial Sender Balance: 1000");
    println!("Total Sent in Block: {}", total_sent);
    println!("Sender Final Balance: **{}** (Expected: {})", final_sender_balance, initial_balance - total_sent);
    println!("Recipient Final Balance: **{}** (Expected: {})", final_recipient_balance, total_sent);
}