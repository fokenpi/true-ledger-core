/*
 * TRUE LEDGER CORE - PHASE 1, PHASE 2, & PHASE 3
 *
 * This version implements the complete, fixed core logic:
 * 1. Identity and Key Recovery (Argon2/PBKDF2).
 * 2. Transaction Signing and Verification (Ed25519).
 * 3. Data Integrity and Batching via a Self-Contained Merkle Tree (FIXED).
 */

// --- General Imports ---
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fs;

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
#[derive(Serialize, Deserialize, Debug)]
struct Transaction {
    from_did: String,
    to_did: String,
    amount: u64,
    timestamp: u64,
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


// --- PHASE 3: SELF-CONTAINED MERKLE TREE CORE FUNCTIONS (FIXED) ---

/// Hashes a single item (a leaf or an intermediate node).
fn hash_item(a: &[u8], b: Option<&[u8]>) -> HashType {
    let mut hasher = Sha256::new();
    hasher.update(a);
    if let Some(b) = b {
        hasher.update(b);
    } else {
        // Rule: If a node has no sibling (odd number of leaves), hash it with itself.
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


/// 8. Recursively builds the Merkle Tree and returns the root hash.
fn build_simple_merkle_root(mut leaves: Vec<HashType>) -> String {
    println!("\n🌳 Creating Merkle Tree from {} transactions...", leaves.len());

    if leaves.is_empty() {
        return "Empty Tree".to_string();
    }
    
    // Recursive loop until only one hash remains (the root)
    while leaves.len() > 1 {
        let mut next_level = Vec::new();
        let mut i = 0;
        
        while i < leaves.len() {
            let left = &leaves[i];
            
            // Check for sibling (right node)
            let right = leaves.get(i + 1); 
            
            // Hash the pair (or hash the single item with itself if odd)
            let new_hash = hash_item(left, right.map(|r| r.as_ref()));
            next_level.push(new_hash);
            
            i += 2; // Move to the next pair
        }
        
        leaves = next_level;
    }

    // The last remaining hash is the root.
    let root_bytes = leaves[0];
    let root_hash = hex::encode(root_bytes);
    
    println!("✅ Merkle Root Generated.");
    root_hash
}


// --- MAIN PROGRAM: Test the full cycle ---
fn main() {
    let user_password = "MySecurePassword123";
    
    println!("--- Starting True Ledger Core: Phases 1, 2, & 3 ---\n");

    // --- 1. Phase 1: Identity Creation & KEK Tests (Login) ---
    
    let identity = create_user_identity(user_password);
    
    // Test KEK-A (Password) and get the Keypair
    let salt_a = SaltString::new(&identity.salt).unwrap();
    let kek_a_derived = derive_key_from_password(user_password, &salt_a);
    
    let keypair_result = decrypt_key(kek_a_derived, &identity);
    let keypair = match keypair_result {
        Ok(kp) => {
            println!("✅ Phase 1 SUCCESS: Identity keypair loaded for signing.");
            kp
        },
        Err(e) => {
            println!("❌ Phase 1 FAILED: Could not load keypair: {}", e);
            return; 
        }
    };
    
    // --- 2. Phase 3: Transaction Batching and Merkle Root ---

    let recipient_did = "did:key:z6Mkk7pLq4eYfW3yVw6jJv".to_string(); 
    let mut transaction_hashes: Vec<HashType> = Vec::new(); 
    let num_transactions = 5;

    for i in 0..num_transactions {
        // a. Create transaction data
        let transaction = Transaction {
            from_did: identity.user_did.clone(),
            to_did: recipient_did.clone(),
            amount: 100 + i, 
            timestamp: 1730908800 + i as u64,
        };

        // b. Sign the transaction (Phase 2)
        let signature = sign_transaction(&keypair, &transaction);
        
        // c. Verification Check
        if !verify_signature(&identity.user_did, &transaction, &signature) {
            eprintln!("Error: Signature failed verification for transaction {}", i);
            continue;
        }

        // d. Create the unique hash for the Merkle Tree (Phase 3)
        let tx_hash_bytes = create_transaction_hash(&transaction, &signature);
        
        // Push the fixed-size hash directly
        transaction_hashes.push(tx_hash_bytes); 
        println!("   [TX {}] Hash: {}", i, hex::encode(tx_hash_bytes));
    }
    
    // 3. Generate the Merkle Root for the entire batch
    let merkle_root = build_simple_merkle_root(transaction_hashes);

    println!("\n--- Phase 3: Data Integrity and Batching Complete ---");
    println!("Final Merkle Root: **{}**", merkle_root);
}