/*
 * TRUE LEDGER CORE - FINAL VERSION (Modularized)
 *
 * This file acts as the application entry point and test runner.
 * Core logic is now managed in src/crypto.rs and src/ledger.rs.
 */

// --- Module Declarations ---
mod crypto;
mod ledger;

// --- Imports from Modules ---
use ed25519_dalek::{Keypair, Signer};
use ledger::{Blockchain, Transaction, create_transaction_hash, HashType};
use argon2::password_hash::SaltString;

// --- Constants (Main app constants) ---
const HASH_SIZE: usize = 32;

// --- Transaction Signing (Must be implemented here as it uses Keypair from crypto, 
//     but needs to be callable by ledger::mine_pending_transactions) ---

/// Signs a transaction using the user's decrypted Keypair.
fn sign_transaction(keypair: &Keypair, transaction: &Transaction) -> Vec<u8> {
    let transaction_bytes = serde_json::to_vec(transaction)
        .expect("Failed to serialize transaction");

    let signature = keypair.sign(&transaction_bytes);
    signature.to_bytes().to_vec()
}


// --- MAIN PROGRAM: Test the full cycle ---
fn main() {
    let user_password = "MySecurePassword123";
    let mining_difficulty = 4; // Difficulty for PoW

    println!("--- Starting True Ledger Core: Blockchain Initialization ---\n");
    
    // 1. Initialize the Blockchain with the Genesis Block
    let mut ledger = Blockchain::new(mining_difficulty);
    
    // --- 2. Identity Creation & Login ---
    let identity = crypto::create_user_identity(user_password);
    let salt_a = SaltString::new(&identity.salt).unwrap();
    let kek_a_derived = crypto::derive_key_from_password(user_password, &salt_a);
    
    let keypair_result = crypto::decrypt_key(kek_a_derived, &identity);
    let keypair = match keypair_result {
        Ok(kp) => {
            println!("\n✅ Identity keypair loaded for signing.");
            kp
        },
        Err(e) => {
            eprintln!("❌ Identity FAILED: Could not load keypair: {}", e);
            return; 
        }
    };
    
    // --- 3. Add Transactions to Pool ---
    let recipient_did = "did:key:z6Mkk7pLq4eYfW3yVw6jJv".to_string(); 
    let num_transactions = 5;
    
    println!("\n--- Phase 3: Adding Transactions to Pool (Sender: {}) ---", &identity.user_did[..10]);
    
    // SIMULATION: Manually add a starting credit to the sender in the Genesis Block
    if let Some(genesis) = ledger.chain.get_mut(0) {
        genesis.transactions.push(Transaction {
            from_did: "Genesis".to_string(),
            to_did: identity.user_did.clone(),
            amount: 1000,
            timestamp: 1730908700,
        });
    }

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
    
    // Pass the local 'sign_transaction' function reference to the ledger module
    let block_hash = match ledger.mine_pending_transactions(sign_transaction, &keypair) {
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
    
    // --- 5. Post-Mining Validation and Persistence ---

    // a. Chain Validation
    ledger.is_chain_valid();
    
    // b. Persistence Test: Save the ENTIRE Blockchain state
    let ledger_filename = "true_ledger_state.json";
    
    match ledger.save_to_file(ledger_filename) {
        Ok(_) => println!("\n✅ Entire Blockchain state saved to **{}**.", ledger_filename),
        Err(e) => eprintln!("❌ Full Blockchain Save Failed: {}", e),
    }

    // c. Persistence Test: Load the ENTIRE Blockchain state
    match Blockchain::load_from_file(ledger_filename) {
        Ok(loaded_ledger) => {
            println!("✅ Successfully loaded Blockchain from file. Testing integrity:");
            loaded_ledger.is_chain_valid();
        },
        Err(e) => {
            eprintln!("❌ Full Blockchain Load Failed: {}", e);
        }
    }
    
    // d. Final Balance Check
    let final_sender_balance = ledger.get_balance_of_did(&identity.user_did);
    let final_recipient_balance = ledger.get_balance_of_did(&recipient_did);
    
    println!("\n--- Final Balance Summary ---");
    println!("Initial Sender Balance: 1000");
    println!("Total Sent in Block: {}", total_sent);
    println!("Sender Final Balance: **{}** (Expected: {})", final_sender_balance, initial_balance - total_sent);
    println!("Recipient Final Balance: **{}** (Expected: {})", final_recipient_balance, total_sent);
}