use ed25519_dalek::{Keypair, Signature, Signer, Verifier};
use argon2::{
    password_hash::{
        rand_core::OsRng as ArgonRng, PasswordHash, PasswordHasher, SaltString, 
    },
    Argon2
};
use pbkdf2::pbkdf2_hmac_array;
use sha2::{Digest, Sha256};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce
};
use rand_core::{OsRng, RngCore}; 
use serde::{Deserialize, Serialize};

// --- CONSTANTS ---
const KEY_SIZE: usize = 32; 
const RECOVERY_ITERATIONS: u32 = 100_000;

// --- DATA STRUCTURES (Used only by Crypto functions) ---

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedIdentity {
    pub user_did: String,         
    pub encrypted_key: Vec<u8>,   
    pub nonce: Vec<u8>,           
    pub salt: String,             
    pub recovery_salt: String,    
}

// --- PUBLIC FUNCTIONS ---

/// Derives KEK-A (32-byte key) from user password using Argon2.
pub fn derive_key_from_password(password: &str, salt: &SaltString) -> [u8; KEY_SIZE] {
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

/// Derives KEK-B (32-byte key) from a recovery code using PBKDF2.
pub fn derive_key_from_recovery_code(code: &str, salt_str: &str) -> [u8; KEY_SIZE] {
    
    let salt_bytes = hex::decode(salt_str).expect("Invalid hex salt");
    
    pbkdf2_hmac_array::<Sha256, KEY_SIZE>(
        &code.as_bytes(), 
        &salt_bytes, 
        RECOVERY_ITERATIONS
    )
}

/// Creates a new user identity and encrypts it with the password (KEK-A).
pub fn create_user_identity(password: &str) -> EncryptedIdentity {
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

/// Decrypts the key using a provided KEK.
pub fn decrypt_key(kek: [u8; KEY_SIZE], identity_bundle: &EncryptedIdentity) -> Result<Keypair, String> {
    let cipher = ChaCha20Poly1305::new(&kek.into());
    let nonce = Nonce::from_slice(&identity_bundle.nonce);

    let decrypted_bytes = cipher.decrypt(nonce, identity_bundle.encrypted_key.as_ref())
        .map_err(|_| "DECRYPTION FAILED: Invalid key or MAC.".to_string())?;

    Keypair::from_bytes(&decrypted_bytes)
        .map_err(|_| "Keypair reconstruction failed (decryption corruption).".to_string())
}