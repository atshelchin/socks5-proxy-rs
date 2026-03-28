//! VMess AEAD cryptographic primitives
//!
//! KDF matches v2ray-core's nested HMAC implementation exactly:
//! Each level uses the previous level's HMAC as its hash function.

use aes::Aes128;
use aes_gcm::{aead::KeyInit, Aes128Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use cipher::{BlockEncrypt, generic_array::GenericArray};
use hmac::{Hmac, Mac};
use md5::Md5;
use sha2::{Digest, Sha256};

const VMESS_AUTH_ID_SALT: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
const KDF_SALT: &[u8] = b"VMess AEAD KDF";
const HMAC_BLOCK_SIZE: usize = 64;

// --- UUID ---

pub fn uuid_to_bytes(uuid: &str) -> [u8; 16] {
    let hex: String = uuid.chars().filter(|c| *c != '-').collect();
    let mut bytes = [0u8; 16];
    for i in 0..16 {
        bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    bytes
}

// --- Command Key ---

pub fn compute_cmd_key(uuid_bytes: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(uuid_bytes);
    h.update(VMESS_AUTH_ID_SALT);
    let result = h.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&result);
    key
}

// --- VMess KDF (nested HMAC-SHA256) ---

pub fn vmess_kdf(key: &[u8], paths: &[&[u8]]) -> [u8; 32] {
    let result = hash_at_level(paths, paths.len(), key);
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn hash_at_level(paths: &[&[u8]], level: usize, data: &[u8]) -> Vec<u8> {
    if level == 0 {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(KDF_SALT).unwrap();
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    } else {
        let path_key = paths[level - 1];

        // Normalize key to block size
        let k = if path_key.len() <= HMAC_BLOCK_SIZE {
            let mut buf = vec![0u8; HMAC_BLOCK_SIZE];
            buf[..path_key.len()].copy_from_slice(path_key);
            buf
        } else {
            let hashed = hash_at_level(paths, level - 1, path_key);
            let mut buf = vec![0u8; HMAC_BLOCK_SIZE];
            let copy_len = hashed.len().min(HMAC_BLOCK_SIZE);
            buf[..copy_len].copy_from_slice(&hashed[..copy_len]);
            buf
        };

        let mut ipad = vec![0u8; HMAC_BLOCK_SIZE];
        let mut opad = vec![0u8; HMAC_BLOCK_SIZE];
        for i in 0..HMAC_BLOCK_SIZE {
            ipad[i] = k[i] ^ 0x36;
            opad[i] = k[i] ^ 0x5c;
        }

        let mut inner_data = ipad;
        inner_data.extend_from_slice(data);
        let inner_result = hash_at_level(paths, level - 1, &inner_data);

        let mut outer_data = opad;
        outer_data.extend_from_slice(&inner_result);
        hash_at_level(paths, level - 1, &outer_data)
    }
}

// --- AuthID ---

pub fn generate_auth_id(cmd_key: &[u8], timestamp: u64) -> [u8; 16] {
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&timestamp.to_be_bytes());

    let mut rand4 = [0u8; 4];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut rand4);
    buf[8..12].copy_from_slice(&rand4);

    let crc = crc32_ieee(&buf[0..12]);
    buf[12..16].copy_from_slice(&crc.to_be_bytes());

    // AES key for AuthID = KDF16(cmdKey, "AES Auth ID Encryption")
    let aes_key = vmess_kdf(cmd_key, &[b"AES Auth ID Encryption"]);
    let key = GenericArray::from_slice(&aes_key[..16]);
    let cipher = Aes128::new(key);

    let mut block = GenericArray::clone_from_slice(&buf);
    cipher.encrypt_block(&mut block);
    let mut result = [0u8; 16];
    result.copy_from_slice(&block);
    result
}

// --- CRC32 (IEEE) ---

pub fn crc32_ieee(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

// --- FNV-1a 32-bit ---

pub fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

// --- AEAD wrappers ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgorithm {
    Aes128Gcm,
    ChaCha20Poly1305,
}

pub fn aead_seal(
    algorithm: AeadAlgorithm,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> Vec<u8> {
    use aes_gcm::aead::Aead;

    match algorithm {
        AeadAlgorithm::Aes128Gcm => {
            let cipher = Aes128Gcm::new(GenericArray::from_slice(key));
            let nonce = GenericArray::from_slice(nonce);
            let payload = if let Some(aad) = aad {
                aes_gcm::aead::Payload {
                    msg: plaintext,
                    aad,
                }
            } else {
                aes_gcm::aead::Payload {
                    msg: plaintext,
                    aad: &[],
                }
            };
            cipher.encrypt(nonce, payload).expect("encryption failed")
        }
        AeadAlgorithm::ChaCha20Poly1305 => {
            let cipher =
                ChaCha20Poly1305::new(GenericArray::from_slice(key));
            let nonce = GenericArray::from_slice(nonce);
            let payload = if let Some(aad) = aad {
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad,
                }
            } else {
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad: &[],
                }
            };
            cipher.encrypt(nonce, payload).expect("encryption failed")
        }
    }
}

pub fn aead_open(
    algorithm: AeadAlgorithm,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>, ()> {
    use aes_gcm::aead::Aead;

    match algorithm {
        AeadAlgorithm::Aes128Gcm => {
            let cipher = Aes128Gcm::new(GenericArray::from_slice(key));
            let nonce = GenericArray::from_slice(nonce);
            let payload = if let Some(aad) = aad {
                aes_gcm::aead::Payload {
                    msg: ciphertext,
                    aad,
                }
            } else {
                aes_gcm::aead::Payload {
                    msg: ciphertext,
                    aad: &[],
                }
            };
            cipher.decrypt(nonce, payload).map_err(|_| ())
        }
        AeadAlgorithm::ChaCha20Poly1305 => {
            let cipher =
                ChaCha20Poly1305::new(GenericArray::from_slice(key));
            let nonce = GenericArray::from_slice(nonce);
            let payload = if let Some(aad) = aad {
                chacha20poly1305::aead::Payload {
                    msg: ciphertext,
                    aad,
                }
            } else {
                chacha20poly1305::aead::Payload {
                    msg: ciphertext,
                    aad: &[],
                }
            };
            cipher.decrypt(nonce, payload).map_err(|_| ())
        }
    }
}

// --- Key/IV derivation for body ---

pub fn derive_request_body_key_iv(
    data_key: &[u8],
    data_iv: &[u8],
    security: AeadAlgorithm,
) -> (Vec<u8>, Vec<u8>) {
    match security {
        AeadAlgorithm::Aes128Gcm => {
            let key = Sha256::digest(data_key);
            let iv = Sha256::digest(data_iv);
            (key[..16].to_vec(), iv[..16].to_vec())
        }
        AeadAlgorithm::ChaCha20Poly1305 => {
            let md5_1 = Md5::digest(data_key);
            let md5_2 = Md5::digest(&md5_1);
            let key = [md5_1.as_slice(), md5_2.as_slice()].concat();
            let iv = Md5::digest(data_iv).to_vec();
            (key, iv)
        }
    }
}

pub fn derive_response_body_key_iv(
    request_body_key: &[u8],
    request_body_iv: &[u8],
    security: AeadAlgorithm,
) -> (Vec<u8>, Vec<u8>) {
    match security {
        AeadAlgorithm::Aes128Gcm => {
            let key = Sha256::digest(request_body_key);
            let iv = Sha256::digest(request_body_iv);
            (key[..16].to_vec(), iv[..16].to_vec())
        }
        AeadAlgorithm::ChaCha20Poly1305 => {
            let md5_1 = Md5::digest(request_body_key);
            let md5_2 = Md5::digest(&md5_1);
            let key = [md5_1.as_slice(), md5_2.as_slice()].concat();
            let iv = Md5::digest(request_body_iv).to_vec();
            (key, iv)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuid_to_bytes() {
        let bytes = uuid_to_bytes("1afc1706-34ff-41b1-9dc8-b3ab9ecb6e00");
        assert_eq!(bytes.len(), 16);
        assert_eq!(
            hex::encode(bytes),
            "1afc170634ff41b19dc8b3ab9ecb6e00"
        );
    }

    #[test]
    fn test_compute_cmd_key() {
        let uuid_bytes = uuid_to_bytes("1afc1706-34ff-41b1-9dc8-b3ab9ecb6e00");
        let cmd_key = compute_cmd_key(&uuid_bytes);
        assert_eq!(cmd_key.len(), 16);
        // Verify: MD5(uuid_bytes + salt)
        let mut h = Md5::new();
        h.update(&uuid_bytes);
        h.update(VMESS_AUTH_ID_SALT);
        let expected: [u8; 16] = h.finalize().into();
        assert_eq!(cmd_key, expected);
    }

    #[test]
    fn test_crc32_standard() {
        assert_eq!(crc32_ieee(b"123456789"), 0xcbf43926);
    }

    #[test]
    fn test_crc32_empty() {
        assert_eq!(crc32_ieee(b""), 0x00000000);
    }

    #[test]
    fn test_fnv1a32_hello() {
        assert_eq!(fnv1a32(b"hello"), 0x4f9f2cab);
    }

    #[test]
    fn test_fnv1a32_empty() {
        assert_eq!(fnv1a32(b""), 0x811c9dc5);
    }

    #[test]
    fn test_kdf_base_case() {
        let test_key = b"testkey";
        let result = vmess_kdf(test_key, &[]);
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(KDF_SALT).unwrap();
        mac.update(test_key);
        let expected: Vec<u8> = mac.finalize().into_bytes().to_vec();
        assert_eq!(result.to_vec(), expected);
    }

    #[test]
    fn test_kdf_1_path_differs_from_simple_chain() {
        let test_key = b"testkey";
        let result = vmess_kdf(test_key, &[b"path1"]);
        // Simple (wrong) chain: HMAC(key=HMAC("path1", "VMess AEAD KDF"), msg=testkey)
        let inner = <Hmac<Sha256> as Mac>::new_from_slice(b"path1")
            .unwrap()
            .chain_update(KDF_SALT)
            .finalize()
            .into_bytes();
        let simple_chain = <Hmac<Sha256> as Mac>::new_from_slice(&inner)
            .unwrap()
            .chain_update(test_key)
            .finalize()
            .into_bytes();
        // Nested HMAC should differ from simple chain
        assert_ne!(result.to_vec(), simple_chain.to_vec());
    }

    #[test]
    fn test_kdf_deterministic() {
        let test_key = b"testkey";
        let p2 = b"p2";
        let a = vmess_kdf(test_key, &[b"p1", &p2[..]]);
        let b = vmess_kdf(test_key, &[b"p1", &p2[..]]);
        assert_eq!(a, b);
    }

    #[test]
    fn test_kdf_different_paths() {
        let test_key = b"testkey";
        let a = vmess_kdf(test_key, &[b"path_a"]);
        let b = vmess_kdf(test_key, &[b"path_b"]);
        assert_ne!(a, b);
    }

    #[test]
    fn test_kdf_output_32_bytes() {
        let test_key = b"testkey";
        assert_eq!(vmess_kdf(test_key, &[]).len(), 32);
        assert_eq!(vmess_kdf(test_key, &[b"p1"]).len(), 32);
        assert_eq!(vmess_kdf(test_key, &[b"p1", b"p2", b"p3"]).len(), 32);
    }

    #[test]
    fn test_aead_aes_gcm_roundtrip() {
        let key = [0x03u8; 16];
        let nonce = [0x04u8; 12];
        let plaintext = b"hello vmess world";
        let aad = b"additional-data";
        let sealed = aead_seal(AeadAlgorithm::Aes128Gcm, &key, &nonce, plaintext, Some(aad));
        assert_eq!(sealed.len(), plaintext.len() + 16);
        let opened = aead_open(AeadAlgorithm::Aes128Gcm, &key, &nonce, &sealed, Some(aad)).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn test_aead_aes_gcm_no_aad() {
        let key = [0x03u8; 16];
        let nonce = [0x04u8; 12];
        let plaintext = b"hello vmess world";
        let sealed = aead_seal(AeadAlgorithm::Aes128Gcm, &key, &nonce, plaintext, None);
        let opened = aead_open(AeadAlgorithm::Aes128Gcm, &key, &nonce, &sealed, None).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn test_aead_wrong_key() {
        let key = [0x03u8; 16];
        let nonce = [0x04u8; 12];
        let plaintext = b"hello vmess world";
        let aad = b"additional-data";
        let sealed = aead_seal(AeadAlgorithm::Aes128Gcm, &key, &nonce, plaintext, Some(aad));
        let wrong_key = [0xffu8; 16];
        assert!(aead_open(AeadAlgorithm::Aes128Gcm, &wrong_key, &nonce, &sealed, Some(aad)).is_err());
    }

    #[test]
    fn test_aead_wrong_aad() {
        let key = [0x03u8; 16];
        let nonce = [0x04u8; 12];
        let plaintext = b"hello vmess world";
        let aad = b"additional-data";
        let sealed = aead_seal(AeadAlgorithm::Aes128Gcm, &key, &nonce, plaintext, Some(aad));
        assert!(aead_open(AeadAlgorithm::Aes128Gcm, &key, &nonce, &sealed, Some(b"wrong")).is_err());
    }

    #[test]
    fn test_auth_id_produces_16_bytes() {
        let cmd_key = [0xaau8; 16];
        let auth_id = generate_auth_id(&cmd_key, std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs());
        assert_eq!(auth_id.len(), 16);
    }

    #[test]
    fn test_auth_id_decrypts_valid() {
        let cmd_key = [0xaau8; 16];
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let auth_id = generate_auth_id(&cmd_key, timestamp);

        // Decrypt
        let aes_key_full = vmess_kdf(&cmd_key, &[b"AES Auth ID Encryption"]);
        let key = GenericArray::from_slice(&aes_key_full[..16]);
        let cipher = Aes128::new(key);
        use cipher::BlockDecrypt;
        let mut block = GenericArray::clone_from_slice(&auth_id);
        cipher.decrypt_block(&mut block);
        let decrypted: &[u8] = block.as_slice();

        let ts = u64::from_be_bytes(decrypted[0..8].try_into().unwrap());
        assert_eq!(ts, timestamp);

        let expected_crc = crc32_ieee(&decrypted[0..12]);
        let actual_crc = u32::from_be_bytes(decrypted[12..16].try_into().unwrap());
        assert_eq!(actual_crc, expected_crc);
    }

    #[test]
    fn test_auth_id_different_timestamps() {
        let cmd_key = [0xaau8; 16];
        let a = generate_auth_id(&cmd_key, 1000000);
        let b = generate_auth_id(&cmd_key, 1000001);
        assert_ne!(a, b);
    }

    #[test]
    fn test_request_body_key_gcm() {
        let data_key: Vec<u8> = (0..16).collect();
        let data_iv: Vec<u8> = (16..32).collect();
        let (key, iv) = derive_request_body_key_iv(&data_key, &data_iv, AeadAlgorithm::Aes128Gcm);
        let expected_key = &Sha256::digest(&data_key)[..16];
        let expected_iv = &Sha256::digest(&data_iv)[..16];
        assert_eq!(key, expected_key);
        assert_eq!(iv, expected_iv);
    }

    #[test]
    fn test_response_body_key_gcm() {
        let data_key: Vec<u8> = (0..16).collect();
        let data_iv: Vec<u8> = (16..32).collect();
        let (req_key, req_iv) = derive_request_body_key_iv(&data_key, &data_iv, AeadAlgorithm::Aes128Gcm);
        let (resp_key, resp_iv) = derive_response_body_key_iv(&req_key, &req_iv, AeadAlgorithm::Aes128Gcm);
        let expected_key = &Sha256::digest(&req_key)[..16];
        let expected_iv = &Sha256::digest(&req_iv)[..16];
        assert_eq!(resp_key, expected_key);
        assert_eq!(resp_iv, expected_iv);
    }

    #[test]
    fn test_request_response_keys_differ() {
        let data_key: Vec<u8> = (0..16).collect();
        let data_iv: Vec<u8> = (16..32).collect();
        let (req_key, _) = derive_request_body_key_iv(&data_key, &data_iv, AeadAlgorithm::Aes128Gcm);
        let (resp_key, _) = derive_response_body_key_iv(&req_key, &data_iv, AeadAlgorithm::Aes128Gcm);
        assert_ne!(req_key, resp_key);
    }
}

// Helper for tests - hex encoding
#[cfg(test)]
mod hex {
    pub fn encode(data: impl AsRef<[u8]>) -> String {
        data.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
    }
}
