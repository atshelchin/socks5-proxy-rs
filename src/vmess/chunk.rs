//! VMess chunked stream encoder/decoder
//!
//! Option 0x01 (chunk stream, no masking):
//!   [2 bytes BE length (plaintext_len + 16)] [AEAD-encrypted payload]

use super::crypto::{AeadAlgorithm, aead_open, aead_seal};

const MAX_CHUNK_SIZE: usize = 1 << 14; // 16KB

fn make_nonce(base_iv: &[u8], count: u16) -> Vec<u8> {
    let mut nonce = vec![0u8; 12];
    let copy_len = base_iv.len().min(12);
    nonce[..copy_len].copy_from_slice(&base_iv[..copy_len]);
    nonce[0..2].copy_from_slice(&count.to_be_bytes());
    nonce
}

// ============================================================
// Encoder
// ============================================================

pub struct ChunkEncoder {
    key: Vec<u8>,
    iv: Vec<u8>,
    algorithm: AeadAlgorithm,
    count: u16,
}

impl ChunkEncoder {
    pub fn new(key: &[u8], iv: &[u8], algorithm: AeadAlgorithm) -> Self {
        Self {
            key: key.to_vec(),
            iv: iv.to_vec(),
            algorithm,
            count: 0,
        }
    }

    pub fn encode(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        let mut offset = 0;

        while offset < plaintext.len() {
            let end = (offset + MAX_CHUNK_SIZE).min(plaintext.len());
            let chunk = &plaintext[offset..end];

            let nonce = make_nonce(&self.iv, self.count);
            self.count += 1;
            let encrypted = aead_seal(self.algorithm, &self.key, &nonce, chunk, None);

            // 2-byte length header (includes tag)
            let len = encrypted.len() as u16;
            result.extend_from_slice(&len.to_be_bytes());
            result.extend_from_slice(&encrypted);
            offset = end;
        }

        result
    }
}

// ============================================================
// Decoder
// ============================================================

pub struct ChunkDecoder {
    key: Vec<u8>,
    iv: Vec<u8>,
    algorithm: AeadAlgorithm,
    count: u16,
    buffer: Vec<u8>,
}

impl ChunkDecoder {
    pub fn new(key: &[u8], iv: &[u8], algorithm: AeadAlgorithm) -> Self {
        Self {
            key: key.to_vec(),
            iv: iv.to_vec(),
            algorithm,
            count: 0,
            buffer: Vec::new(),
        }
    }

    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<Vec<u8>>, ()> {
        if self.buffer.is_empty() {
            self.buffer = data.to_vec();
        } else {
            self.buffer.extend_from_slice(data);
        }

        let mut results = Vec::new();

        while self.buffer.len() >= 2 {
            let chunk_len =
                u16::from_be_bytes([self.buffer[0], self.buffer[1]]) as usize;

            if chunk_len == 0 {
                // End of stream
                self.buffer = self.buffer[2..].to_vec();
                break;
            }

            if self.buffer.len() < 2 + chunk_len {
                break;
            }

            let encrypted = &self.buffer[2..2 + chunk_len];
            let nonce = make_nonce(&self.iv, self.count);
            self.count += 1;
            let plaintext = aead_open(self.algorithm, &self.key, &nonce, encrypted, None)?;
            results.push(plaintext);

            self.buffer = self.buffer[2 + chunk_len..].to_vec();
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_small() {
        let key = [0x05u8; 16];
        let iv = [0x06u8; 16];
        let mut encoder = ChunkEncoder::new(&key, &iv, AeadAlgorithm::Aes128Gcm);
        let mut decoder = ChunkDecoder::new(&key, &iv, AeadAlgorithm::Aes128Gcm);

        let plain = b"Hello, VMess!";
        let encoded = encoder.encode(plain);
        assert!(encoded.len() > plain.len());

        let decoded = decoder.decode(&encoded).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0], plain);
    }

    #[test]
    fn test_roundtrip_large() {
        let key = [0x05u8; 16];
        let iv = [0x06u8; 16];
        let mut encoder = ChunkEncoder::new(&key, &iv, AeadAlgorithm::Aes128Gcm);
        let mut decoder = ChunkDecoder::new(&key, &iv, AeadAlgorithm::Aes128Gcm);

        // 32KB - will split into 2 chunks
        let plain = vec![0x41u8; 32 * 1024];
        let encoded = encoder.encode(&plain);

        let decoded = decoder.decode(&encoded).unwrap();
        assert_eq!(decoded.len(), 2);
        let reassembled: Vec<u8> = decoded.into_iter().flatten().collect();
        assert_eq!(reassembled, plain);
    }

    #[test]
    fn test_fragmented_input() {
        let key = [0x05u8; 16];
        let iv = [0x06u8; 16];
        let mut encoder = ChunkEncoder::new(&key, &iv, AeadAlgorithm::Aes128Gcm);
        let mut decoder = ChunkDecoder::new(&key, &iv, AeadAlgorithm::Aes128Gcm);

        let plain = b"fragmented data test";
        let encoded = encoder.encode(plain);

        // Feed byte by byte
        let mut results = Vec::new();
        for i in 0..encoded.len() {
            let chunks = decoder.decode(&encoded[i..i + 1]).unwrap();
            results.extend(chunks);
        }
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], plain);
    }

    #[test]
    fn test_multiple_encodes() {
        let key = [0x05u8; 16];
        let iv = [0x06u8; 16];
        let mut encoder = ChunkEncoder::new(&key, &iv, AeadAlgorithm::Aes128Gcm);
        let mut decoder = ChunkDecoder::new(&key, &iv, AeadAlgorithm::Aes128Gcm);

        let msg1 = b"message one";
        let msg2 = b"message two";

        let enc1 = encoder.encode(msg1);
        let enc2 = encoder.encode(msg2);

        let dec1 = decoder.decode(&enc1).unwrap();
        let dec2 = decoder.decode(&enc2).unwrap();
        assert_eq!(dec1[0], msg1);
        assert_eq!(dec2[0], msg2);
    }

    #[test]
    fn test_wrong_key() {
        let key = [0x05u8; 16];
        let iv = [0x06u8; 16];
        let mut encoder = ChunkEncoder::new(&key, &iv, AeadAlgorithm::Aes128Gcm);
        let mut wrong_decoder =
            ChunkDecoder::new(&[0xffu8; 16], &iv, AeadAlgorithm::Aes128Gcm);

        let encoded = encoder.encode(b"secret");
        assert!(wrong_decoder.decode(&encoded).is_err());
    }
}
