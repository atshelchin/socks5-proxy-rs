//! VMess AEAD client implementation (alterId=0)


#[cfg(test)]
use super::chunk::ChunkEncoder;
use super::chunk::ChunkDecoder;
use super::crypto::*;

// --- Config ---

#[derive(Debug, Clone)]
pub struct VMessUpstream {
    pub address: String,
    pub port: u16,
    pub uuid: String,
    pub security: Security,
    pub network: Network,
    pub tls: bool,
    pub ws_path: Option<String>,
    pub ws_host: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    Aes128Gcm,
    ChaCha20Poly1305,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Ws,
}

impl Security {
    pub fn byte(&self) -> u8 {
        match self {
            Security::Aes128Gcm => 0x03,
            Security::ChaCha20Poly1305 => 0x04,
            Security::None => 0x05,
        }
    }

    pub fn aead_algo(&self) -> AeadAlgorithm {
        match self {
            Security::ChaCha20Poly1305 => AeadAlgorithm::ChaCha20Poly1305,
            _ => AeadAlgorithm::Aes128Gcm,
        }
    }
}

// --- Pre-computed session keys ---

#[derive(Debug, Clone)]
pub struct VMessSession {
    pub uuid_bytes: [u8; 16],
    pub cmd_key: [u8; 16],
    pub config: VMessUpstream,
}

impl VMessSession {
    pub fn new(config: VMessUpstream) -> Self {
        let uuid_bytes = uuid_to_bytes(&config.uuid);
        let cmd_key = compute_cmd_key(&uuid_bytes);
        Self {
            uuid_bytes,
            cmd_key,
            config,
        }
    }
}

// --- Build request header ---

pub struct RequestResult {
    pub header_buf: Vec<u8>,
    pub request_body_key: Vec<u8>,
    pub request_body_iv: Vec<u8>,
    pub response_body_key: Vec<u8>,
    pub response_body_iv: Vec<u8>,
    pub response_auth_v: u8,
}

pub fn build_request(
    session: &VMessSession,
    target_host: &str,
    target_port: u16,
) -> RequestResult {
    let cmd_key = &session.cmd_key;
    let config = &session.config;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut rng = rand::thread_rng();

    // Random keys for this connection
    let mut raw_key = [0u8; 16];
    let mut raw_iv = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rng, &mut raw_key);
    rand::RngCore::fill_bytes(&mut rng, &mut raw_iv);

    let algo = config.security.aead_algo();
    let (data_key, data_iv) = derive_request_body_key_iv(&raw_key, &raw_iv, algo);

    let mut response_auth_v = [0u8; 1];
    rand::RngCore::fill_bytes(&mut rng, &mut response_auth_v);
    let response_auth_v = response_auth_v[0];

    let sec_byte = config.security.byte();
    let option = 0x01u8; // chunk stream
    let padding_len = 0u8;

    // Address encoding
    let (addr_type, addr_buf) = encode_address(target_host);

    // Build instruction
    let instr_len = 1 + 16 + 16 + 1 + 1 + 1 + 1 + 1 + 2 + 1 + addr_buf.len() + padding_len as usize;
    let mut instruction = vec![0u8; instr_len + 4]; // +4 for FNV1a

    let mut offset = 0;
    instruction[offset] = 0x01; // Version
    offset += 1;
    instruction[offset..offset + 16].copy_from_slice(&data_iv[..16]);
    offset += 16;
    instruction[offset..offset + 16].copy_from_slice(&data_key[..16]);
    offset += 16;
    instruction[offset] = response_auth_v;
    offset += 1;
    instruction[offset] = option;
    offset += 1;
    instruction[offset] = (padding_len << 4) | sec_byte;
    offset += 1;
    instruction[offset] = 0x00; // Reserved
    offset += 1;
    instruction[offset] = 0x01; // CMD: TCP
    offset += 1;
    instruction[offset..offset + 2].copy_from_slice(&target_port.to_be_bytes());
    offset += 2;
    instruction[offset] = addr_type;
    offset += 1;
    instruction[offset..offset + addr_buf.len()].copy_from_slice(&addr_buf);
    offset += addr_buf.len();

    // FNV1a of everything before it
    let fnv = fnv1a32(&instruction[..offset]);
    instruction[offset..offset + 4].copy_from_slice(&fnv.to_be_bytes());

    // Generate AuthID
    let auth_id = generate_auth_id(cmd_key, timestamp);

    // Connection nonce
    let mut connection_nonce = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rng, &mut connection_nonce);

    // Derive header encryption keys
    let header_length_key = vmess_kdf(
        cmd_key,
        &[b"VMess Header AEAD Key_Length", &auth_id[..], &connection_nonce[..]],
    );
    let header_length_iv = vmess_kdf(
        cmd_key,
        &[b"VMess Header AEAD Nonce_Length", &auth_id[..], &connection_nonce[..]],
    );
    let header_payload_key = vmess_kdf(
        cmd_key,
        &[b"VMess Header AEAD Key", &auth_id[..], &connection_nonce[..]],
    );
    let header_payload_iv = vmess_kdf(
        cmd_key,
        &[b"VMess Header AEAD Nonce", &auth_id[..], &connection_nonce[..]],
    );

    // Encrypt header
    let mut instr_len_buf = [0u8; 2];
    instr_len_buf.copy_from_slice(&(instruction.len() as u16).to_be_bytes());

    let encrypted_length = aead_seal(
        AeadAlgorithm::Aes128Gcm,
        &header_length_key[..16],
        &header_length_iv[..12],
        &instr_len_buf,
        Some(&auth_id),
    );
    let encrypted_payload = aead_seal(
        AeadAlgorithm::Aes128Gcm,
        &header_payload_key[..16],
        &header_payload_iv[..12],
        &instruction,
        Some(&auth_id),
    );

    // Assemble: AuthID(16) + encryptedLength(18) + connectionNonce(8) + encryptedPayload(var)
    let mut header_buf = Vec::new();
    header_buf.extend_from_slice(&auth_id);
    header_buf.extend_from_slice(&encrypted_length);
    header_buf.extend_from_slice(&connection_nonce);
    header_buf.extend_from_slice(&encrypted_payload);

    // Body keys
    let request_body_key = data_key;
    let request_body_iv = data_iv;
    let (response_body_key, response_body_iv) =
        derive_response_body_key_iv(&request_body_key, &request_body_iv, algo);

    RequestResult {
        header_buf,
        request_body_key,
        request_body_iv,
        response_body_key,
        response_body_iv,
        response_auth_v,
    }
}

fn encode_address(host: &str) -> (u8, Vec<u8>) {
    // Check IPv4
    if let Ok(addr) = host.parse::<std::net::Ipv4Addr>() {
        return (0x01, addr.octets().to_vec());
    }
    // Check IPv6
    if host.contains(':') {
        if let Ok(addr) = host.parse::<std::net::Ipv6Addr>() {
            return (0x03, addr.octets().to_vec());
        }
        // Try parsing as colon-separated hex (like the TS version)
        let parts: Vec<&str> = host.split(':').collect();
        let mut buf = vec![0u8; 16];
        for (i, part) in parts.iter().enumerate().take(8) {
            let val = u16::from_str_radix(part, 16).unwrap_or(0);
            buf[i * 2] = (val >> 8) as u8;
            buf[i * 2 + 1] = val as u8;
        }
        return (0x03, buf);
    }
    // Domain
    let domain_bytes = host.as_bytes();
    let mut buf = vec![0u8; 1 + domain_bytes.len()];
    buf[0] = domain_bytes.len() as u8;
    buf[1..].copy_from_slice(domain_bytes);
    (0x02, buf)
}

// --- Response handler ---

pub struct ResponseHandler {
    resp_len_key: Vec<u8>,
    resp_len_iv: Vec<u8>,
    resp_hdr_key: Vec<u8>,
    resp_hdr_iv: Vec<u8>,
    response_auth_v: u8,
    response_body_key: Vec<u8>,
    response_body_iv: Vec<u8>,
    algorithm: AeadAlgorithm,
    header_parsed: bool,
    header_buf: Vec<u8>,
    decoder: Option<ChunkDecoder>,
}

impl ResponseHandler {
    pub fn new(req: &RequestResult, algo: AeadAlgorithm) -> Self {
        let resp_len_key =
            vmess_kdf(&req.response_body_key, &[b"AEAD Resp Header Len Key"])[..16].to_vec();
        let resp_len_iv =
            vmess_kdf(&req.response_body_iv, &[b"AEAD Resp Header Len IV"])[..12].to_vec();
        let resp_hdr_key =
            vmess_kdf(&req.response_body_key, &[b"AEAD Resp Header Key"])[..16].to_vec();
        let resp_hdr_iv =
            vmess_kdf(&req.response_body_iv, &[b"AEAD Resp Header IV"])[..12].to_vec();

        Self {
            resp_len_key,
            resp_len_iv,
            resp_hdr_key,
            resp_hdr_iv,
            response_auth_v: req.response_auth_v,
            response_body_key: req.response_body_key.clone(),
            response_body_iv: req.response_body_iv.clone(),
            algorithm: algo,
            header_parsed: false,
            header_buf: Vec::new(),
            decoder: None,
        }
    }

    /// Process incoming data. Returns decoded plaintext chunks.
    /// Returns Err if authentication/decryption fails.
    pub fn handle_data(&mut self, data: &[u8]) -> Result<Vec<Vec<u8>>, ()> {
        const RESP_HDR_LEN_SIZE: usize = 18;

        if !self.header_parsed {
            self.header_buf.extend_from_slice(data);

            if self.header_buf.len() < RESP_HDR_LEN_SIZE {
                return Ok(vec![]);
            }

            let len_plain = aead_open(
                AeadAlgorithm::Aes128Gcm,
                &self.resp_len_key,
                &self.resp_len_iv,
                &self.header_buf[..RESP_HDR_LEN_SIZE],
                None,
            )?;
            let hdr_payload_len =
                u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
            let total_hdr_size = RESP_HDR_LEN_SIZE + hdr_payload_len + 16;

            if self.header_buf.len() < total_hdr_size {
                return Ok(vec![]);
            }

            let hdr_plain = aead_open(
                AeadAlgorithm::Aes128Gcm,
                &self.resp_hdr_key,
                &self.resp_hdr_iv,
                &self.header_buf[RESP_HDR_LEN_SIZE..total_hdr_size],
                None,
            )?;

            if hdr_plain[0] != self.response_auth_v {
                return Err(());
            }

            self.header_parsed = true;
            self.decoder = Some(ChunkDecoder::new(
                &self.response_body_key,
                &self.response_body_iv,
                self.algorithm,
            ));

            let remaining = self.header_buf[total_hdr_size..].to_vec();
            self.header_buf.clear();

            if !remaining.is_empty() {
                return self.decoder.as_mut().unwrap().decode(&remaining);
            }
            return Ok(vec![]);
        }

        self.decoder.as_mut().unwrap().decode(data)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_request_valid() {
        let session = VMessSession::new(VMessUpstream {
            address: "test.example.com".to_string(),
            port: 443,
            uuid: "c831391d-9878-b879-1234-acda48b30811".to_string(),
            security: Security::Aes128Gcm,
            network: Network::Tcp,
            tls: false,
            ws_path: None,
            ws_host: None,
        });

        let req = build_request(&session, "httpbin.org", 80);

        assert!(req.header_buf.len() > 42);
        assert_eq!(req.request_body_key.len(), 16);
        assert_eq!(req.request_body_iv.len(), 16);
        assert_eq!(req.response_body_key.len(), 16);
        assert_eq!(req.response_body_iv.len(), 16);
    }

    #[test]
    fn test_header_can_be_decrypted() {
        let session = VMessSession::new(VMessUpstream {
            address: "test.example.com".to_string(),
            port: 443,
            uuid: "c831391d-9878-b879-1234-acda48b30811".to_string(),
            security: Security::Aes128Gcm,
            network: Network::Tcp,
            tls: false,
            ws_path: None,
            ws_host: None,
        });

        let req = build_request(&session, "httpbin.org", 80);
        let hdr = &req.header_buf;

        let auth_id = &hdr[0..16];
        let enc_len = &hdr[16..34];
        let conn_nonce = &hdr[34..42];
        let enc_payload = &hdr[42..];

        // Decrypt length
        let len_key = vmess_kdf(
            &session.cmd_key,
            &[b"VMess Header AEAD Key_Length", auth_id, conn_nonce],
        );
        let len_iv = vmess_kdf(
            &session.cmd_key,
            &[b"VMess Header AEAD Nonce_Length", auth_id, conn_nonce],
        );
        let len_plain = aead_open(
            AeadAlgorithm::Aes128Gcm,
            &len_key[..16],
            &len_iv[..12],
            enc_len,
            Some(auth_id),
        )
        .unwrap();
        let instr_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
        assert!(instr_len > 40);

        // Decrypt payload
        let pay_key = vmess_kdf(
            &session.cmd_key,
            &[b"VMess Header AEAD Key", auth_id, conn_nonce],
        );
        let pay_iv = vmess_kdf(
            &session.cmd_key,
            &[b"VMess Header AEAD Nonce", auth_id, conn_nonce],
        );
        let instr_plain = aead_open(
            AeadAlgorithm::Aes128Gcm,
            &pay_key[..16],
            &pay_iv[..12],
            enc_payload,
            Some(auth_id),
        )
        .unwrap();
        assert_eq!(instr_plain.len(), instr_len);

        // Parse instruction
        assert_eq!(instr_plain[0], 0x01); // version
        assert_eq!(instr_plain[34], 0x01); // option: chunk stream
        assert_eq!(instr_plain[37], 0x01); // CMD: TCP

        let port = u16::from_be_bytes([instr_plain[38], instr_plain[39]]);
        assert_eq!(port, 80);

        assert_eq!(instr_plain[40], 0x02); // addr type: domain
        let domain_len = instr_plain[41] as usize;
        let domain = std::str::from_utf8(&instr_plain[42..42 + domain_len]).unwrap();
        assert_eq!(domain, "httpbin.org");
    }

    #[test]
    fn test_different_targets_different_headers() {
        let session = VMessSession::new(VMessUpstream {
            address: "test.example.com".to_string(),
            port: 443,
            uuid: "c831391d-9878-b879-1234-acda48b30811".to_string(),
            security: Security::Aes128Gcm,
            network: Network::Tcp,
            tls: false,
            ws_path: None,
            ws_host: None,
        });

        let a = build_request(&session, "a.com", 80);
        let b = build_request(&session, "b.com", 443);
        assert_ne!(a.header_buf, b.header_buf);
    }

    #[test]
    fn test_ipv4_target() {
        let session = VMessSession::new(VMessUpstream {
            address: "test.example.com".to_string(),
            port: 443,
            uuid: "c831391d-9878-b879-1234-acda48b30811".to_string(),
            security: Security::Aes128Gcm,
            network: Network::Tcp,
            tls: false,
            ws_path: None,
            ws_host: None,
        });

        let req = build_request(&session, "1.2.3.4", 8080);
        assert!(req.header_buf.len() > 42);
    }

    #[test]
    fn test_server_can_decrypt_data_chunks() {
        let session = VMessSession::new(VMessUpstream {
            address: "test.example.com".to_string(),
            port: 443,
            uuid: "c831391d-9878-b879-1234-acda48b30811".to_string(),
            security: Security::Aes128Gcm,
            network: Network::Tcp,
            tls: false,
            ws_path: None,
            ws_host: None,
        });

        let req = build_request(&session, "httpbin.org", 80);
        let mut encoder =
            ChunkEncoder::new(&req.request_body_key, &req.request_body_iv, AeadAlgorithm::Aes128Gcm);

        let http_request = b"GET /get HTTP/1.1\r\nHost: httpbin.org\r\n\r\n";
        let encrypted = encoder.encode(http_request);

        let mut decoder =
            ChunkDecoder::new(&req.request_body_key, &req.request_body_iv, AeadAlgorithm::Aes128Gcm);
        let decrypted = decoder.decode(&encrypted).unwrap();

        assert_eq!(decrypted.len(), 1);
        assert_eq!(decrypted[0], http_request);
    }

    #[test]
    fn test_simulated_response_decode() {
        let session = VMessSession::new(VMessUpstream {
            address: "test.example.com".to_string(),
            port: 443,
            uuid: "c831391d-9878-b879-1234-acda48b30811".to_string(),
            security: Security::Aes128Gcm,
            network: Network::Tcp,
            tls: false,
            ws_path: None,
            ws_host: None,
        });

        let req = build_request(&session, "httpbin.org", 80);

        // Simulate server building response header
        let resp_len_key =
            vmess_kdf(&req.response_body_key, &[b"AEAD Resp Header Len Key"])[..16].to_vec();
        let resp_len_iv =
            vmess_kdf(&req.response_body_iv, &[b"AEAD Resp Header Len IV"])[..12].to_vec();
        let resp_hdr_key =
            vmess_kdf(&req.response_body_key, &[b"AEAD Resp Header Key"])[..16].to_vec();
        let resp_hdr_iv =
            vmess_kdf(&req.response_body_iv, &[b"AEAD Resp Header IV"])[..12].to_vec();

        let resp_hdr_plain = [req.response_auth_v, 0x00, 0x00, 0x00];
        let len_buf = 4u16.to_be_bytes();

        let enc_len = aead_seal(
            AeadAlgorithm::Aes128Gcm,
            &resp_len_key,
            &resp_len_iv,
            &len_buf,
            None,
        );
        let enc_hdr = aead_seal(
            AeadAlgorithm::Aes128Gcm,
            &resp_hdr_key,
            &resp_hdr_iv,
            &resp_hdr_plain,
            None,
        );

        // Simulate response data
        let mut response_encoder = ChunkEncoder::new(
            &req.response_body_key,
            &req.response_body_iv,
            AeadAlgorithm::Aes128Gcm,
        );
        let response_body = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
        let enc_body = response_encoder.encode(response_body);

        // Full response
        let mut full_response = Vec::new();
        full_response.extend_from_slice(&enc_len);
        full_response.extend_from_slice(&enc_hdr);
        full_response.extend_from_slice(&enc_body);

        // Client decodes
        let dec_len = aead_open(
            AeadAlgorithm::Aes128Gcm,
            &resp_len_key,
            &resp_len_iv,
            &full_response[..18],
            None,
        )
        .unwrap();
        let hdr_len = u16::from_be_bytes([dec_len[0], dec_len[1]]) as usize;
        assert_eq!(hdr_len, 4);

        let dec_hdr = aead_open(
            AeadAlgorithm::Aes128Gcm,
            &resp_hdr_key,
            &resp_hdr_iv,
            &full_response[18..38],
            None,
        )
        .unwrap();
        assert_eq!(dec_hdr[0], req.response_auth_v);

        let mut response_decoder = ChunkDecoder::new(
            &req.response_body_key,
            &req.response_body_iv,
            AeadAlgorithm::Aes128Gcm,
        );
        let body_chunks = response_decoder.decode(&full_response[38..]).unwrap();
        assert_eq!(body_chunks.len(), 1);
        assert_eq!(body_chunks[0], response_body);
    }
}
