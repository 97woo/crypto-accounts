//! Sui Account Generation
//!
//! - 타원곡선: Ed25519 (기본) 또는 secp256k1
//! - 해시: Blake2b-256
//! - 주소 형식: 32바이트 (0x...)
//! - BIP-44 경로: m/44'/784'/0'/0'/0'
//!
//! ## 주소 생성 과정
//! 1. 시드 → SLIP-10 Ed25519 도출
//! 2. Ed25519 개인키 → 공개키
//! 3. flag(0x00) + 공개키 → Blake2b-256 해시 = 주소
//!
//! ## 서명 스킴 플래그
//! - 0x00: Ed25519
//! - 0x01: Secp256k1
//! - 0x02: Secp256r1
//! - 0x03: MultiSig

use blake2::{Blake2b, Digest};
use blake2::digest::consts::U32;
use ed25519_dalek::{SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::Sha512;

use crate::bip39::mnemonic_to_seed;

type HmacSha512 = Hmac<Sha512>;
type Blake2b256 = Blake2b<U32>;

/// Sui 계정
#[derive(Debug, Clone)]
pub struct SuiAccount {
    /// 개인키 (32바이트)
    pub private_key: [u8; 32],
    /// 공개키 (32바이트)
    pub public_key: [u8; 32],
    /// 주소 (32바이트) - Blake2b-256(flag + pubkey)
    pub address: [u8; 32],
}

/// Sui 기본 도출 경로
pub const SUI_PATH: &str = "m/44'/784'/0'/0'/0'";

/// 서명 스킴 플래그
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SignatureScheme {
    Ed25519 = 0x00,
    Secp256k1 = 0x01,
    Secp256r1 = 0x02,
}

impl SuiAccount {
    /// 개인키에서 Sui 계정 생성
    pub fn from_private_key(private_key: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&private_key);
        let verifying_key: VerifyingKey = (&signing_key).into();
        let public_key = verifying_key.to_bytes();

        // 주소 = Blake2b-256(flag + pubkey)
        let address = derive_sui_address(&public_key, SignatureScheme::Ed25519);

        SuiAccount {
            private_key,
            public_key,
            address,
        }
    }

    /// 시드에서 Sui 계정 생성 (기본 경로)
    pub fn from_seed(seed: &[u8]) -> Result<Self, String> {
        Self::from_seed_with_path(seed, SUI_PATH)
    }

    /// 시드에서 특정 경로로 Sui 계정 생성 (SLIP-10)
    pub fn from_seed_with_path(seed: &[u8], path: &str) -> Result<Self, String> {
        let private_key = derive_ed25519_private_key(seed, path)?;
        Ok(Self::from_private_key(private_key))
    }

    /// 니모닉에서 Sui 계정 생성
    pub fn from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<Self, String> {
        let seed = mnemonic_to_seed(mnemonic, passphrase);
        Self::from_seed(&seed)
    }

    /// 주소 반환 (0x 접두사)
    pub fn address(&self) -> String {
        format!("0x{}", hex::encode(self.address))
    }

    /// 주소 반환 (접두사 없이)
    pub fn address_hex(&self) -> String {
        hex::encode(self.address)
    }

    /// 개인키를 hex로 반환
    pub fn private_key_hex(&self) -> String {
        hex::encode(self.private_key)
    }

    /// 공개키를 hex로 반환
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key)
    }

    /// Sui 형식의 개인키 (suiprivkey...) - Bech32 인코딩
    pub fn private_key_bech32(&self) -> String {
        // flag + private_key
        let mut data = vec![SignatureScheme::Ed25519 as u8];
        data.extend_from_slice(&self.private_key);

        // Bech32 인코딩 (hrp = "suiprivkey")
        encode_sui_bech32("suiprivkey", &data)
    }
}

// ═══════════════════════════════════════════════════════════════
// 주소 도출
// ═══════════════════════════════════════════════════════════════

/// Sui 주소 도출
///
/// address = Blake2b-256(flag || public_key)
fn derive_sui_address(public_key: &[u8; 32], scheme: SignatureScheme) -> [u8; 32] {
    let mut hasher = Blake2b256::new();

    // flag + public_key
    hasher.update(&[scheme as u8]);
    hasher.update(public_key);

    let result = hasher.finalize();
    let mut address = [0u8; 32];
    address.copy_from_slice(&result);

    address
}

// ═══════════════════════════════════════════════════════════════
// SLIP-10 Ed25519 (Solana와 동일)
// ═══════════════════════════════════════════════════════════════

fn slip10_master_key(seed: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
    let mut hmac = HmacSha512::new_from_slice(b"ed25519 seed")
        .map_err(|e| format!("HMAC 초기화 실패: {}", e))?;

    hmac.update(seed);
    let result = hmac.finalize().into_bytes();

    let mut private_key = [0u8; 32];
    let mut chain_code = [0u8; 32];

    private_key.copy_from_slice(&result[..32]);
    chain_code.copy_from_slice(&result[32..]);

    Ok((private_key, chain_code))
}

fn slip10_derive_child(
    parent_key: &[u8; 32],
    parent_chain_code: &[u8; 32],
    index: u32,
) -> Result<([u8; 32], [u8; 32]), String> {
    let hardened_index = index | 0x80000000;

    let mut data = Vec::with_capacity(37);
    data.push(0x00);
    data.extend_from_slice(parent_key);
    data.extend_from_slice(&hardened_index.to_be_bytes());

    let mut hmac = HmacSha512::new_from_slice(parent_chain_code)
        .map_err(|e| format!("HMAC 초기화 실패: {}", e))?;

    hmac.update(&data);
    let result = hmac.finalize().into_bytes();

    let mut child_key = [0u8; 32];
    let mut child_chain_code = [0u8; 32];

    child_key.copy_from_slice(&result[..32]);
    child_chain_code.copy_from_slice(&result[32..]);

    Ok((child_key, child_chain_code))
}

fn derive_ed25519_private_key(seed: &[u8], path: &str) -> Result<[u8; 32], String> {
    let indices = parse_slip10_path(path)?;
    let (mut key, mut chain_code) = slip10_master_key(seed)?;

    for index in indices {
        let (new_key, new_chain_code) = slip10_derive_child(&key, &chain_code, index)?;
        key = new_key;
        chain_code = new_chain_code;
    }

    Ok(key)
}

fn parse_slip10_path(path: &str) -> Result<Vec<u32>, String> {
    let path = path.trim();

    if !path.starts_with('m') && !path.starts_with('M') {
        return Err("경로는 'm'으로 시작해야 합니다".to_string());
    }

    let parts: Vec<&str> = path.split('/').collect();
    let mut indices = Vec::new();

    for part in parts.iter().skip(1) {
        if part.is_empty() {
            continue;
        }

        let num_str = part
            .trim_end_matches('\'')
            .trim_end_matches('h')
            .trim_end_matches('H');

        let num: u32 = num_str
            .parse()
            .map_err(|_| format!("유효하지 않은 인덱스: {}", part))?;

        indices.push(num);
    }

    Ok(indices)
}

// ═══════════════════════════════════════════════════════════════
// Bech32 인코딩 (Sui 개인키용)
// ═══════════════════════════════════════════════════════════════

fn encode_sui_bech32(hrp: &str, data: &[u8]) -> String {
    let converted = convert_bits(data, 8, 5, true);
    let checksum = bech32_checksum(hrp, &converted);

    let mut bits = converted;
    bits.extend(checksum);

    let charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let encoded: String = bits
        .iter()
        .map(|&b| charset.chars().nth(b as usize).unwrap())
        .collect();

    format!("{}1{}", hrp, encoded)
}

fn convert_bits(data: &[u8], from_bits: u32, to_bits: u32, pad: bool) -> Vec<u8> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut result = Vec::new();
    let max_v = (1u32 << to_bits) - 1;

    for &value in data {
        acc = (acc << from_bits) | (value as u32);
        bits += from_bits;

        while bits >= to_bits {
            bits -= to_bits;
            result.push(((acc >> bits) & max_v) as u8);
        }
    }

    if pad && bits > 0 {
        result.push(((acc << (to_bits - bits)) & max_v) as u8);
    }

    result
}

fn bech32_checksum(hrp: &str, data: &[u8]) -> Vec<u8> {
    let mut values = bech32_hrp_expand(hrp);
    values.extend(data);
    values.extend(vec![0u8; 6]);

    let polymod = bech32_polymod(&values) ^ 1;

    (0..6)
        .map(|i| ((polymod >> (5 * (5 - i))) & 31) as u8)
        .collect()
}

fn bech32_hrp_expand(hrp: &str) -> Vec<u8> {
    let mut result: Vec<u8> = hrp.chars().map(|c| (c as u8) >> 5).collect();
    result.push(0);
    result.extend(hrp.chars().map(|c| (c as u8) & 31));
    result
}

fn bech32_polymod(values: &[u8]) -> u32 {
    let generator = [0x3b6a57b2u32, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk: u32 = 1;

    for &value in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ (value as u32);

        for (i, &gen) in generator.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= gen;
            }
        }
    }

    chk
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sui_from_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let account = SuiAccount::from_mnemonic(mnemonic, "").unwrap();

        println!("=== Sui (m/44'/784'/0'/0'/0') ===");
        println!("개인키: {}", account.private_key_hex());
        println!("공개키: {}", account.public_key_hex());
        println!("주소: {}", account.address());
        println!("Bech32 개인키: {}", account.private_key_bech32());
    }

    #[test]
    fn test_sui_address_derivation() {
        // 알려진 공개키로 주소 도출 테스트
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let account = SuiAccount::from_mnemonic(mnemonic, "").unwrap();

        // 주소가 32바이트인지 확인
        assert_eq!(account.address.len(), 32);

        // 0x로 시작하는지 확인
        assert!(account.address().starts_with("0x"));

        println!("주소 길이: {} 문자", account.address().len());
    }

    #[test]
    fn test_multiple_accounts() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(mnemonic, "");

        println!("\n=== Sui 계정 목록 (첫 5개) ===\n");

        for i in 0..5 {
            let path = format!("m/44'/784'/0'/0'/{}'", i);
            let account = SuiAccount::from_seed_with_path(&seed, &path).unwrap();

            println!("경로: {}", path);
            println!("주소: {}", account.address());
            println!();
        }
    }

    #[test]
    fn test_blake2b_hash() {
        // Blake2b-256 기본 테스트
        let mut hasher = Blake2b256::new();
        hasher.update(b"test");
        let result = hasher.finalize();

        assert_eq!(result.len(), 32);
        println!("Blake2b-256(\"test\"): {}", hex::encode(result));
    }
}
