# Crypto Accounts

## 프로젝트 목표

블록체인 계정 생성 과정을 직접 구현하며 암호학 기초를 학습한다.
[Ian Coleman BIP39](https://iancoleman.io/bip39/)처럼 동작하는 도구를 만든다.

### 학습 로드맵

1. **Account** - 니모닉 → 키 도출 → 주소 생성 (현재)
2. **Transaction** - 가스, 서명
3. **추후 확장** - ZK, 기타 암호학 응용

---

## 구현 진행 상황

| 항목 | 상태 | 파일 |
|------|------|------|
| BIP-39 니모닉 | ✅ 완료 | `crypto-lib/src/bip39.rs` |
| BIP-32 HD 키 도출 | ✅ 완료 | `crypto-lib/src/bip32.rs` |
| EVM 계정 (Ethereum 등) | ✅ 완료 | `crypto-lib/src/evm/mod.rs` |
| Bitcoin 계정 | ⏳ 예정 | `crypto-lib/src/bitcoin/` |
| Solana 계정 | ⏳ 예정 | `crypto-lib/src/solana/` |
| Sui 계정 | ⏳ 예정 | `crypto-lib/src/sui/` |
| Cosmos 계정 | ⏳ 예정 | `crypto-lib/src/cosmos/` |
| JavaScript 웹 UI | ⏳ 예정 | `web/` |

---

## 지원 체인

| 체인 | 타원곡선 | 해시 | 주소 형식 | BIP-44 경로 |
|------|---------|------|----------|-------------|
| **Bitcoin** | secp256k1 | SHA-256 + RIPEMD-160 | Base58/Bech32 | m/84'/0'/0' (SegWit) |
| **EVM** | secp256k1 | Keccak-256 | 20바이트 (0x...) | m/44'/60'/0' |
| **Solana** | Ed25519 | SHA-256 | Base58 | m/44'/501'/0' |
| **Sui** | Ed25519 | Blake2b | 32바이트 (0x...) | m/44'/784'/0' |
| **Cosmos** | secp256k1 | SHA-256 + RIPEMD-160 | Bech32 | m/44'/118'/0' |

---

## 핵심 알고리즘 요약

### BIP-39: 니모닉 생성

```
엔트로피(128/256비트) → SHA-256 체크섬 → 11비트씩 분할 → 단어 인덱스 → 니모닉
니모닉 + 패스프레이즈 → PBKDF2-HMAC-SHA512 (2048회) → 512비트 시드
```

**핵심 함수:** `entropy_to_indices()` - 엔트로피+체크섬을 11비트씩 잘라 2048개 단어 중 선택

### BIP-32: HD 키 도출

```
시드 → HMAC-SHA512("Bitcoin seed") → 마스터 개인키 + 체인코드
마스터 키 + 경로(m/44'/60'/0'/0/0) → 자식 키 도출
```

**강화 도출 vs 일반 도출:**
- 강화(Hardened, '): `HMAC(체인코드, 0x00 || 개인키 || 인덱스)` - 개인키 필요
- 일반(Normal): `HMAC(체인코드, 공개키 || 인덱스)` - 공개키만으로 가능

### EVM 주소 생성

```
개인키 → secp256k1 공개키(65바이트) → prefix 제거(64바이트)
→ Keccak-256 해시(32바이트) → 마지막 20바이트 = 주소
→ EIP-55 체크섬 적용 (대소문자로 체크섬 표현)
```

---

## 프로젝트 구조

```text
crypto-accounts/
├── CLAUDE.md                    # 이 파일 (프로젝트 컨텍스트)
├── LICENSE
├── crypto-lib/                  # Rust 라이브러리 (암호학 학습용)
│   ├── src/
│   │   ├── lib.rs              # 모듈 선언
│   │   ├── bip39.rs            # 니모닉 생성 (완료)
│   │   ├── bip32.rs            # HD 키 도출 (완료)
│   │   ├── wordlist/
│   │   │   └── english.txt     # BIP-39 영어 단어 2048개
│   │   ├── bitcoin/            # Bitcoin 주소 (예정)
│   │   ├── evm/
│   │   │   └── mod.rs          # EVM 주소 (완료)
│   │   ├── solana/             # Solana 주소 (예정)
│   │   ├── sui/                # Sui 주소 (예정)
│   │   └── cosmos/             # Cosmos 주소 (예정)
│   └── Cargo.toml
│
├── web/                         # JavaScript 웹 UI (예정)
├── docs/                        # BIP 문서
└── notes/                       # 학습 노트
```

---

## 기술 스택 및 의존성

### Rust 크레이트 (Cargo.toml)

| 크레이트 | 용도 |
|---------|------|
| `sha2` | SHA-256, SHA-512 해시 |
| `ripemd` | RIPEMD-160 해시 (Bitcoin) |
| `tiny-keccak` | Keccak-256 해시 (EVM) |
| `hmac` | HMAC 인증 코드 |
| `pbkdf2` | 키 유도 함수 (BIP-39 시드) |
| `secp256k1` | 타원곡선 암호 (Bitcoin, EVM) |
| `ed25519-dalek` | Ed25519 서명 (Solana, Sui) |
| `blake2` | Blake2 해시 (Sui) |
| `hex` | 16진수 인코딩 |
| `bs58` | Base58 인코딩 (Bitcoin, Solana) |
| `bech32` | Bech32 인코딩 (Bitcoin SegWit, Cosmos) |
| `rand` | 난수 생성 |

---

## 개발 명령어

```bash
# 프로젝트 디렉토리
cd /Users/parkgeonwoo/crypto-accounts/crypto-lib

# 빌드
cargo build

# 테스트 실행
cargo test

# 코드 검사 (린트)
cargo clippy

# 특정 테스트만 실행
cargo test test_evm_from_mnemonic
```

---

## 테스트 니모닉 (검증용)

BIP-39 표준 테스트 벡터:
```
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
```

이 니모닉으로 생성한 EVM 주소 (m/44'/60'/0'/0/0):
```
0x9858EfFD232B4033E47d90003D41EC34EcaEda94
```

Ian Coleman 사이트에서 동일한 결과 확인 가능.

---




## 참고 자료

- [BIP-32: HD Wallets](./docs/bip-0032.md)
- [BIP-39: Mnemonic](./docs/bip-0039.md)
- [BIP-43: Purpose Field](./docs/bip-0043.md)
- [BIP-44: Multi-Account](./docs/bip-0044.md)
- [Ian Coleman BIP39 Tool](https://iancoleman.io/bip39/)
- [EIP-55: Mixed-case checksum address encoding](https://eips.ethereum.org/EIPS/eip-55)

---

## GitHub

- 저장소: https://github.com/97woo/crypto-accounts
