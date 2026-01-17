---
description: "기능별로 커밋 분리하고 Co-Author 없이 푸시"
---

# /commit-clean Command

변경된 파일들을 기능별로 분류해서 각각 커밋하고, Claude Co-Author 없이 푸시합니다.

## Arguments

- `(none)`: 기능별 커밋 + 푸시 (기본)
- `--no-push`: 커밋만 하고 푸시 안 함
- `--dry-run`: 실제 커밋 없이 계획만 보여줌

## Instructions

### Step 1: 변경 파일 분석

```bash
git status --porcelain
git diff --name-only
git diff --cached --name-only
```

변경된 파일이 없으면 "커밋할 변경사항이 없습니다" 출력 후 종료.

### Step 2: 파일 분류

파일 경로와 확장자를 기반으로 그룹 분류:

| 패턴 | 그룹 | 커밋 prefix |
|------|------|-------------|
| `src/**/mod.rs`, `src/**/*.rs` (새 기능) | feature | `feat` |
| `src/**/*.rs` (버그 수정, 작은 변경) | fix | `fix` |
| `*.md`, `docs/**` | docs | `docs` |
| `notes/**` | docs | `docs` |
| `Cargo.toml`, `package.json`, `*.config.*` | config | `chore` |
| `tests/**`, `*_test.*`, `*.test.*` | test | `test` |
| `.github/**`, `.claude/**` | ci/tooling | `chore` |

**분류 기준:**
1. 새 파일(untracked) + 구현 코드 → `feat`
2. 기존 파일 수정 + 작은 변경 → `fix`
3. 린트/포맷 수정 → `fix` or `style`
4. 문서 파일 → `docs`

### Step 3: 커밋 메시지 생성

각 그룹에 대해 커밋 메시지 작성:

```
<prefix>(<scope>): <설명>

- 변경사항 1
- 변경사항 2
```

**규칙:**
- 한국어로 작성
- 첫 줄 50자 이내
- Co-Author 절대 추가하지 않음
- HEREDOC 사용해서 커밋

```bash
git commit -m "$(cat <<'EOF'
feat(evm): EVM 계정 생성 구현

- secp256k1 공개키 생성
- Keccak-256 해시로 주소 도출
EOF
)"
```

### Step 4: 커밋 실행

그룹별로 순서대로:

```bash
# 그룹 1
git add <파일들>
git commit -m "..."

# 그룹 2
git add <파일들>
git commit -m "..."
```

### Step 5: 푸시

`--no-push` 옵션이 없으면:

```bash
git push origin <현재브랜치>
```

### Step 6: 결과 출력

```
✅ 커밋 완료

1. feat(evm): EVM 계정 생성 구현
   - crypto-lib/src/evm/mod.rs

2. fix: clippy 경고 수정
   - crypto-lib/src/bip39.rs
   - crypto-lib/src/bip32.rs

3. docs: 문서 업데이트
   - CLAUDE.md
   - notes/bip-39_learn.md

🚀 origin/main에 푸시 완료
```

## 예시

### 일반 사용
```
/commit-clean
```

### 푸시 없이 커밋만
```
/commit-clean --no-push
```

### 계획만 확인
```
/commit-clean --dry-run
```

## 주의사항

- staged 상태 파일이 있으면 먼저 unstage (`git reset HEAD`)
- 민감한 파일 (.env 등) 커밋 방지 확인
- 충돌 시 사용자에게 알림
