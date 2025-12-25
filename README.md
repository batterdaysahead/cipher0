# cipher0

Offline-first TUI password manager with TOTP support. Built with Go.

https://github.com/user-attachments/assets/a0f3b2b8-fbe8-421f-b72b-7c7b93ba103f

## Features

- AES-256-GCM encryption
- Argon2id key derivation (5 iterations, 256MB, 4 threads)
- OS keyring integration (macOS Keychain / Linux Secret Service)
- 12-word BIP39 recovery phrase
- TOTP with QR code export
- Auto-clearing clipboard
- Encrypted backups

## Install

```bash
git clone https://github.com/batterdaysahead/cipher0.git
cd cipher0
make build
```

## Usage

```bash
cipher0                              # run TUI
cipher0 --vault /path/to/vault.c0    # session-only vault

cipher0 backup /path/to/backup.c0    # create backup
cipher0 restore /path/to/backup.c0   # restore (needs phrase)
cipher0 verify /path/to/backup.c0    # verify backup

cipher0 config set vault /path       # save vault path
cipher0 config get vault             # show vault path
```

## Keys

**Login:** `Enter` unlock, `Tab` recovery phrase, `Esc` quit

**Dashboard:**
- `j/k` navigate, `n` new, `e` edit, `d` delete
- `r` reveal password, `p` copy password, `u` copy username
- `t` copy TOTP, `o` show QR
- `/` search, `Esc` clear filter
- `s` settings, `b` backup, `l` lock, `q` quit

**Entry form:** `Tab` next, `Ctrl+S` save, `Ctrl+G` generate, `Esc` cancel

## Security

See [SECURITY.md](SECURITY.md) for details.

- Vault encrypted with AES-256-GCM using random MEK
- Password + keyring secret derives the key (stolen files can't be brute-forced)
- Argon2id limits attempts to ~340k/day (~250ms each)
- Backups require recovery phrase, not password
- Sensitive data zeroed from memory
- Files created with 0600 permissions

## Config

- macOS/Linux: `~/.config/cipher0/config.json`

## Dev

```bash
make run         # run
make test        # test
make test-cover  # coverage
make build       # build
make fmt         # format
make lint        # lint
make clean       # clean
```
