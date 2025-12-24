# Security

## Encryption

**Vault data:** AES-256-GCM with random 12-byte nonce per encryption.

**Key derivation:** Argon2id (5 iterations, 256MB, 4 threads) → 32-byte key. Salt is 32 random bytes per vault.

## Keyring Protection

Your password alone doesn't unlock the vault. We combine it with a 32-byte random secret stored in the OS keyring (macOS Keychain / Linux Secret Service).

```
combined = password || keyringSecret
key = Argon2id(combined, salt)
```

If someone steals your vault file, they can't brute-force it—the keyring secret isn't in the file.

## MEK Pattern

A random Master Encryption Key (MEK) encrypts your data. The MEK itself is encrypted twice:
- Once with password+keyring (for normal unlock)
- Once with recovery phrase (for emergency access)

This lets you unlock with either method.

## Recovery Phrase

12-word BIP39 mnemonic (128 bits entropy). Never stored in the vault. Used for recovery or migrating to a new device.

## Backups

Backup files have password fields cleared—they only work with the recovery phrase. This prevents "steal backup + reuse password" attacks.

## Vault Format (v1.1)

```json
{
  "version": "1.1",
  "security_mode": "password_keyring",
  "kdf": {
    "algorithm": "argon2id",
    "params": {
      "memory": 262144,
      "iterations": 5,
      "parallelism": 4
    }
  },
  "keyring_fingerprint": "sha256...",
  "salt_password": "hex",
  "salt_phrase": "hex",
  "encrypted_mek_password": "hex",
  "encrypted_mek_phrase": "hex",
  "encrypted_data": "hex"
}
```

## Memory

- Sensitive data zeroed via `ZeroMemory()` after use
- MEK cleared on vault lock
- Signal handlers clean up on SIGINT/SIGTERM/SIGHUP
- Clipboard cleared after timeout

## Files

- Vault: 0600 (owner read/write only)
- Config: 0644
