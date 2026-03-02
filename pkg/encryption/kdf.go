package encryption

import (
	"golang.org/x/crypto/argon2"
)

const (
	argon2Time    = 3
	argon2Memory  = 64 * 1024 // 64 MB
	argon2Threads = 4
	argon2KeyLen  = 32
)

// DeriveKeyArgon2id derives a 32-byte AES-256 key from a password and salt using Argon2id.
// The result is deterministic: same password + salt always produces the same key.
func DeriveKeyArgon2id(password []byte, salt []byte) []byte {
	return argon2.IDKey(password, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
}
