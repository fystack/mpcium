package encryption

import (
	"bytes"
	"testing"
)

func TestDeriveKeyArgon2id_KeyLength(t *testing.T) {
	password := []byte("test-password")
	salt := []byte("0123456789abcdef0123456789abcdef")

	key := DeriveKeyArgon2id(password, salt)
	if len(key) != 32 {
		t.Fatalf("expected key length 32, got %d", len(key))
	}
}

func TestDeriveKeyArgon2id_Deterministic(t *testing.T) {
	password := []byte("my-secret-password")
	salt := []byte("fixed-salt-value-here-32-bytes!!")

	key1 := DeriveKeyArgon2id(password, salt)
	key2 := DeriveKeyArgon2id(password, salt)

	if !bytes.Equal(key1, key2) {
		t.Fatal("same password and salt should produce identical keys")
	}
}

func TestDeriveKeyArgon2id_DifferentSalts(t *testing.T) {
	password := []byte("same-password")
	salt1 := []byte("salt-one-padded-to-be-long-enough")
	salt2 := []byte("salt-two-padded-to-be-long-enough")

	key1 := DeriveKeyArgon2id(password, salt1)
	key2 := DeriveKeyArgon2id(password, salt2)

	if bytes.Equal(key1, key2) {
		t.Fatal("different salts should produce different keys")
	}
}

func TestDeriveKeyArgon2id_DifferentPasswords(t *testing.T) {
	salt := []byte("same-salt-value-padded-enough!!")
	key1 := DeriveKeyArgon2id([]byte("password-one"), salt)
	key2 := DeriveKeyArgon2id([]byte("password-two"), salt)

	if bytes.Equal(key1, key2) {
		t.Fatal("different passwords should produce different keys")
	}
}

func TestDeriveKeyArgon2id_LongPassword(t *testing.T) {
	// Simulates a password from `openssl rand -hex 32` (64 chars)
	password := []byte("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
	salt := []byte("0123456789abcdef0123456789abcdef")

	key := DeriveKeyArgon2id(password, salt)
	if len(key) != 32 {
		t.Fatalf("expected key length 32, got %d", len(key))
	}
}
