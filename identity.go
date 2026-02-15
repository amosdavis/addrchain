package addrchain

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Identity holds the node's Ed25519 keypair.
type Identity struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// NodeID returns the hex-encoded public key used as the node identifier.
func (id *Identity) NodeID() string {
	return hex.EncodeToString(id.PublicKey)
}

// DefaultKeyDir returns the default directory for key storage.
func DefaultKeyDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".addrchain")
}

// LoadOrCreateIdentity loads a keypair from disk, or generates and saves a new one.
func LoadOrCreateIdentity(dir string) (*Identity, error) {
	if dir == "" {
		dir = DefaultKeyDir()
	}

	keyPath := filepath.Join(dir, "key")

	data, err := os.ReadFile(keyPath)
	if err == nil {
		return parseKeyFile(data)
	}

	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read key file: %w", err)
	}

	// Generate new keypair.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create key dir: %w", err)
	}

	encoded := hex.EncodeToString(priv.Seed())
	if err := os.WriteFile(keyPath, []byte(encoded), 0600); err != nil {
		return nil, fmt.Errorf("write key file: %w", err)
	}

	warnIfPermissionsTooOpen(keyPath)

	return &Identity{PublicKey: pub, PrivateKey: priv}, nil
}

// parseKeyFile reads a hex-encoded Ed25519 seed and derives the keypair.
func parseKeyFile(data []byte) (*Identity, error) {
	seed, err := hex.DecodeString(string(data))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid key file: expected %d-byte hex seed", ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return &Identity{PublicKey: pub, PrivateKey: priv}, nil
}

// warnIfPermissionsTooOpen checks file permissions and warns if too open (Unix only).
func warnIfPermissionsTooOpen(path string) {
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	perm := info.Mode().Perm()
	if perm&0077 != 0 {
		fmt.Fprintf(os.Stderr, "WARNING: key file %s has permissions %o (should be 0600)\n", path, perm)
	}
}

// RotateIdentity generates a new keypair and saves it, returning both old and new identities.
func RotateIdentity(dir string) (oldID *Identity, newID *Identity, err error) {
	if dir == "" {
		dir = DefaultKeyDir()
	}

	oldID, err = LoadOrCreateIdentity(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("load old identity: %w", err)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("generate new key: %w", err)
	}

	keyPath := filepath.Join(dir, "key")
	encoded := hex.EncodeToString(priv.Seed())
	if err := os.WriteFile(keyPath, []byte(encoded), 0600); err != nil {
		return nil, nil, fmt.Errorf("write new key: %w", err)
	}

	newID = &Identity{PublicKey: pub, PrivateKey: priv}
	return oldID, newID, nil
}
