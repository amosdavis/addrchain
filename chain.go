package addrchain

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Transaction types supported by the chain.
const (
	TxClaim   = "CLAIM"
	TxRelease = "RELEASE"
	TxRenew   = "RENEW"
	TxRevoke  = "REVOKE"
)

// Rate-limiting constants: max claims per node per window of blocks.
const (
	RateLimitMaxClaims = 10
	RateLimitWindow    = 50
)

// Transaction represents a single operation on the address ledger.
type Transaction struct {
	Type      string `json:"type"`
	NodeID    string `json:"node_id"`
	Address   string `json:"address"`
	Timestamp int64  `json:"timestamp"`
	Seq       uint64 `json:"seq"`
	// NewNodeID is only used for REVOKE transactions to declare the new identity.
	NewNodeID string `json:"new_node_id,omitempty"`
	Signature string `json:"signature"`
}

// SigningPayload returns the canonical bytes that must be signed.
func (tx *Transaction) SigningPayload() []byte {
	payload := fmt.Sprintf("%s|%s|%s|%d|%d|%s", tx.Type, tx.NodeID, tx.Address, tx.Timestamp, tx.Seq, tx.NewNodeID)
	return []byte(payload)
}

// Sign signs the transaction with the given private key.
func (tx *Transaction) Sign(key ed25519.PrivateKey) {
	sig := ed25519.Sign(key, tx.SigningPayload())
	tx.Signature = hex.EncodeToString(sig)
}

// VerifySignature verifies that the transaction was signed by the node's public key.
// The NodeID is the hex-encoded public key.
func (tx *Transaction) VerifySignature() bool {
	pubBytes, err := hex.DecodeString(tx.NodeID)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return false
	}
	sigBytes, err := hex.DecodeString(tx.Signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pubBytes), tx.SigningPayload(), sigBytes)
}

// Block represents a single block in the chain.
type Block struct {
	Index        uint64        `json:"index"`
	Timestamp    int64         `json:"timestamp"`
	PrevHash     string        `json:"prev_hash"`
	Hash         string        `json:"hash"`
	Transactions []Transaction `json:"transactions"`
}

// ComputeHash calculates the SHA-256 hash of the block's content (excluding the Hash field itself).
func (b *Block) ComputeHash() string {
	data, _ := json.Marshal(struct {
		Index        uint64        `json:"index"`
		Timestamp    int64         `json:"timestamp"`
		PrevHash     string        `json:"prev_hash"`
		Transactions []Transaction `json:"transactions"`
	}{
		Index:        b.Index,
		Timestamp:    b.Timestamp,
		PrevHash:     b.PrevHash,
		Transactions: b.Transactions,
	})
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// GenesisTimestamp is the fixed timestamp for the deterministic genesis block.
const GenesisTimestamp int64 = 0

// NewGenesisBlock creates the deterministic genesis block. All nodes must produce
// the same genesis block to form a compatible chain.
func NewGenesisBlock() Block {
	b := Block{
		Index:        0,
		Timestamp:    GenesisTimestamp,
		PrevHash:     "0000000000000000000000000000000000000000000000000000000000000000",
		Transactions: []Transaction{},
	}
	b.Hash = b.ComputeHash()
	return b
}

// NewBlock creates a new block with the given transactions, linked to the previous block.
func NewBlock(prev Block, txs []Transaction) Block {
	b := Block{
		Index:        prev.Index + 1,
		Timestamp:    time.Now().Unix(),
		PrevHash:     prev.Hash,
		Transactions: txs,
	}
	b.Hash = b.ComputeHash()
	return b
}

// Chain is a thread-safe blockchain.
type Chain struct {
	mu     sync.RWMutex
	Blocks []Block
}

// NewChain creates a new chain initialized with the genesis block.
func NewChain() *Chain {
	return &Chain{
		Blocks: []Block{NewGenesisBlock()},
	}
}

// Len returns the number of blocks in the chain.
func (c *Chain) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.Blocks)
}

// LastBlock returns the most recent block.
func (c *Chain) LastBlock() Block {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Blocks[len(c.Blocks)-1]
}

// GetBlocks returns a copy of all blocks.
func (c *Chain) GetBlocks() []Block {
	c.mu.RLock()
	defer c.mu.RUnlock()
	cp := make([]Block, len(c.Blocks))
	copy(cp, c.Blocks)
	return cp
}

// AddBlock validates and appends a block to the chain. Returns an error if
// the block is invalid.
func (c *Chain) AddBlock(b Block) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	last := c.Blocks[len(c.Blocks)-1]
	if err := validateBlock(b, last, c.Blocks); err != nil {
		return err
	}
	c.Blocks = append(c.Blocks, b)
	return nil
}

// ReplaceChain atomically replaces the entire chain if the candidate is valid
// and longer. Returns true if the chain was replaced.
func (c *Chain) ReplaceChain(candidate []Block) (bool, error) {
	if err := ValidateChain(candidate); err != nil {
		return false, fmt.Errorf("candidate chain invalid: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(candidate) <= len(c.Blocks) {
		if len(candidate) == len(c.Blocks) {
			// Tiebreaker: lowest tip hash wins.
			if candidate[len(candidate)-1].Hash >= c.Blocks[len(c.Blocks)-1].Hash {
				return false, nil
			}
		} else {
			return false, nil
		}
	}

	c.Blocks = make([]Block, len(candidate))
	copy(c.Blocks, candidate)
	return true, nil
}

// validateBlock checks a single block against the previous block and the full chain context.
func validateBlock(b Block, prev Block, chain []Block) error {
	if b.Index != prev.Index+1 {
		return fmt.Errorf("invalid index: expected %d, got %d", prev.Index+1, b.Index)
	}
	if b.PrevHash != prev.Hash {
		return errors.New("previous hash mismatch")
	}
	if b.Hash != b.ComputeHash() {
		return errors.New("block hash mismatch")
	}
	for i := range b.Transactions {
		tx := &b.Transactions[i]
		if !tx.VerifySignature() {
			return fmt.Errorf("invalid signature on transaction %d", i)
		}
		if err := validateTxType(tx); err != nil {
			return fmt.Errorf("transaction %d: %w", i, err)
		}
	}
	if err := enforceRateLimit(b, chain); err != nil {
		return err
	}
	return nil
}

// validateTxType checks that the transaction type is known and fields are valid.
func validateTxType(tx *Transaction) error {
	switch tx.Type {
	case TxClaim, TxRelease, TxRenew:
		if tx.Address == "" {
			return errors.New("address is required")
		}
	case TxRevoke:
		if tx.NewNodeID == "" {
			return errors.New("new_node_id is required for REVOKE")
		}
	default:
		return fmt.Errorf("unknown transaction type: %s", tx.Type)
	}
	return nil
}

// enforceRateLimit ensures no NodeID exceeds RateLimitMaxClaims CLAIM transactions
// within the last RateLimitWindow blocks (including the candidate block).
func enforceRateLimit(candidate Block, chain []Block) error {
	claimCounts := make(map[string]int)

	// Count claims in the candidate block.
	for _, tx := range candidate.Transactions {
		if tx.Type == TxClaim {
			claimCounts[tx.NodeID]++
		}
	}

	// Count claims in the preceding window.
	windowStart := 0
	if len(chain) > RateLimitWindow {
		windowStart = len(chain) - RateLimitWindow
	}
	for i := windowStart; i < len(chain); i++ {
		for _, tx := range chain[i].Transactions {
			if tx.Type == TxClaim {
				claimCounts[tx.NodeID]++
			}
		}
	}

	for nodeID, count := range claimCounts {
		if count > RateLimitMaxClaims {
			return fmt.Errorf("rate limit exceeded for node %s: %d claims in window (max %d)", nodeID[:16], count, RateLimitMaxClaims)
		}
	}
	return nil
}

// ValidateChain validates an entire chain from genesis to tip.
func ValidateChain(blocks []Block) error {
	if len(blocks) == 0 {
		return errors.New("empty chain")
	}

	genesis := NewGenesisBlock()
	if blocks[0].Hash != genesis.Hash || blocks[0].PrevHash != genesis.PrevHash || blocks[0].Index != 0 {
		return errors.New("genesis block mismatch")
	}

	seqTracker := make(map[string]uint64)

	for i := 1; i < len(blocks); i++ {
		b := blocks[i]
		prev := blocks[i-1]

		if b.Index != prev.Index+1 {
			return fmt.Errorf("block %d: invalid index", i)
		}
		if b.PrevHash != prev.Hash {
			return fmt.Errorf("block %d: previous hash mismatch", i)
		}
		if b.Hash != b.ComputeHash() {
			return fmt.Errorf("block %d: hash mismatch", i)
		}

		for j, tx := range b.Transactions {
			if !tx.VerifySignature() {
				return fmt.Errorf("block %d tx %d: invalid signature", i, j)
			}
			if err := validateTxType(&tx); err != nil {
				return fmt.Errorf("block %d tx %d: %w", i, j, err)
			}
			// Sequence number replay protection.
			if tx.Seq <= seqTracker[tx.NodeID] && tx.Seq != 0 {
				return fmt.Errorf("block %d tx %d: replayed sequence number %d", i, j, tx.Seq)
			}
			if tx.Seq > seqTracker[tx.NodeID] {
				seqTracker[tx.NodeID] = tx.Seq
			}
		}

		if err := enforceRateLimit(b, blocks[:i]); err != nil {
			return fmt.Errorf("block %d: %w", i, err)
		}
	}
	return nil
}
