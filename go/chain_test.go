package addrchain

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

func generateTestKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	return pub, priv
}

func nodeIDFromKey(pub ed25519.PublicKey) string {
	return hex.EncodeToString(pub)
}

func TestGenesisBlockDeterministic(t *testing.T) {
	g1 := NewGenesisBlock()
	g2 := NewGenesisBlock()
	if g1.Hash != g2.Hash {
		t.Fatalf("genesis blocks must be deterministic: %s != %s", g1.Hash, g2.Hash)
	}
	if g1.Index != 0 {
		t.Fatalf("genesis index must be 0")
	}
	if g1.PrevHash != "0000000000000000000000000000000000000000000000000000000000000000" {
		t.Fatalf("genesis prev hash must be all zeros")
	}
}

func TestBlockHashIntegrity(t *testing.T) {
	g := NewGenesisBlock()
	if g.Hash != g.ComputeHash() {
		t.Fatal("genesis hash does not match computed hash")
	}

	pub, priv := generateTestKey()
	tx := Transaction{
		Type:      TxClaim,
		NodeID:    nodeIDFromKey(pub),
		Address:   "192.168.1.100",
		Timestamp: 1000,
		Seq:       1,
	}
	tx.Sign(priv)

	b := NewBlock(g, []Transaction{tx})
	if b.Hash != b.ComputeHash() {
		t.Fatal("block hash does not match computed hash")
	}
}

func TestTransactionSignatureVerification(t *testing.T) {
	pub, priv := generateTestKey()
	tx := Transaction{
		Type:      TxClaim,
		NodeID:    nodeIDFromKey(pub),
		Address:   "10.0.0.1",
		Timestamp: 1000,
		Seq:       1,
	}
	tx.Sign(priv)

	if !tx.VerifySignature() {
		t.Fatal("valid signature should verify")
	}

	tx.Address = "10.0.0.2"
	if tx.VerifySignature() {
		t.Fatal("tampered transaction should not verify")
	}
}

func TestTransactionForgedNodeID(t *testing.T) {
	_, priv := generateTestKey()
	pub2, _ := generateTestKey()

	tx := Transaction{
		Type:      TxClaim,
		NodeID:    nodeIDFromKey(pub2),
		Address:   "10.0.0.1",
		Timestamp: 1000,
		Seq:       1,
	}
	tx.Sign(priv)

	if tx.VerifySignature() {
		t.Fatal("transaction signed with wrong key should not verify")
	}
}

func TestNewChain(t *testing.T) {
	c := NewChain()
	if c.Len() != 1 {
		t.Fatalf("new chain should have 1 block (genesis), got %d", c.Len())
	}
}

func TestAddValidBlock(t *testing.T) {
	c := NewChain()
	pub, priv := generateTestKey()

	tx := Transaction{
		Type:      TxClaim,
		NodeID:    nodeIDFromKey(pub),
		Address:   "192.168.1.50",
		Timestamp: 2000,
		Seq:       1,
	}
	tx.Sign(priv)

	b := NewBlock(c.LastBlock(), []Transaction{tx})
	if err := c.AddBlock(b); err != nil {
		t.Fatalf("failed to add valid block: %v", err)
	}
	if c.Len() != 2 {
		t.Fatalf("chain should have 2 blocks, got %d", c.Len())
	}
}

func TestRejectBrokenHash(t *testing.T) {
	c := NewChain()
	pub, priv := generateTestKey()

	tx := Transaction{
		Type:      TxClaim,
		NodeID:    nodeIDFromKey(pub),
		Address:   "192.168.1.50",
		Timestamp: 2000,
		Seq:       1,
	}
	tx.Sign(priv)

	b := NewBlock(c.LastBlock(), []Transaction{tx})
	b.Hash = "badhash"
	if err := c.AddBlock(b); err == nil {
		t.Fatal("should reject block with incorrect hash")
	}
}

func TestRejectBrokenPrevHash(t *testing.T) {
	c := NewChain()
	pub, priv := generateTestKey()

	tx := Transaction{
		Type:      TxClaim,
		NodeID:    nodeIDFromKey(pub),
		Address:   "192.168.1.50",
		Timestamp: 2000,
		Seq:       1,
	}
	tx.Sign(priv)

	b := NewBlock(c.LastBlock(), []Transaction{tx})
	b.PrevHash = "0000000000000000000000000000000000000000000000000000000000000001"
	b.Hash = b.ComputeHash()
	if err := c.AddBlock(b); err == nil {
		t.Fatal("should reject block with wrong prev hash")
	}
}

func TestRejectInvalidSignature(t *testing.T) {
	c := NewChain()
	pub, _ := generateTestKey()

	tx := Transaction{
		Type:      TxClaim,
		NodeID:    nodeIDFromKey(pub),
		Address:   "10.0.0.1",
		Timestamp: 1000,
		Seq:       1,
		Signature: "deadbeef",
	}

	b := NewBlock(c.LastBlock(), []Transaction{tx})
	b.Hash = b.ComputeHash()
	if err := c.AddBlock(b); err == nil {
		t.Fatal("should reject block with invalid transaction signature")
	}
}

func TestRejectUnknownTxType(t *testing.T) {
	c := NewChain()
	pub, priv := generateTestKey()

	tx := Transaction{
		Type:      "STEAL",
		NodeID:    nodeIDFromKey(pub),
		Address:   "10.0.0.1",
		Timestamp: 1000,
		Seq:       1,
	}
	tx.Sign(priv)

	b := NewBlock(c.LastBlock(), []Transaction{tx})
	b.Hash = b.ComputeHash()
	if err := c.AddBlock(b); err == nil {
		t.Fatal("should reject block with unknown transaction type")
	}
}

func TestValidateChainValid(t *testing.T) {
	c := NewChain()
	pub, priv := generateTestKey()

	for i := uint64(1); i <= 3; i++ {
		tx := Transaction{
			Type:      TxClaim,
			NodeID:    nodeIDFromKey(pub),
			Address:   "10.0.0." + string(rune('0'+i)),
			Timestamp: int64(i * 1000),
			Seq:       i,
		}
		tx.Sign(priv)
		b := NewBlock(c.LastBlock(), []Transaction{tx})
		if err := c.AddBlock(b); err != nil {
			t.Fatalf("block %d: %v", i, err)
		}
	}

	if err := ValidateChain(c.GetBlocks()); err != nil {
		t.Fatalf("valid chain should validate: %v", err)
	}
}

func TestValidateChainRejectsReplay(t *testing.T) {
	pub, priv := generateTestKey()
	nid := nodeIDFromKey(pub)

	genesis := NewGenesisBlock()

	tx1 := Transaction{Type: TxClaim, NodeID: nid, Address: "10.0.0.1", Timestamp: 1000, Seq: 1}
	tx1.Sign(priv)
	b1 := NewBlock(genesis, []Transaction{tx1})

	tx2 := Transaction{Type: TxClaim, NodeID: nid, Address: "10.0.0.2", Timestamp: 2000, Seq: 1}
	tx2.Sign(priv)
	b2 := NewBlock(b1, []Transaction{tx2})

	err := ValidateChain([]Block{genesis, b1, b2})
	if err == nil {
		t.Fatal("should reject chain with replayed sequence number")
	}
}

func TestReplaceChainLonger(t *testing.T) {
	c := NewChain()

	pub, priv := generateTestKey()
	nid := nodeIDFromKey(pub)

	genesis := NewGenesisBlock()
	var candidate []Block
	candidate = append(candidate, genesis)

	prev := genesis
	for i := uint64(1); i <= 3; i++ {
		tx := Transaction{Type: TxClaim, NodeID: nid, Address: "10.0.0." + string(rune('0'+i)), Timestamp: int64(i * 1000), Seq: i}
		tx.Sign(priv)
		b := NewBlock(prev, []Transaction{tx})
		candidate = append(candidate, b)
		prev = b
	}

	replaced, err := c.ReplaceChain(candidate)
	if err != nil {
		t.Fatalf("replace should succeed: %v", err)
	}
	if !replaced {
		t.Fatal("longer valid chain should replace shorter one")
	}
	if c.Len() != 4 {
		t.Fatalf("chain should have 4 blocks, got %d", c.Len())
	}
}

func TestReplaceChainRejectsShorter(t *testing.T) {
	c := NewChain()
	pub, priv := generateTestKey()
	nid := nodeIDFromKey(pub)

	tx := Transaction{Type: TxClaim, NodeID: nid, Address: "10.0.0.1", Timestamp: 1000, Seq: 1}
	tx.Sign(priv)
	b := NewBlock(c.LastBlock(), []Transaction{tx})
	_ = c.AddBlock(b)

	candidate := []Block{NewGenesisBlock()}
	replaced, _ := c.ReplaceChain(candidate)
	if replaced {
		t.Fatal("shorter chain should not replace longer one")
	}
}

func TestRateLimitEnforced(t *testing.T) {
	c := NewChain()
	pub, priv := generateTestKey()
	nid := nodeIDFromKey(pub)

	// Fill up to the rate limit across multiple blocks.
	for i := uint64(1); i <= uint64(RateLimitMaxClaims); i++ {
		tx := Transaction{Type: TxClaim, NodeID: nid, Address: "10.0.0." + string(rune(48+i)), Timestamp: int64(i * 1000), Seq: i}
		tx.Sign(priv)
		b := NewBlock(c.LastBlock(), []Transaction{tx})
		if err := c.AddBlock(b); err != nil {
			t.Fatalf("block %d should succeed: %v", i, err)
		}
	}

	// One more should be rejected.
	seq := uint64(RateLimitMaxClaims + 1)
	tx := Transaction{Type: TxClaim, NodeID: nid, Address: "10.0.0.99", Timestamp: 99000, Seq: seq}
	tx.Sign(priv)
	b := NewBlock(c.LastBlock(), []Transaction{tx})
	if err := c.AddBlock(b); err == nil {
		t.Fatal("should reject block exceeding rate limit")
	}
}

func TestRevokeTxRequiresNewNodeID(t *testing.T) {
	c := NewChain()
	pub, priv := generateTestKey()
	nid := nodeIDFromKey(pub)

	tx := Transaction{Type: TxRevoke, NodeID: nid, Timestamp: 1000, Seq: 1}
	tx.Sign(priv)

	b := NewBlock(c.LastBlock(), []Transaction{tx})
	b.Hash = b.ComputeHash()
	if err := c.AddBlock(b); err == nil {
		t.Fatal("REVOKE without NewNodeID should be rejected")
	}
}

func TestValidRevokeTx(t *testing.T) {
	c := NewChain()
	pub, priv := generateTestKey()
	pub2, _ := generateTestKey()
	nid := nodeIDFromKey(pub)
	newNid := nodeIDFromKey(pub2)

	tx := Transaction{Type: TxRevoke, NodeID: nid, NewNodeID: newNid, Timestamp: 1000, Seq: 1}
	tx.Sign(priv)

	b := NewBlock(c.LastBlock(), []Transaction{tx})
	if err := c.AddBlock(b); err != nil {
		t.Fatalf("valid REVOKE should succeed: %v", err)
	}
}
