package addrchain

import (
	"encoding/hex"
	"testing"
)

func TestClaimAndRelease(t *testing.T) {
	cs := NewClaimStore(100)
	pub, priv := generateTestKey()
	nid := nodeIDFromKey(pub)

	chain := NewChain()

	tx := Transaction{Type: TxClaim, NodeID: nid, Address: "10.0.0.1", Timestamp: 1000, Seq: 1}
	tx.Sign(priv)
	b := NewBlock(chain.LastBlock(), []Transaction{tx})
	_ = chain.AddBlock(b)
	cs.ApplyBlock(b)

	if owner := cs.GetOwner("10.0.0.1"); owner != nid {
		t.Fatalf("expected owner %s, got %s", nid[:16], owner)
	}

	tx2 := Transaction{Type: TxRelease, NodeID: nid, Address: "10.0.0.1", Timestamp: 2000, Seq: 2}
	tx2.Sign(priv)
	b2 := NewBlock(chain.LastBlock(), []Transaction{tx2})
	_ = chain.AddBlock(b2)
	cs.ApplyBlock(b2)

	if owner := cs.GetOwner("10.0.0.1"); owner != "" {
		t.Fatalf("address should be released, got owner %s", owner)
	}
}

func TestConflictDetection(t *testing.T) {
	cs := NewClaimStore(100)
	pub1, priv1 := generateTestKey()
	pub2, priv2 := generateTestKey()
	nid1 := nodeIDFromKey(pub1)
	nid2 := nodeIDFromKey(pub2)

	chain := NewChain()

	// Node 1 claims address.
	tx1 := Transaction{Type: TxClaim, NodeID: nid1, Address: "10.0.0.1", Timestamp: 1000, Seq: 1}
	tx1.Sign(priv1)
	b1 := NewBlock(chain.LastBlock(), []Transaction{tx1})
	_ = chain.AddBlock(b1)
	cs.ApplyBlock(b1)

	// Node 2 tries to claim same address — should be rejected.
	tx2 := Transaction{Type: TxClaim, NodeID: nid2, Address: "10.0.0.1", Timestamp: 2000, Seq: 1}
	tx2.Sign(priv2)
	b2 := NewBlock(chain.LastBlock(), []Transaction{tx2})

	if err := cs.ValidateNewBlock(b2); err == nil {
		t.Fatal("should reject conflicting claim")
	}
}

func TestReleaseByWrongNode(t *testing.T) {
	cs := NewClaimStore(100)
	pub1, priv1 := generateTestKey()
	pub2, priv2 := generateTestKey()
	nid1 := nodeIDFromKey(pub1)
	nid2 := nodeIDFromKey(pub2)

	chain := NewChain()

	tx1 := Transaction{Type: TxClaim, NodeID: nid1, Address: "10.0.0.1", Timestamp: 1000, Seq: 1}
	tx1.Sign(priv1)
	b1 := NewBlock(chain.LastBlock(), []Transaction{tx1})
	_ = chain.AddBlock(b1)
	cs.ApplyBlock(b1)

	// Node 2 tries to release node 1's address.
	tx2 := Transaction{Type: TxRelease, NodeID: nid2, Address: "10.0.0.1", Timestamp: 2000, Seq: 1}
	tx2.Sign(priv2)
	b2 := NewBlock(chain.LastBlock(), []Transaction{tx2})

	if err := cs.ValidateNewBlock(b2); err == nil {
		t.Fatal("should reject release by non-owner")
	}
	_ = nid2
}

func TestLeaseExpiry(t *testing.T) {
	leaseTTL := uint64(5)
	cs := NewClaimStore(leaseTTL)

	pub, priv := generateTestKey()
	nid := nodeIDFromKey(pub)

	chain := NewChain()

	// Claim at block 1.
	tx := Transaction{Type: TxClaim, NodeID: nid, Address: "10.0.0.1", Timestamp: 1000, Seq: 1}
	tx.Sign(priv)
	b := NewBlock(chain.LastBlock(), []Transaction{tx})
	_ = chain.AddBlock(b)
	cs.ApplyBlock(b)

	// Simulate blocks 2..7 (past TTL) with no renewal.
	for i := uint64(2); i <= leaseTTL+2; i++ {
		empty := NewBlock(chain.LastBlock(), []Transaction{})
		_ = chain.AddBlock(empty)
		cs.ApplyBlock(empty)
	}

	if owner := cs.GetOwner("10.0.0.1"); owner != "" {
		t.Fatalf("claim should have expired, but got owner %s", owner)
	}
}

func TestRenewExtendsLease(t *testing.T) {
	leaseTTL := uint64(5)
	cs := NewClaimStore(leaseTTL)

	pub, priv := generateTestKey()
	nid := nodeIDFromKey(pub)

	chain := NewChain()

	// Claim at block 1.
	tx := Transaction{Type: TxClaim, NodeID: nid, Address: "10.0.0.1", Timestamp: 1000, Seq: 1}
	tx.Sign(priv)
	b := NewBlock(chain.LastBlock(), []Transaction{tx})
	_ = chain.AddBlock(b)
	cs.ApplyBlock(b)

	// Add blocks 2..4 (within TTL).
	for i := uint64(2); i <= 4; i++ {
		empty := NewBlock(chain.LastBlock(), []Transaction{})
		_ = chain.AddBlock(empty)
		cs.ApplyBlock(empty)
	}

	// Renew at block 5.
	txR := Transaction{Type: TxRenew, NodeID: nid, Address: "10.0.0.1", Timestamp: 5000, Seq: 2}
	txR.Sign(priv)
	bR := NewBlock(chain.LastBlock(), []Transaction{txR})
	_ = chain.AddBlock(bR)
	cs.ApplyBlock(bR)

	// Add blocks 6..9 (within TTL from renewal).
	for i := uint64(6); i <= 9; i++ {
		empty := NewBlock(chain.LastBlock(), []Transaction{})
		_ = chain.AddBlock(empty)
		cs.ApplyBlock(empty)
	}

	if owner := cs.GetOwner("10.0.0.1"); owner != nid {
		t.Fatal("claim should still be active after renewal")
	}
}

func TestRevokeMigratesClaims(t *testing.T) {
	cs := NewClaimStore(100)
	pub1, priv1 := generateTestKey()
	pub2, _ := generateTestKey()
	nid1 := nodeIDFromKey(pub1)
	nid2 := nodeIDFromKey(pub2)

	chain := NewChain()

	// Claim address with old key.
	tx := Transaction{Type: TxClaim, NodeID: nid1, Address: "10.0.0.1", Timestamp: 1000, Seq: 1}
	tx.Sign(priv1)
	b := NewBlock(chain.LastBlock(), []Transaction{tx})
	_ = chain.AddBlock(b)
	cs.ApplyBlock(b)

	// Revoke old key, migrate to new.
	txR := Transaction{Type: TxRevoke, NodeID: nid1, NewNodeID: nid2, Timestamp: 2000, Seq: 2}
	txR.Sign(priv1)
	bR := NewBlock(chain.LastBlock(), []Transaction{txR})
	_ = chain.AddBlock(bR)
	cs.ApplyBlock(bR)

	if owner := cs.GetOwner("10.0.0.1"); owner != nid2 {
		t.Fatalf("claim should be migrated to new node ID, got %s", owner)
	}
}

func TestRebuildDetectsRollbackLoss(t *testing.T) {
	cs := NewClaimStore(100)
	pub, priv := generateTestKey()
	nid := nodeIDFromKey(pub)

	chain := NewChain()

	// Claim address.
	tx := Transaction{Type: TxClaim, NodeID: nid, Address: "10.0.0.1", Timestamp: 1000, Seq: 1}
	tx.Sign(priv)
	b := NewBlock(chain.LastBlock(), []Transaction{tx})
	_ = chain.AddBlock(b)
	cs.ApplyBlock(b)

	// Now rebuild from a chain that doesn't include our claim (simulating rollback).
	genesisOnly := []Block{NewGenesisBlock()}
	lost := cs.RebuildFromChain(genesisOnly, nid)

	if len(lost) != 1 || lost[0] != "10.0.0.1" {
		t.Fatalf("expected to detect loss of 10.0.0.1, got %v", lost)
	}
}

func TestGetClaimsByNode(t *testing.T) {
	cs := NewClaimStore(100)
	pub, priv := generateTestKey()
	nid := nodeIDFromKey(pub)

	chain := NewChain()

	for i := uint64(1); i <= 3; i++ {
		addr := "10.0.0." + string(rune('0'+i))
		tx := Transaction{Type: TxClaim, NodeID: nid, Address: addr, Timestamp: int64(i * 1000), Seq: i}
		tx.Sign(priv)
		b := NewBlock(chain.LastBlock(), []Transaction{tx})
		_ = chain.AddBlock(b)
		cs.ApplyBlock(b)
	}

	addrs := cs.GetClaimsByNode(nid)
	if len(addrs) != 3 {
		t.Fatalf("expected 3 claims, got %d", len(addrs))
	}
}

func TestPruneExpiredBlocks(t *testing.T) {
	pub, priv := generateTestKey()
	nid := nodeIDFromKey(pub)
	_ = hex.EncodeToString(pub)

	genesis := NewGenesisBlock()
	blocks := []Block{genesis}
	prev := genesis

	// Block 1: claim that will expire.
	tx := Transaction{Type: TxClaim, NodeID: nid, Address: "10.0.0.1", Timestamp: 1000, Seq: 1}
	tx.Sign(priv)
	b1 := NewBlock(prev, []Transaction{tx})
	blocks = append(blocks, b1)
	prev = b1

	// Blocks 2..12: empty (TTL of 5 means block 1's claim expires by block 7).
	for i := uint64(2); i <= 12; i++ {
		bE := NewBlock(prev, []Transaction{})
		blocks = append(blocks, bE)
		prev = bE
	}

	pruned := PruneExpiredBlocks(blocks, 5)
	// All claims expired, so pruning should keep just genesis + the last block.
	if len(pruned) >= len(blocks) {
		t.Fatalf("pruning should reduce chain, got %d (original %d)", len(pruned), len(blocks))
	}
}
