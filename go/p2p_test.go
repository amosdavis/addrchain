package addrchain

import (
	"net"
	"testing"
	"time"
)

func TestPeerDiscoveryAndSync(t *testing.T) {
	// Create two nodes with separate chains.
	pub1, priv1 := generateTestKey()
	nid1 := nodeIDFromKey(pub1)
	chain1 := NewChain()
	claims1 := NewClaimStore(100)

	pub2, _ := generateTestKey()
	nid2 := nodeIDFromKey(pub2)
	chain2 := NewChain()
	claims2 := NewClaimStore(100)

	// Add a block to chain1 so it's longer.
	tx := Transaction{Type: TxClaim, NodeID: nid1, Address: "10.0.0.1", Timestamp: 1000, Seq: 1}
	tx.Sign(priv1)
	b := NewBlock(chain1.LastBlock(), []Transaction{tx})
	_ = chain1.AddBlock(b)
	claims1.ApplyBlock(b)

	// Start node1 on dynamic ports (port 0).
	node1 := NewNode(nid1, chain1, claims1, 0, 0, nil)
	if err := node1.Start(); err != nil {
		t.Fatalf("node1 start: %v", err)
	}
	defer node1.Stop()

	// Start node2 with node1 as a manual peer.
	node2 := NewNode(nid2, chain2, claims2, 0, 0, []string{node1.TCPAddr})
	if err := node2.Start(); err != nil {
		t.Fatalf("node2 start: %v", err)
	}
	defer node2.Stop()

	// Wait for sync with polling.
	for i := 0; i < 10; i++ {
		if chain2.Len() >= 2 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if chain2.Len() != 2 {
		t.Fatalf("node2 should have synced to 2 blocks, got %d", chain2.Len())
	}
}

func TestBroadcastNewBlock(t *testing.T) {
	pub1, priv1 := generateTestKey()
	nid1 := nodeIDFromKey(pub1)
	chain1 := NewChain()
	claims1 := NewClaimStore(100)

	pub2, _ := generateTestKey()
	nid2 := nodeIDFromKey(pub2)
	chain2 := NewChain()
	claims2 := NewClaimStore(100)

	node1 := NewNode(nid1, chain1, claims1, 0, 0, nil)
	_ = node1.Start()
	defer node1.Stop()

	node2 := NewNode(nid2, chain2, claims2, 0, 0, []string{node1.TCPAddr})
	_ = node2.Start()
	defer node2.Stop()

	// Also tell node1 about node2.
	node1.mu.Lock()
	node1.peers[node2.TCPAddr] = &Peer{NodeID: nid2, TCPAddr: node2.TCPAddr, LastSeen: time.Now()}
	node1.mu.Unlock()

	time.Sleep(1 * time.Second)

	// Node1 creates and broadcasts a new block.
	tx := Transaction{Type: TxClaim, NodeID: nid1, Address: "192.168.1.50", Timestamp: 1000, Seq: 1}
	tx.Sign(priv1)
	b := NewBlock(chain1.LastBlock(), []Transaction{tx})
	_ = chain1.AddBlock(b)
	claims1.ApplyBlock(b)
	node1.BroadcastBlock(b)

	time.Sleep(2 * time.Second)

	if chain2.Len() != 2 {
		t.Fatalf("node2 should have received broadcast block, chain len = %d", chain2.Len())
	}
	_ = nid2
}

func TestRejectMalformedMessage(t *testing.T) {
	pub, _ := generateTestKey()
	nid := nodeIDFromKey(pub)
	chain := NewChain()
	claims := NewClaimStore(100)

	node := NewNode(nid, chain, claims, 0, 0, nil)
	_ = node.Start()
	defer node.Stop()

	// Send garbage to TCP port — should not crash the node.
	conn, err := net.DialTimeout("tcp", node.TCPAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Write([]byte("this is not json{{{"))
	conn.Close()

	// Node should still be alive.
	time.Sleep(500 * time.Millisecond)
	if chain.Len() != 1 {
		t.Fatal("node chain should be unchanged after malformed message")
	}
}

func TestRollbackCallback(t *testing.T) {
	pub1, priv1 := generateTestKey()
	nid1 := nodeIDFromKey(pub1)
	chain1 := NewChain()
	claims1 := NewClaimStore(100)

	// Node1 claims an address.
	tx := Transaction{Type: TxClaim, NodeID: nid1, Address: "10.0.0.1", Timestamp: 1000, Seq: 1}
	tx.Sign(priv1)
	b := NewBlock(chain1.LastBlock(), []Transaction{tx})
	_ = chain1.AddBlock(b)
	claims1.ApplyBlock(b)

	node1 := NewNode(nid1, chain1, claims1, 0, 0, nil)

	var rolledBack []string
	node1.SetRollbackCallback(func(lost []string) {
		rolledBack = lost
	})

	_ = node1.Start()
	defer node1.Stop()

	// Create a longer chain from a different node that doesn't include node1's claim.
	pub2, priv2 := generateTestKey()
	nid2 := nodeIDFromKey(pub2)

	genesis := NewGenesisBlock()
	longerChain := []Block{genesis}
	prev := genesis
	for i := uint64(1); i <= 3; i++ {
		tx := Transaction{Type: TxClaim, NodeID: nid2, Address: "192.168.0." + string(rune('0'+i)), Timestamp: int64(i * 1000), Seq: i}
		tx.Sign(priv2)
		blk := NewBlock(prev, []Transaction{tx})
		longerChain = append(longerChain, blk)
		prev = blk
	}

	node1.tryReplaceChain(longerChain)

	if len(rolledBack) != 1 || rolledBack[0] != "10.0.0.1" {
		t.Fatalf("expected rollback of 10.0.0.1, got %v", rolledBack)
	}
}


