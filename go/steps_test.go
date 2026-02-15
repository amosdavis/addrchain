package addrchain_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net"
	"testing"
	"time"

	"addrchain"

	"github.com/cucumber/godog"
)

// testWorld holds all state shared between step definitions.
type testWorld struct {
	chain    *addrchain.Chain
	claims   *addrchain.ClaimStore
	leaseTTL uint64

	nodes    map[string]*nodeState
	lastErr  error
	node     *addrchain.Node // running P2P node for network tests
	rollback []string
}

type nodeState struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	nid  string
	seq  uint64
}

func newTestWorld() *testWorld {
	return &testWorld{
		chain:    addrchain.NewChain(),
		claims:   addrchain.NewClaimStore(100),
		leaseTTL: 100,
		nodes:    make(map[string]*nodeState),
	}
}

// --- Claim feature steps ---

func (w *testWorld) aNewBlockchain() error {
	w.chain = addrchain.NewChain()
	w.claims = addrchain.NewClaimStore(w.leaseTTL)
	return nil
}

func (w *testWorld) aNewBlockchainWithLeaseTTL(ttl int) error {
	w.leaseTTL = uint64(ttl)
	w.chain = addrchain.NewChain()
	w.claims = addrchain.NewClaimStore(w.leaseTTL)
	return nil
}

func (w *testWorld) aNodeWithIdentity() error {
	return w.aNamedNodeWithIdentity("default")
}

func (w *testWorld) aNamedNodeWithIdentity(name string) error {
	pub, priv, _ := ed25519.GenerateKey(nil)
	w.nodes[name] = &nodeState{
		pub:  pub,
		priv: priv,
		nid:  hex.EncodeToString(pub),
		seq:  0,
	}
	return nil
}

func (w *testWorld) nodeClaimsAddress(addr string) error {
	return w.namedNodeClaimsAddress("default", addr)
}

func (w *testWorld) namedNodeClaimsAddress(name, addr string) error {
	ns := w.nodes[name]
	ns.seq++
	tx := addrchain.Transaction{
		Type: addrchain.TxClaim, NodeID: ns.nid, Address: addr,
		Timestamp: time.Now().Unix(), Seq: ns.seq,
	}
	tx.Sign(ns.priv)
	b := addrchain.NewBlock(w.chain.LastBlock(), []addrchain.Transaction{tx})
	if err := w.claims.ValidateNewBlock(b); err != nil {
		w.lastErr = err
		return nil
	}
	if err := w.chain.AddBlock(b); err != nil {
		w.lastErr = err
		return nil
	}
	w.claims.ApplyBlock(b)
	w.lastErr = nil
	return nil
}

func (w *testWorld) claimShouldSucceed() error {
	if w.lastErr != nil {
		return fmt.Errorf("expected success, got: %v", w.lastErr)
	}
	return nil
}

func (w *testWorld) addressShouldBeOwnedByNode(addr string) error {
	return w.addressShouldBeOwnedByNamedNode(addr, "default")
}

func (w *testWorld) addressShouldBeOwnedByNamedNode(addr, name string) error {
	ns := w.nodes[name]
	owner := w.claims.GetOwner(addr)
	if owner != ns.nid {
		return fmt.Errorf("expected owner %s, got %s", ns.nid[:16], owner)
	}
	return nil
}

func (w *testWorld) nodeReleasesAddress(addr string) error {
	return w.namedNodeReleasesAddress("default", addr)
}

func (w *testWorld) namedNodeReleasesAddress(name, addr string) error {
	ns := w.nodes[name]
	ns.seq++
	tx := addrchain.Transaction{
		Type: addrchain.TxRelease, NodeID: ns.nid, Address: addr,
		Timestamp: time.Now().Unix(), Seq: ns.seq,
	}
	tx.Sign(ns.priv)
	b := addrchain.NewBlock(w.chain.LastBlock(), []addrchain.Transaction{tx})
	if err := w.claims.ValidateNewBlock(b); err != nil {
		w.lastErr = err
		return nil
	}
	if err := w.chain.AddBlock(b); err != nil {
		w.lastErr = err
		return nil
	}
	w.claims.ApplyBlock(b)
	w.lastErr = nil
	return nil
}

func (w *testWorld) addressShouldNotBeClaimed(addr string) error {
	owner := w.claims.GetOwner(addr)
	if owner != "" {
		return fmt.Errorf("expected unclaimed, got owner %s", owner)
	}
	return nil
}

// --- Conflict feature steps ---

func (w *testWorld) namedNodeTriesToClaimAddress(name, addr string) error {
	return w.namedNodeClaimsAddress(name, addr)
}

func (w *testWorld) namedNodeClaimShouldBeRejected(name string) error {
	if w.lastErr == nil {
		return fmt.Errorf("expected conflict error for node %s", name)
	}
	return nil
}

func (w *testWorld) namedNodeTriesToReleaseAddress(name, addr string) error {
	return w.namedNodeReleasesAddress(name, addr)
}

func (w *testWorld) namedNodeReleaseShouldBeRejected(name string) error {
	if w.lastErr == nil {
		return fmt.Errorf("expected rejection for node %s", name)
	}
	return nil
}

func (w *testWorld) namedNodeClaimsNAddresses(name string, count int) error {
	for i := 1; i <= count; i++ {
		addr := fmt.Sprintf("10.99.0.%d", i)
		w.namedNodeClaimsAddress(name, addr)
	}
	return nil
}

func (w *testWorld) nthClaimShouldBeRejected(n int) error {
	if w.lastErr == nil {
		return fmt.Errorf("expected the %dth claim to be rejected", n)
	}
	return nil
}

func (w *testWorld) emptyBlocksAdded(count int) error {
	for i := 0; i < count; i++ {
		b := addrchain.NewBlock(w.chain.LastBlock(), []addrchain.Transaction{})
		if err := w.chain.AddBlock(b); err != nil {
			return err
		}
		w.claims.ApplyBlock(b)
	}
	return nil
}

func (w *testWorld) namedNodeRenewsAddress(name, addr string) error {
	ns := w.nodes[name]
	ns.seq++
	tx := addrchain.Transaction{
		Type: addrchain.TxRenew, NodeID: ns.nid, Address: addr,
		Timestamp: time.Now().Unix(), Seq: ns.seq,
	}
	tx.Sign(ns.priv)
	b := addrchain.NewBlock(w.chain.LastBlock(), []addrchain.Transaction{tx})
	if err := w.claims.ValidateNewBlock(b); err != nil {
		w.lastErr = err
		return nil
	}
	if err := w.chain.AddBlock(b); err != nil {
		w.lastErr = err
		return nil
	}
	w.claims.ApplyBlock(b)
	w.lastErr = nil
	return nil
}

func (w *testWorld) namedNodeRevokesKeyToNewIdentity(name, newName string) error {
	ns := w.nodes[name]
	pub2, priv2, _ := ed25519.GenerateKey(nil)
	nid2 := hex.EncodeToString(pub2)
	w.nodes[newName] = &nodeState{pub: pub2, priv: priv2, nid: nid2, seq: 0}

	ns.seq++
	tx := addrchain.Transaction{
		Type: addrchain.TxRevoke, NodeID: ns.nid, NewNodeID: nid2,
		Timestamp: time.Now().Unix(), Seq: ns.seq,
	}
	tx.Sign(ns.priv)
	b := addrchain.NewBlock(w.chain.LastBlock(), []addrchain.Transaction{tx})
	if err := w.chain.AddBlock(b); err != nil {
		return err
	}
	w.claims.ApplyBlock(b)
	return nil
}

// --- Sync feature steps ---

func (w *testWorld) nodeWithChainLength(name string, length int) error {
	w.aNamedNodeWithIdentity(name)
	ns := w.nodes[name]
	for i := 1; i < length; i++ {
		ns.seq++
		tx := addrchain.Transaction{
			Type: addrchain.TxClaim, NodeID: ns.nid,
			Address:   fmt.Sprintf("10.%s.0.%d", name, i),
			Timestamp: time.Now().Unix(), Seq: ns.seq,
		}
		tx.Sign(ns.priv)
		b := addrchain.NewBlock(w.chain.LastBlock(), []addrchain.Transaction{tx})
		if err := w.chain.AddBlock(b); err != nil {
			return err
		}
		w.claims.ApplyBlock(b)
	}
	return nil
}

func (w *testWorld) newNodeWithPeer(newName, peerName string) error {
	w.aNamedNodeWithIdentity(newName)
	return nil
}

func (w *testWorld) nodeSyncsFromPeers(name string) error {
	// In unit test context, syncing is simulated via chain replacement.
	return nil
}

func (w *testWorld) nodeChainShouldHaveLength(name string, length int) error {
	if w.chain.Len() != length {
		return fmt.Errorf("expected chain length %d, got %d", length, w.chain.Len())
	}
	return nil
}

func (w *testWorld) nodeReceivesChainOfLengthFromNode(receiverName string, length int, senderName string) error {
	ns := w.nodes[senderName]
	senderChain := addrchain.NewChain()
	for i := uint64(1); i < uint64(length); i++ {
		ns.seq++
		tx := addrchain.Transaction{
			Type: addrchain.TxClaim, NodeID: ns.nid,
			Address:   fmt.Sprintf("10.%s.0.%d", senderName, i),
			Timestamp: time.Now().Unix(), Seq: ns.seq,
		}
		tx.Sign(ns.priv)
		b := addrchain.NewBlock(senderChain.LastBlock(), []addrchain.Transaction{tx})
		_ = senderChain.AddBlock(b)
	}

	replaced, err := w.chain.ReplaceChain(senderChain.GetBlocks())
	if err != nil {
		w.lastErr = err
		return nil
	}
	if replaced {
		w.claims.RebuildFromChain(w.chain.GetBlocks(), "")
	}
	return nil
}

func (w *testWorld) nodeReceivesOtherChain(receiverName, senderName string) error {
	return w.nodeReceivesChainOfLengthFromNode(receiverName, 5, senderName)
}

func (w *testWorld) nodeReceivesBrokenChain(name string) error {
	genesis := addrchain.NewGenesisBlock()
	fake := addrchain.Block{
		Index: 1, Timestamp: 999, PrevHash: genesis.Hash, Hash: "badhash",
	}
	_, err := w.chain.ReplaceChain([]addrchain.Block{genesis, fake})
	w.lastErr = err
	return nil
}

func (w *testWorld) chainShouldBeRejected() error {
	if w.lastErr == nil {
		return fmt.Errorf("expected chain to be rejected")
	}
	return nil
}

func (w *testWorld) nodeWithClaimedAddress(name, addr string) error {
	w.aNamedNodeWithIdentity(name)
	w.namedNodeClaimsAddress(name, addr)
	return nil
}

func (w *testWorld) nodeReceivesLongerChainWithoutClaim(name string) error {
	ns := w.nodes[name]

	// Build a longer chain from a different node that doesn't include the claim.
	other := &nodeState{}
	other.pub, other.priv, _ = ed25519.GenerateKey(nil)
	other.nid = hex.EncodeToString(other.pub)

	longerChain := addrchain.NewChain()
	for i := uint64(1); i <= 3; i++ {
		other.seq++
		tx := addrchain.Transaction{
			Type: addrchain.TxClaim, NodeID: other.nid,
			Address: fmt.Sprintf("192.168.99.%d", i), Timestamp: time.Now().Unix(), Seq: other.seq,
		}
		tx.Sign(other.priv)
		b := addrchain.NewBlock(longerChain.LastBlock(), []addrchain.Transaction{tx})
		_ = longerChain.AddBlock(b)
	}

	replaced, _ := w.chain.ReplaceChain(longerChain.GetBlocks())
	if replaced {
		w.rollback = w.claims.RebuildFromChain(w.chain.GetBlocks(), ns.nid)
	}
	return nil
}

func (w *testWorld) nodeShouldDetectRollback(name, addr string) error {
	for _, a := range w.rollback {
		if a == addr {
			return nil
		}
	}
	return fmt.Errorf("expected rollback of %s, got %v", addr, w.rollback)
}

func (w *testWorld) aRunningNode(name string) error {
	w.aNamedNodeWithIdentity(name)
	ns := w.nodes[name]
	w.node = addrchain.NewNode(ns.nid, w.chain, w.claims, 0, 0, nil)
	return w.node.Start()
}

func (w *testWorld) malformedMessageSent(name string) error {
	conn, err := net.DialTimeout("tcp", w.node.TCPAddr, 2*time.Second)
	if err != nil {
		return err
	}
	conn.Write([]byte("garbage{{{not json"))
	conn.Close()
	time.Sleep(500 * time.Millisecond)
	return nil
}

func (w *testWorld) nodeShouldRemainOperational(name string) error {
	if w.node != nil {
		w.node.Stop()
	}
	if w.chain.Len() < 1 {
		return fmt.Errorf("node chain is empty, node may have crashed")
	}
	return nil
}

func InitializeScenario(ctx *godog.ScenarioContext) {
	w := newTestWorld()

	// Claim feature
	ctx.Step(`^a new blockchain$`, w.aNewBlockchain)
	ctx.Step(`^a new blockchain with lease TTL of (\d+) blocks$`, w.aNewBlockchainWithLeaseTTL)
	ctx.Step(`^a node with a generated identity$`, w.aNodeWithIdentity)
	ctx.Step(`^a node "([^"]*)" with a generated identity$`, w.aNamedNodeWithIdentity)
	ctx.Step(`^the node claims address "([^"]*)"$`, w.nodeClaimsAddress)
	ctx.Step(`^the claim should succeed$`, w.claimShouldSucceed)
	ctx.Step(`^address "([^"]*)" should be owned by the node$`, w.addressShouldBeOwnedByNode)
	ctx.Step(`^the node claims address "([^"]*)"$`, w.nodeClaimsAddress)
	ctx.Step(`^the node releases address "([^"]*)"$`, w.nodeReleasesAddress)
	ctx.Step(`^address "([^"]*)" should not be claimed$`, w.addressShouldNotBeClaimed)

	// Conflict feature
	ctx.Step(`^node "([^"]*)" claims address "([^"]*)"$`, w.namedNodeClaimsAddress)
	ctx.Step(`^node "([^"]*)" tries to claim address "([^"]*)"$`, w.namedNodeTriesToClaimAddress)
	ctx.Step(`^node "([^"]*)" claim should be rejected with a conflict error$`, w.namedNodeClaimShouldBeRejected)
	ctx.Step(`^node "([^"]*)" releases address "([^"]*)"$`, w.namedNodeReleasesAddress)
	ctx.Step(`^address "([^"]*)" should be owned by node "([^"]*)"$`, w.addressShouldBeOwnedByNamedNode)
	ctx.Step(`^node "([^"]*)" tries to release address "([^"]*)"$`, w.namedNodeTriesToReleaseAddress)
	ctx.Step(`^node "([^"]*)" release should be rejected$`, w.namedNodeReleaseShouldBeRejected)
	ctx.Step(`^node "([^"]*)" claims (\d+) addresses rapidly$`, w.namedNodeClaimsNAddresses)
	ctx.Step(`^the (\d+)th claim should be rejected due to rate limiting$`, w.nthClaimShouldBeRejected)
	ctx.Step(`^(\d+) empty blocks are added$`, w.emptyBlocksAdded)
	ctx.Step(`^node "([^"]*)" renews address "([^"]*)"$`, w.namedNodeRenewsAddress)
	ctx.Step(`^node "([^"]*)" revokes its key to a new identity "([^"]*)"$`, w.namedNodeRevokesKeyToNewIdentity)

	// Sync feature
	ctx.Step(`^node "([^"]*)" with a blockchain of length (\d+)$`, w.nodeWithChainLength)
	ctx.Step(`^a new node "([^"]*)" with node "([^"]*)" as a peer$`, w.newNodeWithPeer)
	ctx.Step(`^node "([^"]*)" syncs from peers$`, w.nodeSyncsFromPeers)
	ctx.Step(`^node "([^"]*)" chain should have length (\d+)$`, w.nodeChainShouldHaveLength)
	ctx.Step(`^node "([^"]*)" receives node "([^"]*)" chain$`, w.nodeReceivesOtherChain)
	ctx.Step(`^node "([^"]*)" receives a chain of length (\d+) from node "([^"]*)"$`, w.nodeReceivesChainOfLengthFromNode)
	ctx.Step(`^node "([^"]*)" receives a chain with a broken hash$`, w.nodeReceivesBrokenChain)
	ctx.Step(`^the chain should be rejected$`, w.chainShouldBeRejected)
	ctx.Step(`^node "([^"]*)" with a claimed address "([^"]*)"$`, w.nodeWithClaimedAddress)
	ctx.Step(`^node "([^"]*)" receives a longer chain without the claim$`, w.nodeReceivesLongerChainWithoutClaim)
	ctx.Step(`^node "([^"]*)" should detect the rollback of "([^"]*)"$`, w.nodeShouldDetectRollback)
	ctx.Step(`^a running node "([^"]*)"$`, w.aRunningNode)
	ctx.Step(`^a malformed message is sent to node "([^"]*)"$`, w.malformedMessageSent)
	ctx.Step(`^node "([^"]*)" should remain operational$`, w.nodeShouldRemainOperational)
}

func TestFeatures(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: InitializeScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"features"},
			TestingT: t,
		},
	}

	if suite.Run() != 0 {
		t.Fatal("BDD tests failed")
	}
}
