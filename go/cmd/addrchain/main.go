package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"addrchain"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		cmdServe()
	case "claim":
		cmdClaim()
	case "release":
		cmdRelease()
	case "revoke":
		cmdRevoke()
	case "list":
		cmdList()
	case "status":
		cmdStatus()
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`addrchain - Minimal blockchain for self-assignable network addresses

Usage:
  addrchain serve  [--port PORT] [--udp-port PORT] [--peer ADDR]...  Start the node
  addrchain claim  <address>  [--port PORT]                          Claim a network address
  addrchain release <address> [--port PORT]                          Release a claimed address
  addrchain revoke            [--port PORT]                          Revoke key and migrate claims
  addrchain list              [--port PORT]                          List all claimed addresses
  addrchain status            [--port PORT]                          Show node status
  addrchain help                                                     Show this help

Options:
  --port PORT       TCP port for the node (default: 9877)
  --udp-port PORT   UDP port for peer discovery (default: 9876)
  --peer ADDR       Manual peer address (host:port), can be repeated`)
}

func parseFlag(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func parseFlagAll(args []string, flag string) []string {
	var vals []string
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			vals = append(vals, args[i+1])
		}
	}
	return vals
}

func parseTCPPort(args []string) int {
	if s := parseFlag(args, "--port"); s != "" {
		p, err := strconv.Atoi(s)
		if err != nil {
			log.Fatalf("invalid --port: %s", s)
		}
		return p
	}
	return addrchain.DefaultTCPPort
}

func cmdServe() {
	args := os.Args[2:]
	tcpPort := parseTCPPort(args)
	udpPort := addrchain.DefaultUDPPort
	if s := parseFlag(args, "--udp-port"); s != "" {
		p, err := strconv.Atoi(s)
		if err != nil {
			log.Fatalf("invalid --udp-port: %s", s)
		}
		udpPort = p
	}
	manualPeers := parseFlagAll(args, "--peer")

	identity, err := addrchain.LoadOrCreateIdentity("")
	if err != nil {
		log.Fatalf("identity: %v", err)
	}

	chain := addrchain.NewChain()
	claims := addrchain.NewClaimStore(addrchain.DefaultLeaseTTLBlocks)

	node := addrchain.NewNode(identity.NodeID(), chain, claims, tcpPort, udpPort, manualPeers)

	// Auto re-claim on rollback.
	var seq atomic.Uint64
	seq.Store(1)
	node.SetRollbackCallback(func(lost []string) {
		for _, addr := range lost {
			tx := addrchain.Transaction{
				Type:      addrchain.TxClaim,
				NodeID:    identity.NodeID(),
				Address:   addr,
				Timestamp: time.Now().Unix(),
				Seq:       seq.Add(1),
			}
			tx.Sign(identity.PrivateKey)
			b := addrchain.NewBlock(chain.LastBlock(), []addrchain.Transaction{tx})
			if err := claims.ValidateNewBlock(b); err != nil {
				log.Printf("re-claim %s failed (conflict): %v", addr, err)
				continue
			}
			if err := chain.AddBlock(b); err != nil {
				log.Printf("re-claim %s failed: %v", addr, err)
				continue
			}
			claims.ApplyBlock(b)
			node.BroadcastBlock(b)
			log.Printf("re-claimed %s after rollback", addr)
		}
	})

	if err := node.Start(); err != nil {
		log.Fatalf("start: %v", err)
	}

	fmt.Printf("addrchain node started\n")
	fmt.Printf("  NodeID:   %s\n", identity.NodeID()[:16]+"...")
	fmt.Printf("  TCP:      %s\n", node.TCPAddr)
	fmt.Printf("  UDP:      %d\n", udpPort)
	if len(manualPeers) > 0 {
		fmt.Printf("  Peers:    %s\n", strings.Join(manualPeers, ", "))
	}

	// Run renewal loop in background.
	go renewalLoop(identity, chain, claims, node, &seq)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("\nshutting down...")
	node.Stop()
}

// renewalLoop periodically renews all claims owned by this node.
func renewalLoop(id *addrchain.Identity, chain *addrchain.Chain, claims *addrchain.ClaimStore, node *addrchain.Node, seq *atomic.Uint64) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		addrs := claims.GetClaimsByNode(id.NodeID())
		for _, addr := range addrs {
			tx := addrchain.Transaction{
				Type:      addrchain.TxRenew,
				NodeID:    id.NodeID(),
				Address:   addr,
				Timestamp: time.Now().Unix(),
				Seq:       seq.Add(1),
			}
			tx.Sign(id.PrivateKey)
			b := addrchain.NewBlock(chain.LastBlock(), []addrchain.Transaction{tx})
			if err := claims.ValidateNewBlock(b); err != nil {
				continue
			}
			if err := chain.AddBlock(b); err != nil {
				continue
			}
			claims.ApplyBlock(b)
			node.BroadcastBlock(b)
		}
	}
}

func cmdClaim() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: addrchain claim <address>")
		os.Exit(1)
	}
	address := os.Args[2]
	args := os.Args[3:]
	tcpPort := parseTCPPort(args)

	identity, err := addrchain.LoadOrCreateIdentity("")
	if err != nil {
		log.Fatalf("identity: %v", err)
	}

	chain := addrchain.NewChain()
	claims := addrchain.NewClaimStore(addrchain.DefaultLeaseTTLBlocks)

	// Sync from the running node.
	node := addrchain.NewNode(identity.NodeID(), chain, claims, 0, 0, []string{fmt.Sprintf("127.0.0.1:%d", tcpPort)})
	syncFromLocalNode(node, chain, claims, identity.NodeID())

	// Find next sequence number.
	seq := findNextSeq(chain, identity.NodeID())

	tx := addrchain.Transaction{
		Type:      addrchain.TxClaim,
		NodeID:    identity.NodeID(),
		Address:   address,
		Timestamp: time.Now().Unix(),
		Seq:       seq,
	}
	tx.Sign(identity.PrivateKey)

	b := addrchain.NewBlock(chain.LastBlock(), []addrchain.Transaction{tx})
	if err := claims.ValidateNewBlock(b); err != nil {
		log.Fatalf("claim rejected: %v", err)
	}

	// Send the block to the running node.
	node.BroadcastBlock(b)
	fmt.Printf("claimed %s\n", address)
}

func cmdRelease() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: addrchain release <address>")
		os.Exit(1)
	}
	address := os.Args[2]
	args := os.Args[3:]
	tcpPort := parseTCPPort(args)

	identity, err := addrchain.LoadOrCreateIdentity("")
	if err != nil {
		log.Fatalf("identity: %v", err)
	}

	chain := addrchain.NewChain()
	claims := addrchain.NewClaimStore(addrchain.DefaultLeaseTTLBlocks)

	node := addrchain.NewNode(identity.NodeID(), chain, claims, 0, 0, []string{fmt.Sprintf("127.0.0.1:%d", tcpPort)})
	syncFromLocalNode(node, chain, claims, identity.NodeID())

	seq := findNextSeq(chain, identity.NodeID())

	tx := addrchain.Transaction{
		Type:      addrchain.TxRelease,
		NodeID:    identity.NodeID(),
		Address:   address,
		Timestamp: time.Now().Unix(),
		Seq:       seq,
	}
	tx.Sign(identity.PrivateKey)

	b := addrchain.NewBlock(chain.LastBlock(), []addrchain.Transaction{tx})
	if err := claims.ValidateNewBlock(b); err != nil {
		log.Fatalf("release rejected: %v", err)
	}

	node.BroadcastBlock(b)
	fmt.Printf("released %s\n", address)
}

func cmdRevoke() {
	args := os.Args[2:]
	tcpPort := parseTCPPort(args)

	oldID, newID, err := addrchain.RotateIdentity("")
	if err != nil {
		log.Fatalf("rotate identity: %v", err)
	}

	chain := addrchain.NewChain()
	claims := addrchain.NewClaimStore(addrchain.DefaultLeaseTTLBlocks)

	node := addrchain.NewNode(oldID.NodeID(), chain, claims, 0, 0, []string{fmt.Sprintf("127.0.0.1:%d", tcpPort)})
	syncFromLocalNode(node, chain, claims, oldID.NodeID())

	seq := findNextSeq(chain, oldID.NodeID())

	tx := addrchain.Transaction{
		Type:      addrchain.TxRevoke,
		NodeID:    oldID.NodeID(),
		NewNodeID: newID.NodeID(),
		Timestamp: time.Now().Unix(),
		Seq:       seq,
	}
	tx.Sign(oldID.PrivateKey)

	b := addrchain.NewBlock(chain.LastBlock(), []addrchain.Transaction{tx})
	node.BroadcastBlock(b)

	fmt.Printf("revoked old key, migrated claims to new identity\n")
	fmt.Printf("  Old: %s...\n", oldID.NodeID()[:16])
	fmt.Printf("  New: %s...\n", newID.NodeID()[:16])
}

func cmdList() {
	args := os.Args[2:]
	tcpPort := parseTCPPort(args)

	identity, err := addrchain.LoadOrCreateIdentity("")
	if err != nil {
		log.Fatalf("identity: %v", err)
	}

	chain := addrchain.NewChain()
	claims := addrchain.NewClaimStore(addrchain.DefaultLeaseTTLBlocks)

	node := addrchain.NewNode(identity.NodeID(), chain, claims, 0, 0, []string{fmt.Sprintf("127.0.0.1:%d", tcpPort)})
	syncFromLocalNode(node, chain, claims, identity.NodeID())

	allClaims := claims.GetAllClaims()
	if len(allClaims) == 0 {
		fmt.Println("no addresses claimed")
		return
	}

	fmt.Printf("%-20s  %-20s\n", "ADDRESS", "OWNER")
	fmt.Printf("%-20s  %-20s\n", strings.Repeat("-", 20), strings.Repeat("-", 20))
	for addr, rec := range allClaims {
		owner := rec.NodeID[:16] + "..."
		if rec.NodeID == identity.NodeID() {
			owner += " (you)"
		}
		fmt.Printf("%-20s  %s\n", addr, owner)
	}
}

func cmdStatus() {
	args := os.Args[2:]
	tcpPort := parseTCPPort(args)

	identity, err := addrchain.LoadOrCreateIdentity("")
	if err != nil {
		log.Fatalf("identity: %v", err)
	}

	chain := addrchain.NewChain()
	claims := addrchain.NewClaimStore(addrchain.DefaultLeaseTTLBlocks)

	node := addrchain.NewNode(identity.NodeID(), chain, claims, 0, 0, []string{fmt.Sprintf("127.0.0.1:%d", tcpPort)})
	syncFromLocalNode(node, chain, claims, identity.NodeID())

	myAddrs := claims.GetClaimsByNode(identity.NodeID())

	status := map[string]interface{}{
		"node_id":      identity.NodeID()[:16] + "...",
		"chain_length": chain.Len(),
		"total_claims": len(claims.GetAllClaims()),
		"my_claims":    myAddrs,
	}

	out, _ := json.MarshalIndent(status, "", "  ")
	fmt.Println(string(out))
}

// syncFromLocalNode syncs the chain from the local running node.
func syncFromLocalNode(node *addrchain.Node, chain *addrchain.Chain, claims *addrchain.ClaimStore, nodeID string) {
	if err := node.Start(); err != nil {
		// If can't connect, proceed with genesis-only chain.
		return
	}
	defer node.Stop()
	time.Sleep(2 * time.Second)
	claims.RebuildFromChain(chain.GetBlocks(), nodeID)
}

// findNextSeq scans the chain for the highest sequence number used by a nodeID.
func findNextSeq(chain *addrchain.Chain, nodeID string) uint64 {
	var maxSeq uint64
	for _, b := range chain.GetBlocks() {
		for _, tx := range b.Transactions {
			if tx.NodeID == nodeID && tx.Seq > maxSeq {
				maxSeq = tx.Seq
			}
		}
	}
	return maxSeq + 1
}
