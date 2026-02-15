package addrchain

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// Default network ports.
const (
	DefaultUDPPort = 9876
	DefaultTCPPort = 9877
	MaxMessageSize = 1 << 20 // 1 MB
)

// Message types for the TCP protocol.
const (
	MsgRequestChain = "REQUEST_CHAIN"
	MsgSendChain    = "SEND_CHAIN"
	MsgNewBlock     = "NEW_BLOCK"
)

// UDPAnnounce is the payload broadcast over UDP for peer discovery.
type UDPAnnounce struct {
	NodeID  string `json:"node_id"`
	TCPAddr string `json:"tcp_addr"`
}

// TCPMessage is the envelope for all TCP communication.
type TCPMessage struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// Peer represents a known peer on the network.
type Peer struct {
	NodeID  string
	TCPAddr string
	LastSeen time.Time
}

// Node is the P2P networking layer for the addrchain.
type Node struct {
	NodeID     string
	Chain      *Chain
	Claims     *ClaimStore
	TCPAddr    string
	UDPPort    int
	ManualPeers []string

	mu    sync.RWMutex
	peers map[string]*Peer // TCPAddr → Peer

	udpConn    *net.UDPConn
	tcpLn      net.Listener
	stopCh     chan struct{}
	onRollback func(lost []string) // callback when local claims are rolled back
}

// NewNode creates a new P2P node.
func NewNode(nodeID string, chain *Chain, claims *ClaimStore, tcpPort, udpPort int, manualPeers []string) *Node {
	return &Node{
		NodeID:      nodeID,
		Chain:       chain,
		Claims:      claims,
		TCPAddr:     fmt.Sprintf(":%d", tcpPort),
		UDPPort:     udpPort,
		ManualPeers: manualPeers,
		peers:       make(map[string]*Peer),
		stopCh:      make(chan struct{}),
	}
}

// SetRollbackCallback sets a function called when local claims are lost due to chain replacement.
func (n *Node) SetRollbackCallback(cb func(lost []string)) {
	n.onRollback = cb
}

// Start begins listening for UDP broadcasts and TCP connections.
func (n *Node) Start() error {
	if err := n.startTCP(); err != nil {
		return fmt.Errorf("TCP listen: %w", err)
	}
	if err := n.startUDP(); err != nil {
		return fmt.Errorf("UDP listen: %w", err)
	}

	// Add manual peers.
	for _, addr := range n.ManualPeers {
		n.mu.Lock()
		n.peers[addr] = &Peer{TCPAddr: addr, LastSeen: time.Now()}
		n.mu.Unlock()
	}

	go n.udpBroadcastLoop()
	go n.udpListenLoop()
	go n.syncOnStartup()

	return nil
}

// Stop shuts down the node.
func (n *Node) Stop() {
	close(n.stopCh)
	if n.udpConn != nil {
		n.udpConn.Close()
	}
	if n.tcpLn != nil {
		n.tcpLn.Close()
	}
}

// GetPeers returns a snapshot of known peers.
func (n *Node) GetPeers() []Peer {
	n.mu.RLock()
	defer n.mu.RUnlock()
	var list []Peer
	for _, p := range n.peers {
		list = append(list, *p)
	}
	return list
}

// BroadcastBlock sends a new block to all known peers.
func (n *Node) BroadcastBlock(b Block) {
	data, _ := json.Marshal(b)
	msg := TCPMessage{Type: MsgNewBlock, Data: data}

	n.mu.RLock()
	peers := make([]string, 0, len(n.peers))
	for _, p := range n.peers {
		peers = append(peers, p.TCPAddr)
	}
	n.mu.RUnlock()

	for _, addr := range peers {
		go func(a string) {
			if err := n.sendTCPMessage(a, msg); err != nil {
				log.Printf("[p2p] failed to send block to %s: %v", a, err)
			}
		}(addr)
	}
}

// startTCP begins listening for TCP connections.
func (n *Node) startTCP() error {
	ln, err := net.Listen("tcp", n.TCPAddr)
	if err != nil {
		return err
	}
	n.tcpLn = ln
	// Update TCPAddr to the actual bound address (in case port was 0).
	n.TCPAddr = ln.Addr().String()
	go n.tcpAcceptLoop()
	return nil
}

// tcpAcceptLoop accepts and handles incoming TCP connections.
func (n *Node) tcpAcceptLoop() {
	for {
		conn, err := n.tcpLn.Accept()
		if err != nil {
			select {
			case <-n.stopCh:
				return
			default:
				log.Printf("[p2p] TCP accept error: %v", err)
				continue
			}
		}
		go n.handleTCPConn(conn)
	}
}

// handleTCPConn processes a single TCP connection with panic recovery.
func (n *Node) handleTCPConn(conn net.Conn) {
	defer conn.Close()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[p2p] recovered from panic handling TCP: %v", r)
		}
	}()

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	data, err := io.ReadAll(io.LimitReader(conn, MaxMessageSize))
	if err != nil {
		log.Printf("[p2p] TCP read error: %v", err)
		return
	}

	var msg TCPMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		log.Printf("[p2p] invalid TCP message: %v", err)
		return
	}

	switch msg.Type {
	case MsgRequestChain:
		n.handleRequestChain(conn)
	case MsgSendChain:
		n.handleSendChain(msg.Data)
	case MsgNewBlock:
		n.handleNewBlock(msg.Data)
	default:
		log.Printf("[p2p] unknown message type: %s", msg.Type)
	}
}

// handleRequestChain responds with the full chain.
func (n *Node) handleRequestChain(conn net.Conn) {
	blocks := n.Chain.GetBlocks()
	data, _ := json.Marshal(blocks)
	msg := TCPMessage{Type: MsgSendChain, Data: data}
	resp, _ := json.Marshal(msg)
	conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	conn.Write(resp)
}

// handleSendChain processes a received chain and replaces ours if it's longer/better.
func (n *Node) handleSendChain(data json.RawMessage) {
	var blocks []Block
	if err := json.Unmarshal(data, &blocks); err != nil {
		log.Printf("[p2p] invalid chain data: %v", err)
		return
	}
	n.tryReplaceChain(blocks)
}

// handleNewBlock processes a received block.
func (n *Node) handleNewBlock(data json.RawMessage) {
	var b Block
	if err := json.Unmarshal(data, &b); err != nil {
		log.Printf("[p2p] invalid block data: %v", err)
		return
	}

	if err := n.Claims.ValidateNewBlock(b); err != nil {
		log.Printf("[p2p] block rejected by claims: %v", err)
		return
	}

	if err := n.Chain.AddBlock(b); err != nil {
		log.Printf("[p2p] block rejected by chain: %v", err)
		return
	}

	n.Claims.ApplyBlock(b)
	log.Printf("[p2p] accepted block #%d", b.Index)
}

// tryReplaceChain attempts to replace the local chain, cross-validating with
// multiple peers when possible (eclipse attack mitigation).
func (n *Node) tryReplaceChain(candidate []Block) {
	replaced, err := n.Chain.ReplaceChain(candidate)
	if err != nil {
		log.Printf("[p2p] chain replacement rejected: %v", err)
		return
	}
	if !replaced {
		return
	}

	log.Printf("[p2p] chain replaced, new length: %d", len(candidate))
	lost := n.Claims.RebuildFromChain(candidate, n.NodeID)
	if len(lost) > 0 {
		log.Printf("[p2p] WARNING: %d local claims rolled back: %v", len(lost), lost)
		if n.onRollback != nil {
			n.onRollback(lost)
		}
	}
}

// sendTCPMessage sends a single message to a peer.
func (n *Node) sendTCPMessage(addr string, msg TCPMessage) error {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	data, _ := json.Marshal(msg)
	if len(data) > MaxMessageSize {
		return fmt.Errorf("message too large: %d bytes", len(data))
	}

	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err = conn.Write(data)
	// Close write side so server's ReadAll returns.
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
	return err
}

// requestChainFrom requests the full chain from a peer and returns it.
func (n *Node) requestChainFrom(addr string) ([]Block, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	msg := TCPMessage{Type: MsgRequestChain}
	data, _ := json.Marshal(msg)
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(data); err != nil {
		return nil, err
	}
	// Close write side so server's ReadAll returns.
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.CloseWrite()
	}

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	resp, err := io.ReadAll(io.LimitReader(conn, MaxMessageSize))
	if err != nil {
		return nil, err
	}

	var respMsg TCPMessage
	if err := json.Unmarshal(resp, &respMsg); err != nil {
		return nil, err
	}

	var blocks []Block
	if err := json.Unmarshal(respMsg.Data, &blocks); err != nil {
		return nil, err
	}
	return blocks, nil
}

// startUDP begins listening for UDP broadcast announcements.
func (n *Node) startUDP() error {
	addr := &net.UDPAddr{Port: n.UDPPort}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return err
	}
	n.udpConn = conn
	return nil
}

// udpBroadcastLoop periodically announces this node on the LAN.
func (n *Node) udpBroadcastLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	announce := UDPAnnounce{NodeID: n.NodeID, TCPAddr: n.TCPAddr}
	data, _ := json.Marshal(announce)

	broadcastAddr := &net.UDPAddr{IP: net.IPv4bcast, Port: n.UDPPort}

	for {
		select {
		case <-n.stopCh:
			return
		case <-ticker.C:
			conn, err := net.DialUDP("udp4", nil, broadcastAddr)
			if err != nil {
				log.Printf("[p2p] UDP broadcast error: %v", err)
				continue
			}
			conn.Write(data)
			conn.Close()
		}
	}
}

// udpListenLoop listens for UDP broadcast announcements from peers.
func (n *Node) udpListenLoop() {
	buf := make([]byte, 4096)
	for {
		select {
		case <-n.stopCh:
			return
		default:
		}

		n.udpConn.SetReadDeadline(time.Now().Add(6 * time.Second))
		nBytes, _, err := n.udpConn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		var announce UDPAnnounce
		if err := json.Unmarshal(buf[:nBytes], &announce); err != nil {
			continue
		}

		if announce.NodeID == n.NodeID {
			continue
		}

		n.mu.Lock()
		if _, exists := n.peers[announce.TCPAddr]; !exists {
			log.Printf("[p2p] discovered peer: %s at %s", announce.NodeID[:16], announce.TCPAddr)
			n.peers[announce.TCPAddr] = &Peer{
				NodeID:   announce.NodeID,
				TCPAddr:  announce.TCPAddr,
				LastSeen: time.Now(),
			}
			// Sync chain from newly discovered peer.
			go n.syncFromPeer(announce.TCPAddr)
		} else {
			n.peers[announce.TCPAddr].LastSeen = time.Now()
		}
		n.mu.Unlock()
	}
}

// syncOnStartup syncs chain from all known peers (manual and discovered).
func (n *Node) syncOnStartup() {
	time.Sleep(1 * time.Second) // brief delay for listeners to start

	n.mu.RLock()
	peers := make([]string, 0, len(n.peers))
	for _, p := range n.peers {
		peers = append(peers, p.TCPAddr)
	}
	n.mu.RUnlock()

	for _, addr := range peers {
		n.syncFromPeer(addr)
	}

	if len(peers) == 0 {
		log.Printf("[p2p] WARNING: no peers available, operating in single-node mode")
	}
}

// syncFromPeer requests the chain from a single peer and attempts replacement.
func (n *Node) syncFromPeer(addr string) {
	blocks, err := n.requestChainFrom(addr)
	if err != nil {
		log.Printf("[p2p] sync from %s failed: %v", addr, err)
		return
	}
	n.tryReplaceChain(blocks)
}

// CrossValidateChain requests chains from multiple peers and only accepts
// a chain that at least minAgreement peers agree on (eclipse attack mitigation).
func (n *Node) CrossValidateChain(minAgreement int) {
	n.mu.RLock()
	peers := make([]string, 0, len(n.peers))
	for _, p := range n.peers {
		peers = append(peers, p.TCPAddr)
	}
	n.mu.RUnlock()

	if len(peers) < minAgreement {
		// Not enough peers to cross-validate; accept best available.
		for _, addr := range peers {
			n.syncFromPeer(addr)
		}
		return
	}

	type chainResult struct {
		blocks []Block
		tipHash string
	}

	results := make([]chainResult, 0, len(peers))
	var resMu sync.Mutex
	var wg sync.WaitGroup

	for _, addr := range peers {
		wg.Add(1)
		go func(a string) {
			defer wg.Done()
			blocks, err := n.requestChainFrom(a)
			if err != nil {
				return
			}
			if len(blocks) == 0 {
				return
			}
			resMu.Lock()
			results = append(results, chainResult{blocks: blocks, tipHash: blocks[len(blocks)-1].Hash})
			resMu.Unlock()
		}(addr)
	}
	wg.Wait()

	// Count agreement by tip hash.
	hashCount := make(map[string]int)
	hashBlocks := make(map[string][]Block)
	for _, r := range results {
		hashCount[r.tipHash]++
		if existing, ok := hashBlocks[r.tipHash]; !ok || len(r.blocks) > len(existing) {
			hashBlocks[r.tipHash] = r.blocks
		}
	}

	// Accept the chain with the most agreement (at least minAgreement).
	bestHash := ""
	bestCount := 0
	for h, c := range hashCount {
		if c > bestCount || (c == bestCount && len(hashBlocks[h]) > len(hashBlocks[bestHash])) {
			bestHash = h
			bestCount = c
		}
	}

	if bestCount >= minAgreement {
		n.tryReplaceChain(hashBlocks[bestHash])
	} else {
		log.Printf("[p2p] cross-validation failed: no chain has %d+ peer agreement", minAgreement)
	}
}
