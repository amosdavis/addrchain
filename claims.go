package addrchain

import (
	"fmt"
	"sync"
)

// DefaultLeaseTTLBlocks is the number of blocks after which an unrewened claim expires.
const DefaultLeaseTTLBlocks uint64 = 100

// ClaimRecord tracks the owner and the block at which the claim was last renewed.
type ClaimRecord struct {
	NodeID       string
	LastRenewed  uint64 // Block index of the last CLAIM or RENEW for this address.
	OriginalSeq  uint64
}

// ClaimStore maintains the address→owner mapping derived from the chain.
type ClaimStore struct {
	mu       sync.RWMutex
	claims   map[string]ClaimRecord // address → record
	revoked  map[string]string      // old NodeID → new NodeID
	leaseTTL uint64
}

// NewClaimStore creates a new empty claim store.
func NewClaimStore(leaseTTL uint64) *ClaimStore {
	if leaseTTL == 0 {
		leaseTTL = DefaultLeaseTTLBlocks
	}
	return &ClaimStore{
		claims:   make(map[string]ClaimRecord),
		revoked:  make(map[string]string),
		leaseTTL: leaseTTL,
	}
}

// RebuildFromChain rebuilds the entire claim state by replaying every block.
// Returns a list of addresses that were previously claimed by localNodeID but
// are no longer valid (rolled back), so the caller can attempt re-claim.
func (cs *ClaimStore) RebuildFromChain(blocks []Block, localNodeID string) []string {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	oldClaims := cs.claims
	cs.claims = make(map[string]ClaimRecord)
	cs.revoked = make(map[string]string)

	tipIndex := uint64(0)
	if len(blocks) > 0 {
		tipIndex = blocks[len(blocks)-1].Index
	}

	for _, b := range blocks {
		for _, tx := range b.Transactions {
			cs.applyTx(tx, b.Index)
		}
	}

	// Expire stale leases.
	cs.expireLeases(tipIndex)

	// Detect rollback losses for the local node.
	var lostAddresses []string
	for addr, old := range oldClaims {
		if old.NodeID != localNodeID {
			continue
		}
		current, exists := cs.claims[addr]
		if !exists || current.NodeID != localNodeID {
			lostAddresses = append(lostAddresses, addr)
		}
	}
	return lostAddresses
}

// applyTx applies a single transaction to the claim state (caller must hold the lock).
func (cs *ClaimStore) applyTx(tx Transaction, blockIndex uint64) {
	switch tx.Type {
	case TxClaim:
		if _, taken := cs.claims[tx.Address]; !taken {
			cs.claims[tx.Address] = ClaimRecord{
				NodeID:      cs.resolveNodeID(tx.NodeID),
				LastRenewed: blockIndex,
				OriginalSeq: tx.Seq,
			}
		}
	case TxRelease:
		if rec, exists := cs.claims[tx.Address]; exists {
			if cs.resolveNodeID(tx.NodeID) == rec.NodeID {
				delete(cs.claims, tx.Address)
			}
		}
	case TxRenew:
		if rec, exists := cs.claims[tx.Address]; exists {
			if cs.resolveNodeID(tx.NodeID) == rec.NodeID {
				rec.LastRenewed = blockIndex
				cs.claims[tx.Address] = rec
			}
		}
	case TxRevoke:
		cs.revoked[tx.NodeID] = tx.NewNodeID
		// Migrate all claims from old identity to new identity.
		for addr, rec := range cs.claims {
			if rec.NodeID == tx.NodeID {
				rec.NodeID = tx.NewNodeID
				cs.claims[addr] = rec
			}
		}
	}
}

// resolveNodeID follows the revocation chain to find the current identity.
func (cs *ClaimStore) resolveNodeID(nodeID string) string {
	visited := make(map[string]bool)
	current := nodeID
	for {
		next, ok := cs.revoked[current]
		if !ok || visited[current] {
			return current
		}
		visited[current] = true
		current = next
	}
}

// expireLeases removes claims that have not been renewed within leaseTTL blocks.
func (cs *ClaimStore) expireLeases(tipIndex uint64) {
	for addr, rec := range cs.claims {
		if tipIndex > rec.LastRenewed+cs.leaseTTL {
			delete(cs.claims, addr)
		}
	}
}

// ValidateNewBlock checks whether the transactions in a candidate block conflict
// with existing claims. This is called before adding the block.
func (cs *ClaimStore) ValidateNewBlock(b Block) error {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	// Work on a temporary copy so we can validate intra-block ordering.
	tmpClaims := make(map[string]ClaimRecord, len(cs.claims))
	for k, v := range cs.claims {
		tmpClaims[k] = v
	}
	tmpRevoked := make(map[string]string, len(cs.revoked))
	for k, v := range cs.revoked {
		tmpRevoked[k] = v
	}

	resolveTmp := func(nid string) string {
		visited := make(map[string]bool)
		c := nid
		for {
			next, ok := tmpRevoked[c]
			if !ok || visited[c] {
				return c
			}
			visited[c] = true
			c = next
		}
	}

	for i, tx := range b.Transactions {
		resolved := resolveTmp(tx.NodeID)
		switch tx.Type {
		case TxClaim:
			if existing, taken := tmpClaims[tx.Address]; taken {
				return fmt.Errorf("tx %d: address %s already claimed by %s", i, tx.Address, existing.NodeID[:16])
			}
			tmpClaims[tx.Address] = ClaimRecord{NodeID: resolved, LastRenewed: b.Index, OriginalSeq: tx.Seq}
		case TxRelease:
			rec, exists := tmpClaims[tx.Address]
			if !exists {
				return fmt.Errorf("tx %d: address %s not claimed", i, tx.Address)
			}
			if rec.NodeID != resolved {
				return fmt.Errorf("tx %d: address %s owned by different node", i, tx.Address)
			}
			delete(tmpClaims, tx.Address)
		case TxRenew:
			rec, exists := tmpClaims[tx.Address]
			if !exists {
				return fmt.Errorf("tx %d: cannot renew unclaimed address %s", i, tx.Address)
			}
			if rec.NodeID != resolved {
				return fmt.Errorf("tx %d: address %s owned by different node", i, tx.Address)
			}
		case TxRevoke:
			tmpRevoked[tx.NodeID] = tx.NewNodeID
			for addr, rec := range tmpClaims {
				if rec.NodeID == tx.NodeID {
					rec.NodeID = tx.NewNodeID
					tmpClaims[addr] = rec
				}
			}
		}
	}
	return nil
}

// ApplyBlock updates the claim state with a validated block.
func (cs *ClaimStore) ApplyBlock(b Block) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	for _, tx := range b.Transactions {
		cs.applyTx(tx, b.Index)
	}
	cs.expireLeases(b.Index)
}

// GetOwner returns the owning NodeID for an address, or "" if unclaimed.
func (cs *ClaimStore) GetOwner(address string) string {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	if rec, ok := cs.claims[address]; ok {
		return rec.NodeID
	}
	return ""
}

// GetAllClaims returns a copy of all current claims.
func (cs *ClaimStore) GetAllClaims() map[string]ClaimRecord {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	cp := make(map[string]ClaimRecord, len(cs.claims))
	for k, v := range cs.claims {
		cp[k] = v
	}
	return cp
}

// GetClaimsByNode returns all addresses claimed by a given NodeID.
func (cs *ClaimStore) GetClaimsByNode(nodeID string) []string {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	var addrs []string
	resolved := cs.resolveNodeID(nodeID)
	for addr, rec := range cs.claims {
		if rec.NodeID == resolved {
			addrs = append(addrs, addr)
		}
	}
	return addrs
}

// PruneExpiredBlocks returns a compacted chain: blocks whose transactions are all
// fully resolved (released or expired) are removed, and a checkpoint block
// summarizing the current state is inserted after genesis.
func PruneExpiredBlocks(blocks []Block, leaseTTL uint64) []Block {
	if len(blocks) <= 2 {
		return blocks
	}

	cs := NewClaimStore(leaseTTL)
	tipIndex := blocks[len(blocks)-1].Index
	for _, b := range blocks {
		for _, tx := range b.Transactions {
			cs.applyTx(tx, b.Index)
		}
	}
	cs.expireLeases(tipIndex)

	// Find the earliest block index still referenced by a live claim.
	earliestLive := tipIndex
	for _, rec := range cs.claims {
		if rec.LastRenewed < earliestLive {
			earliestLive = rec.LastRenewed
		}
	}

	// Keep genesis + all blocks from earliestLive onward.
	var pruned []Block
	pruned = append(pruned, blocks[0]) // genesis
	for _, b := range blocks[1:] {
		if b.Index >= earliestLive {
			pruned = append(pruned, b)
		}
	}

	return pruned
}
