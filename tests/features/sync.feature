Feature: Chain Synchronization
  As a network node
  I want to synchronize my blockchain with peers
  So that I have a consistent view of address assignments

  Background:
    Given a fresh addrchain instance

  Scenario: Sync pulls blocks from taller peer
    Given my chain has height 1
    And a peer has chain height 5
    When I sync with the peer
    Then my chain should have height 5

  Scenario: Sync rejects invalid blocks
    Given a peer sends a block with invalid hash
    When I try to sync
    Then the invalid block should be rejected
    And my chain should remain unchanged

  Scenario: Sync marks failed peer
    Given a peer is unreachable
    When I try to sync with the peer 3 times
    Then the peer should be marked as unreachable

  Scenario: Fork resolution on reconnect
    Given two partitioned networks with different chains
    When the networks reconnect
    Then the longest valid chain should win
    And lost claims should be detected
