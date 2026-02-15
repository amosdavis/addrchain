Feature: Chain synchronization
  As a node joining the network
  I want to synchronize with existing peers
  So that I have an up-to-date view of address claims

  Scenario: Sync chain from peer
    Given node "A" with a blockchain of length 3
    And a new node "B" with node "A" as a peer
    When node "B" syncs from peers
    Then node "B" chain should have length 3

  Scenario: Longest chain wins
    Given node "A" with a blockchain of length 3
    And a node "B" with a generated identity
    When node "A" receives a chain of length 5 from node "B"
    Then node "A" chain should have length 5

  Scenario: Reject invalid chain
    Given node "A" with a blockchain of length 2
    When node "A" receives a chain with a broken hash
    Then the chain should be rejected
    And node "A" chain should have length 2

  Scenario: Rollback detection
    Given node "A" with a claimed address "10.0.0.1"
    When node "A" receives a longer chain without the claim
    Then node "A" should detect the rollback of "10.0.0.1"

  Scenario: Malformed message resilience
    Given a running node "A"
    When a malformed message is sent to node "A"
    Then node "A" should remain operational
