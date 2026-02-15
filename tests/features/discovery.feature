Feature: Peer Discovery
  As a network node
  I want to discover other addrchain peers automatically
  So that I can synchronize the blockchain without manual configuration

  Background:
    Given a fresh addrchain instance
    And a node identity is generated

  Scenario: Single node creates genesis chain
    When I start addrchain with no peers
    Then the chain should have height 1
    And I should have 0 active peers

  Scenario: Discover peer via announce
    When another node announces with chain height 5
    Then I should have 1 active peer
    And the best peer should have height 5

  Scenario: Prune timed-out peers
    When another node announces
    And the peer timeout expires
    Then the peer should be pruned

  Scenario: Static peer not evicted
    When I add a static peer "10.0.0.100:9877"
    And the peer timeout expires
    Then the static peer should still exist

  Scenario: Self-discovery prevention
    When I receive an announce with my own pubkey
    Then it should be ignored
    And I should have 0 active peers
