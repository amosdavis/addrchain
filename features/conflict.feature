Feature: Address conflict detection
  As a blockchain network
  I want to detect conflicting address claims
  So that no two nodes can claim the same address

  Scenario: Reject duplicate claim from different node
    Given a new blockchain
    And a node "A" with a generated identity
    And a node "B" with a generated identity
    When node "A" claims address "10.0.0.1"
    And node "B" tries to claim address "10.0.0.1"
    Then node "B" claim should be rejected with a conflict error

  Scenario: Allow claim after release
    Given a new blockchain
    And a node "A" with a generated identity
    And a node "B" with a generated identity
    When node "A" claims address "10.0.0.1"
    And node "A" releases address "10.0.0.1"
    And node "B" claims address "10.0.0.1"
    Then address "10.0.0.1" should be owned by node "B"

  Scenario: Reject release by non-owner
    Given a new blockchain
    And a node "A" with a generated identity
    And a node "B" with a generated identity
    When node "A" claims address "10.0.0.1"
    And node "B" tries to release address "10.0.0.1"
    Then node "B" release should be rejected

  Scenario: Rate limiting enforced
    Given a new blockchain
    And a node "A" with a generated identity
    When node "A" claims 11 addresses rapidly
    Then the 11th claim should be rejected due to rate limiting

  Scenario: Lease expiry frees address
    Given a new blockchain with lease TTL of 5 blocks
    And a node "A" with a generated identity
    When node "A" claims address "10.0.0.1"
    And 6 empty blocks are added
    Then address "10.0.0.1" should not be claimed

  Scenario: Renewal prevents expiry
    Given a new blockchain with lease TTL of 5 blocks
    And a node "A" with a generated identity
    When node "A" claims address "10.0.0.1"
    And 3 empty blocks are added
    And node "A" renews address "10.0.0.1"
    And 3 empty blocks are added
    Then address "10.0.0.1" should be owned by node "A"

  Scenario: Key revocation migrates claims
    Given a new blockchain
    And a node "A" with a generated identity
    When node "A" claims address "10.0.0.1"
    And node "A" revokes its key to a new identity "A2"
    Then address "10.0.0.1" should be owned by node "A2"
