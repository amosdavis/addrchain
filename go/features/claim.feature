Feature: Claiming network addresses
  As a node on the network
  I want to claim a network address on the blockchain
  So that I can self-assign an address without DHCP

  Scenario: Claim a new address
    Given a new blockchain
    And a node with a generated identity
    When the node claims address "192.168.1.100"
    Then the claim should succeed
    And address "192.168.1.100" should be owned by the node

  Scenario: Claim multiple addresses
    Given a new blockchain
    And a node with a generated identity
    When the node claims address "10.0.0.1"
    And the node claims address "10.0.0.2"
    Then address "10.0.0.1" should be owned by the node
    And address "10.0.0.2" should be owned by the node

  Scenario: Release a claimed address
    Given a new blockchain
    And a node with a generated identity
    When the node claims address "10.0.0.1"
    And the node releases address "10.0.0.1"
    Then address "10.0.0.1" should not be claimed
