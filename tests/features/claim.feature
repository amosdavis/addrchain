Feature: Address Claiming
  As a network node
  I want to claim IP addresses via blockchain
  So that I have guaranteed address ownership without DHCP

  Background:
    Given a fresh addrchain instance
    And a node identity is generated

  Scenario: Claim an IPv4 address
    When I claim address "10.0.0.1"
    Then the chain height should be 2
    And address "10.0.0.1" should be claimed by my node

  Scenario: Claim and release an address
    When I claim address "10.0.0.2"
    And I release address "10.0.0.2"
    Then the chain height should be 3
    And address "10.0.0.2" should be unclaimed

  Scenario: Cannot claim an already-claimed address
    When I claim address "10.0.0.3"
    And another node claims address "10.0.0.3"
    Then the second claim should fail with conflict

  Scenario: Claim multiple addresses
    When I claim address "10.0.0.10"
    And I claim address "10.0.0.11"
    And I claim address "10.0.0.12"
    Then I should own 3 addresses
