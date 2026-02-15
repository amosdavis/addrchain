Feature: Subnet Management
  As a network administrator
  I want to create and manage subnets via blockchain
  So that address allocation is organized and verifiable

  Background:
    Given a fresh addrchain instance
    And a node identity is generated

  Scenario: Create a subnet with required gateway and DNS
    When I create subnet "lab-net" with prefix "10.42.0.0/24" gateway "10.42.0.1" dns "8.8.8.8"
    Then the subnet "lab-net" should exist
    And the subnet should have gateway "10.42.0.1"

  Scenario: Reject subnet creation without gateway
    When I try to create subnet "bad-net" with prefix "10.43.0.0/24" without gateway
    Then the creation should fail

  Scenario: Allow explicit no-gateway opt-out
    When I create subnet "isolated-net" with prefix "10.44.0.0/24" with no-gateway flag
    Then the subnet "isolated-net" should exist

  Scenario: Reject overlapping subnets
    When I create subnet "net-a" with prefix "10.50.0.0/24" gateway "10.50.0.1" dns "8.8.8.8"
    And I try to create subnet "net-b" with prefix "10.50.0.0/25" gateway "10.50.0.1" dns "8.8.8.8"
    Then the second subnet creation should fail with overlap error

  Scenario: Claim address within subnet
    When I create subnet "office-net" with prefix "10.60.0.0/24" gateway "10.60.0.1" dns "8.8.8.8"
    And I assign my node to subnet "office-net"
    And I claim address "10.60.0.5" in subnet "office-net"
    Then address "10.60.0.5" should be claimed by my node
