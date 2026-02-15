Feature: Network Partitioning
  As a network administrator
  I want to create logical partitions
  So that traffic isolation is enforced at the blockchain level

  Background:
    Given a fresh addrchain instance
    And a node identity is generated

  Scenario: Create a partition
    When I create partition "secure-zone" with VLAN 100
    Then partition "secure-zone" should exist

  Scenario: Add subnet to partition
    Given partition "dmz" exists with VLAN 200
    And subnet "web-net" exists with prefix "10.70.0.0/24"
    When I add subnet "web-net" to partition "dmz"
    Then subnet "web-net" should be in partition "dmz"

  Scenario: Cross-partition traffic denied by default
    Given partition "zone-a" exists
    And partition "zone-b" exists
    Then cross-partition traffic between "zone-a" and "zone-b" should be denied

  Scenario: Explicitly allow cross-partition traffic
    Given partition "zone-a" exists
    And partition "zone-b" exists
    When I allow cross-partition traffic from "zone-a" to "zone-b"
    Then cross-partition traffic from "zone-a" to "zone-b" should be allowed
