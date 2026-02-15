Feature: VPN Tunnel Management
  As a network node
  I want to establish VPN tunnels via blockchain
  So that encrypted connections are automatically configured

  Background:
    Given a fresh addrchain instance
    And node "alice" exists
    And node "bob" exists

  Scenario: Publish VPN key to chain
    When "alice" publishes a WireGuard VPN key
    Then the chain should contain a VPN_KEY transaction for "alice"

  Scenario: Create VPN tunnel between two nodes
    When "alice" publishes a WireGuard VPN key
    And "bob" publishes a WireGuard VPN key
    And "alice" creates a VPN tunnel to "bob"
    Then the VPN tunnel should be in KEYED state

  Scenario: VPN tunnel lifecycle
    When "alice" and "bob" establish a WireGuard tunnel
    And the handshake completes
    Then the tunnel should transition to ACTIVE state

  Scenario: VPN tunnel teardown
    When "alice" and "bob" have an ACTIVE tunnel
    And "alice" closes the tunnel
    Then the tunnel should transition to CLOSED state
