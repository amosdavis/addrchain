Feature: State Snapshot
  As a network node operator
  I want to serialize and restore blockchain state via snapshots
  So that I can prune old blocks and recover quickly

  Background:
    Given a fresh addrchain instance

  Scenario: Create and verify a snapshot
    Given I have claimed address "10.0.0.10"
    When I create a snapshot at the current block
    Then the snapshot hash should verify successfully

  Scenario: Restore state from a snapshot
    Given I have claimed addresses "10.0.0.20" and "10.0.0.21"
    When I create a snapshot at the current block
    And I restore the snapshot into a fresh instance
    Then the restored instance should have 2 claims
    And address "10.0.0.20" should be claimed by the original owner

  Scenario: Detect corrupted snapshot
    Given I have claimed address "10.0.0.30"
    When I create a snapshot at the current block
    And a byte in the snapshot payload is flipped
    Then the snapshot hash verification should fail

  Scenario: Reject unknown snapshot version
    When I create a snapshot at the current block
    And the snapshot version field is set to 99
    Then loading the snapshot should fail with a format error

  Scenario: Prune chain and restore via snapshot
    Given I have added 5 blocks with claims
    When I create a snapshot at block 3
    And I prune the chain before block 3
    Then the chain should have 3 remaining blocks
    And restoring the snapshot should recover all 5 claims

  Scenario: Empty snapshot roundtrip
    When I create a snapshot with no state
    Then the snapshot should verify successfully
    And the snapshot size should be 80 bytes
