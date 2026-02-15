Feature: Address Conflict Resolution
  As a blockchain network
  I want deterministic conflict resolution
  So that two simultaneous claims resolve without ambiguity

  Background:
    Given a fresh addrchain instance

  Scenario: First-come-first-served on same chain
    Given node "alice" exists
    And node "bob" exists
    When "alice" claims "10.0.0.1"
    And "bob" tries to claim "10.0.0.1"
    Then "bob" claim should be rejected
    And "alice" should own "10.0.0.1"

  Scenario: Longer chain wins on fork
    Given node "alice" has a chain of height 5
    And node "bob" has a chain of height 3
    When chains are merged
    Then the resulting chain height should be 5
    And all claims from the longer chain should be preserved

  Scenario: Deterministic tiebreak on equal height
    Given two chains of equal height with different tips
    When chains are compared
    Then the chain with the lower tip hash should win
