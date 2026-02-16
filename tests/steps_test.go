package addrchain_test

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/cucumber/godog"
)

// testContext holds state for BDD step definitions.
type testContext struct {
	addrctlPath string
	lastOutput  string
	lastErr     error
	lastExit    int
}

func newTestContext() *testContext {
	return &testContext{
		addrctlPath: "../cli/addrctl.exe",
	}
}

// runAddrctl executes the addrctl CLI and captures output.
func (tc *testContext) runAddrctl(args ...string) {
	cmd := exec.Command(tc.addrctlPath, args...)
	out, err := cmd.CombinedOutput()
	tc.lastOutput = string(out)
	tc.lastErr = err
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			tc.lastExit = exitErr.ExitCode()
		} else {
			tc.lastExit = -1
		}
	} else {
		tc.lastExit = 0
	}
}

// Step definitions

func (tc *testContext) aFreshAddrchainInstance() error {
	if _, err := os.Stat(tc.addrctlPath); os.IsNotExist(err) {
		return fmt.Errorf("addrctl not found at %s", tc.addrctlPath)
	}
	return nil
}

func (tc *testContext) aNodeIdentityIsGenerated() error {
	// addrctl generates ephemeral identity automatically
	return nil
}

func (tc *testContext) iClaimAddress(addr string) error {
	tc.runAddrctl("claim", addr)
	if tc.lastExit != 0 {
		return fmt.Errorf("claim failed: %s", tc.lastOutput)
	}
	return nil
}

func (tc *testContext) iReleaseAddress(addr string) error {
	tc.runAddrctl("release", addr)
	if tc.lastExit != 0 {
		return fmt.Errorf("release failed: %s", tc.lastOutput)
	}
	return nil
}

func (tc *testContext) theChainStatusShouldShow() error {
	tc.runAddrctl("status")
	if tc.lastExit != 0 {
		return fmt.Errorf("status failed: %s", tc.lastOutput)
	}
	return nil
}

func (tc *testContext) theOutputShouldContain(text string) error {
	if !strings.Contains(tc.lastOutput, text) {
		return fmt.Errorf("output does not contain %q:\n%s", text, tc.lastOutput)
	}
	return nil
}

func (tc *testContext) iShowIdentity() error {
	tc.runAddrctl("identity")
	if tc.lastExit != 0 {
		return fmt.Errorf("identity failed: %s", tc.lastOutput)
	}
	return nil
}

func (tc *testContext) theIdentityShouldBeAHexString() error {
	lines := strings.Split(strings.TrimSpace(tc.lastOutput), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "node_pubkey:") {
			parts := strings.Fields(line)
			if len(parts) < 2 {
				return fmt.Errorf("missing pubkey value")
			}
			pubkey := parts[1]
			if len(pubkey) != 64 { // 32 bytes = 64 hex chars
				return fmt.Errorf("pubkey length %d, expected 64", len(pubkey))
			}
			return nil
		}
	}
	return fmt.Errorf("node_pubkey not found in output")
}

func (tc *testContext) iCreateSubnetWithoutGateway() error {
	tc.runAddrctl("subnet", "create", "10.0.0.0/24")
	// This should fail (gateway required)
	if tc.lastExit == 0 {
		return fmt.Errorf("expected failure without gateway, but succeeded")
	}
	return nil
}

func (tc *testContext) theCreationShouldFail() error {
	if tc.lastExit == 0 {
		return fmt.Errorf("expected failure but got success")
	}
	return nil
}

func (tc *testContext) iCreateSubnetWithGatewayAndDNS(prefix, gw, dns string) error {
	tc.runAddrctl("subnet", "create", prefix, "--gateway", gw, "--dns", dns)
	if tc.lastExit != 0 {
		return fmt.Errorf("subnet create failed: %s", tc.lastOutput)
	}
	return nil
}

func (tc *testContext) iListPeers() error {
	tc.runAddrctl("peers")
	if tc.lastExit != 0 {
		return fmt.Errorf("peers failed: %s", tc.lastOutput)
	}
	return nil
}

func (tc *testContext) theOutputShouldShowZeroPeers() error {
	if !strings.Contains(tc.lastOutput, "active_peers: 0") {
		return fmt.Errorf("expected 0 peers, got: %s", tc.lastOutput)
	}
	return nil
}

func (tc *testContext) iUpdateSubnetWithSingleFlag(subnetID, flag, value string) error {
	tc.runAddrctl("subnet", "update", subnetID, flag, value)
	if tc.lastExit != 0 {
		return fmt.Errorf("subnet update failed: %s", tc.lastOutput)
	}
	return nil
}

func (tc *testContext) iUpdateSubnetWithMultipleFlags(subnetID, f1, v1, f2, v2, f3, v3 string) error {
	tc.runAddrctl("subnet", "update", subnetID, f1, v1, f2, v2, f3, v3)
	if tc.lastExit != 0 {
		return fmt.Errorf("subnet update failed: %s", tc.lastOutput)
	}
	return nil
}

func (tc *testContext) iTryUpdateSubnetNoFlags(subnetID string) error {
	tc.runAddrctl("subnet", "update", subnetID)
	return nil
}

func (tc *testContext) iTryUpdateSubnetNoID() error {
	tc.runAddrctl("subnet", "update")
	return nil
}

func (tc *testContext) theUpdateShouldFail() error {
	if tc.lastExit == 0 {
		return fmt.Errorf("expected failure but got success")
	}
	return nil
}

func (tc *testContext) iDeleteSubnet(subnetID string) error {
	tc.runAddrctl("subnet", "delete", subnetID)
	if tc.lastExit != 0 {
		return fmt.Errorf("subnet delete failed: %s", tc.lastOutput)
	}
	return nil
}

func (tc *testContext) iTryDeleteSubnetNoID() error {
	tc.runAddrctl("subnet", "delete")
	return nil
}

func (tc *testContext) theDeleteShouldFail() error {
	if tc.lastExit == 0 {
		return fmt.Errorf("expected failure but got success")
	}
	return nil
}

func InitializeScenario(ctx *godog.ScenarioContext) {
	tc := newTestContext()

	ctx.Step(`^a fresh addrchain instance$`, tc.aFreshAddrchainInstance)
	ctx.Step(`^a node identity is generated$`, tc.aNodeIdentityIsGenerated)
	ctx.Step(`^I claim address "([^"]*)"$`, tc.iClaimAddress)
	ctx.Step(`^I release address "([^"]*)"$`, tc.iReleaseAddress)
	ctx.Step(`^the chain status should show$`, tc.theChainStatusShouldShow)
	ctx.Step(`^the output should contain "([^"]*)"$`, tc.theOutputShouldContain)
	ctx.Step(`^I show identity$`, tc.iShowIdentity)
	ctx.Step(`^the identity should be a hex string$`, tc.theIdentityShouldBeAHexString)
	ctx.Step(`^I try to create subnet "([^"]*)" with prefix "([^"]*)" without gateway$`,
		func(name, prefix string) error {
			tc.runAddrctl("subnet", "create", prefix)
			return nil
		})
	ctx.Step(`^the creation should fail$`, tc.theCreationShouldFail)
	ctx.Step(`^I create subnet with prefix "([^"]*)" gateway "([^"]*)" dns "([^"]*)"$`,
		tc.iCreateSubnetWithGatewayAndDNS)
	ctx.Step(`^I list peers$`, tc.iListPeers)
	ctx.Step(`^I should have 0 active peers$`, tc.theOutputShouldShowZeroPeers)
	ctx.Step(`^I update subnet "([^"]*)" with "([^"]*)" "([^"]*)"$`,
		tc.iUpdateSubnetWithSingleFlag)
	ctx.Step(`^I update subnet "([^"]*)" with flags "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)"$`,
		tc.iUpdateSubnetWithMultipleFlags)
	ctx.Step(`^I try to update subnet "([^"]*)" with no flags$`,
		tc.iTryUpdateSubnetNoFlags)
	ctx.Step(`^I try to update subnet without an id$`,
		tc.iTryUpdateSubnetNoID)
	ctx.Step(`^the update should fail$`, tc.theUpdateShouldFail)
	ctx.Step(`^I delete subnet "([^"]*)"$`, tc.iDeleteSubnet)
	ctx.Step(`^I try to delete subnet without an id$`, tc.iTryDeleteSubnetNoID)
	ctx.Step(`^the delete should fail$`, tc.theDeleteShouldFail)
}

func TestFeatures(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: InitializeScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"features"},
			TestingT: t,
		},
	}

	if suite.Run() != 0 {
		t.Fatal("non-zero status returned, failed to run feature tests")
	}
}
