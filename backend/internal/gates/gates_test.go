package gates

import (
	"testing"

	"github.com/google/uuid"
)

func TestNormalizeStage(t *testing.T) {
	for in, want := range map[string]string{"pre-commit": "pre_commit", "PULL-REQUEST": "pull_request", " ci ": "ci", "deploy": "deploy", "ide": "ide", "release": "release"} {
		if got, ok := NormalizeStage(in); !ok || got != want {
			t.Errorf("%q: %q %v", in, got, ok)
		}
	}
	if _, ok := NormalizeStage("production"); ok {
		t.Error("unknown stage accepted")
	}
}

func TestStrongestAndEffect(t *testing.T) {
	if Strongest(OutcomeWarn, OutcomeBlock) != OutcomeBlock || Strongest(OutcomeBlock, OutcomeApproval) != OutcomeBlock ||
		Strongest(OutcomePass, OutcomeExceptionApplied) != OutcomeExceptionApplied || Strongest(OutcomeApproval, OutcomeWarn) != OutcomeApproval {
		t.Error("outcome order")
	}
	for mode, want := range map[string]string{"block": OutcomeBlock, "warn": OutcomeWarn, "require_approval": OutcomeApproval, "x": OutcomePass} {
		if EffectOf(mode) != want {
			t.Errorf("%s → %s", mode, EffectOf(mode))
		}
	}
}

// Rule 7, service side: a decision blocks only with a policy id.
func TestFinalizeNeverBlocksWithoutPolicy(t *testing.T) {
	pol := PolicyRef{ID: uuid.Must(uuid.NewV7()), Name: "No critical", Version: 3}
	gid := uuid.Must(uuid.NewV7())

	d := Decision{}
	Finalize(&d)
	if d.Outcome != OutcomePass || len(d.Reasons) != 1 || d.Reasons[0].Code != ReasonNoPolicy {
		t.Fatalf("no gate: %+v", d)
	}

	d = Decision{Gates: []GateResult{{ID: &gid, Mode: "block", Matched: true, Effect: OutcomeBlock, Policy: pol}}}
	Finalize(&d)
	if d.Outcome != OutcomeBlock || len(d.PolicyIDs) != 1 || d.PolicyIDs[0] != pol.ID || d.PolicyVersions[0] != 3 {
		t.Fatalf("block with policy: %+v", d)
	}

	// A blocking effect without a policy (cannot come from the engine, which
	// loads gates with their policy) is downgraded to pass.
	for _, eff := range []string{OutcomeBlock, OutcomeApproval} {
		d = Decision{Gates: []GateResult{{ID: &gid, Mode: "block", Matched: true, Effect: eff}}}
		Finalize(&d)
		if d.Outcome != OutcomePass || len(d.PolicyIDs) != 0 {
			t.Fatalf("%s without policy must pass: %+v", eff, d)
		}
		found := false
		for _, r := range d.Reasons {
			found = found || r.Code == ReasonRule7Downgraded
		}
		if !found {
			t.Errorf("downgrade reason missing: %+v", d.Reasons)
		}
	}

	// Skipped and non-matching gates do not decide.
	d = Decision{Gates: []GateResult{{ID: &gid, Effect: effectSkipped, Policy: pol}, {ID: &gid, Effect: OutcomePass, Policy: pol}}}
	Finalize(&d)
	if d.Outcome != OutcomePass || len(d.PolicyIDs) != 0 {
		t.Fatalf("skipped: %+v", d)
	}

	// Warn and an applied exception keep their policies for the record.
	d = Decision{Gates: []GateResult{{ID: &gid, Effect: OutcomeWarn, Policy: pol}, {ID: &gid, Effect: OutcomeExceptionApplied, Policy: pol}}}
	Finalize(&d)
	if d.Outcome != OutcomeWarn || len(d.PolicyIDs) != 1 || d.Blocks() {
		t.Fatalf("warn: %+v", d)
	}
}
