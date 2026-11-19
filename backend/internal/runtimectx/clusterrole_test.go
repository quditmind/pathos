package runtimectx

import (
	"bytes"
	"errors"
	"io"
	"os"
	"slices"
	"testing"

	"go.yaml.in/yaml/v3"
)

// The ClusterRole shipped in deploy/kubernetes grants exactly what the
// inventory lists: get, list and watch, never Secrets or ConfigMaps.
func TestClusterRoleMatchesResources(t *testing.T) {
	raw, err := os.ReadFile("../../../deploy/kubernetes/pathos-reader-clusterrole.yaml")
	if os.IsNotExist(err) {
		t.Skip("deploy/ not available in this build context")
	}
	if err != nil {
		t.Fatal(err)
	}
	granted := map[string]bool{}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	for {
		var doc struct {
			Kind  string `yaml:"kind"`
			Rules []struct {
				APIGroups []string `yaml:"apiGroups"`
				Resources []string `yaml:"resources"`
				Verbs     []string `yaml:"verbs"`
			} `yaml:"rules"`
		}
		if err := dec.Decode(&doc); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if doc.Kind != "ClusterRole" {
			continue
		}
		for _, r := range doc.Rules {
			for _, v := range r.Verbs {
				if !slices.Contains([]string{"get", "list", "watch"}, v) {
					t.Errorf("verb %q is not read-only", v)
				}
			}
			for _, g := range r.APIGroups {
				for _, res := range r.Resources {
					if res == "secrets" || res == "configmaps" || res == "*" || g == "*" {
						t.Errorf("must not grant %s/%s", g, res)
					}
					granted[g+"/"+res] = true
				}
			}
		}
	}
	for _, r := range Resources {
		if !granted[r.Group+"/"+r.Plural] {
			t.Errorf("the ClusterRole does not grant %s/%s, which the inventory lists", r.Group, r.Plural)
		}
	}
	if len(granted) != len(Resources) {
		t.Errorf("the ClusterRole grants %d resources, the inventory reads %d", len(granted), len(Resources))
	}
}
