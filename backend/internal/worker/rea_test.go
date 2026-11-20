package worker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestREAInputNameAndConfig(t *testing.T) {
	for in, want := range map[string]string{"server": "server", "../../etc/passwd": "passwd", "a b;c.bin": "a_b_c.bin", "": "artifact.bin",
		".hidden": "hidden", `C:\build\app.exe`: "app.exe"} {
		if got := reaInputName(in); got != want {
			t.Errorf("reaInputName(%q) = %q, want %q", in, got, want)
		}
	}
	c := REAConfig{Tools: []string{"radare2", "frida", "radare2", "ghidra"}, MemoryMB: 1, TimeoutSeconds: 99999999}
	c.normalise()
	if !slices.Equal(c.Tools, []string{"radare2", "ghidra"}) || c.MemoryMB != 4096 || c.TimeoutSeconds != 1800 || c.MaxFunctions != 20000 {
		t.Errorf("normalise: %+v", c)
	}
	empty := REAConfig{}
	empty.normalise()
	if !slices.Equal(empty.Tools, []string{"radare2", "binwalk"}) {
		t.Errorf("default tools: %v", empty.Tools)
	}
}

func TestCompactREAVersion(t *testing.T) {
	got := compactREAVersion("pathos-rea dev; radare2 6.2.6; binwalk 3.1.0; ghidra -; jadx -; ilspy 11.2.0.10050\n")
	if got != "pathos-rea dev; radare2 6.2.6; binwalk 3.1.0; ilspy 11.2.0.10050" {
		t.Errorf("%q", got)
	}
	if long := compactREAVersion(strings.Repeat("tool 1.0; ", 30)); len(long) > 100 {
		t.Errorf("too long: %d", len(long))
	}
}

func TestREAToolNeverRunsWithoutSandbox(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "server")
	if err := os.WriteFile(art, []byte("\x7fELF"), 0o600); err != nil {
		t.Fatal(err)
	}
	in := RunInput{Out: filepath.Join(dir, "out.json"), TargetFile: art, Target: &JobTarget{Kind: "artifact", FileName: "server"}}
	if _, err := (reaTool{}).Run(context.Background(), in); err == nil || !strings.Contains(err.Error(), "sandbox runner") {
		t.Fatalf("without a runner the analysis must fail, not run elsewhere: %v", err)
	}
	if _, err := os.Stat(in.Out); !errors.Is(err, os.ErrNotExist) {
		t.Error("an output was written without the sandbox")
	}
	if skipped, _ := (reaTool{}).Run(context.Background(), RunInput{Target: &JobTarget{Kind: "image"}}); skipped == "" {
		t.Error("an image target must be skipped")
	}
}

func TestVerifyBlobAttestation(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "download")
	if err := os.WriteFile(art, []byte("binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	stmt := base64.StdEncoding.EncodeToString([]byte(`{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://slsa.dev/provenance/v1",` +
		`"subject":[{"name":"download","digest":{"sha256":"aa"}}],"predicate":{"runDetails":{"builder":{"id":"https://ci.example.test/builder"}},` +
		`"buildDefinition":{"externalParameters":{"workflow":{"repository":"https://git.example.test/acme/api"}}}}}`))
	bundle, _ := json.MarshalIndent(map[string]any{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"dsseEnvelope": map[string]any{"payload": stmt, "payloadType": "application/vnd.in-toto+json"}}, "", "  ")
	var got [][]string
	ok := func(_ context.Context, _ []string, args ...string) ([]byte, string, error) {
		got = append(got, args)
		return nil, "", nil
	}
	tg := &JobTarget{Kind: "artifact", FileName: "server", SignatureMaterial: "c2ln", ProvenanceMaterial: string(bundle),
		Signature: &SignatureConfig{Mode: "key", PublicKey: "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----\n", Attestation: "slsaprovenance1"}}
	rep := verifySignature(context.Background(), ok, true, RunInput{Target: tg, TargetFile: filepath.Join(dir, "artifact")}, dir)
	if rep.Status != "verified" || rep.Attestation == nil || rep.Attestation.Status != "verified" ||
		rep.Attestation.BuilderID != "https://ci.example.test/builder" || rep.Attestation.SourceRepo != "https://git.example.test/acme/api" {
		t.Fatalf("report: %+v %+v", rep, rep.Attestation)
	}
	var att []string
	for _, a := range got {
		if a[0] == "verify-blob-attestation" {
			att = a
		}
	}
	if !slices.Contains(att, "--bundle") || !slices.Contains(att, "slsaprovenance1") || !slices.Contains(att, "--key") || att[len(att)-1] != art {
		t.Errorf("attestation command: %v", att)
	}
	// No provenance uploaded: missing; an invalid one: invalid.
	tg.ProvenanceMaterial = ""
	if rep := verifySignature(context.Background(), ok, true, RunInput{Target: tg, TargetFile: filepath.Join(dir, "artifact")}, dir); rep.Attestation.Status != "missing" {
		t.Errorf("missing: %+v", rep.Attestation)
	}
	tg.ProvenanceMaterial = string(bundle)
	bad := func(_ context.Context, _ []string, args ...string) ([]byte, string, error) {
		if args[0] == "verify-blob-attestation" {
			return nil, "Error: invalid signature when validating ASN.1 encoded signature\n", errors.New("exit 1")
		}
		return nil, "", nil
	}
	if rep := verifySignature(context.Background(), bad, true, RunInput{Target: tg, TargetFile: filepath.Join(dir, "artifact")}, dir); rep.Attestation.Status != "invalid" {
		t.Errorf("invalid: %+v", rep.Attestation)
	}
}
