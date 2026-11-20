package worker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"pathos/internal/scanners"
)

// Sigstore signature and attestation verification of image and artifact
// targets with the pinned cosign binary. The result is evidence (the
// report is stored with the scan) whatever it is; a finding is created only
// when the target requires a valid signature.

// SignatureConfig is a target's verification policy.
type SignatureConfig struct {
	// Mode: "" (off), key or keyless.
	Mode           string `json:"mode"`
	PublicKey      string `json:"public_key,omitempty"`
	Identity       string `json:"identity,omitempty"`
	IdentityRegexp string `json:"identity_regexp,omitempty"`
	Issuer         string `json:"issuer,omitempty"`
	// Require: a missing or invalid signature is a finding and fails the
	// security gate.
	Require bool `json:"require,omitempty"`
	// Attestation is a cosign predicate type to verify as well (image
	// targets), e.g. slsaprovenance.
	Attestation string `json:"attestation,omitempty"`
	// IgnoreTlog skips the transparency log (keys whose signatures were
	// never uploaded to Rekor).
	IgnoreTlog bool `json:"ignore_tlog,omitempty"`
}

type cosignTool struct{ cfg Config }

func (t cosignTool) Version(ctx context.Context) (string, error) {
	return simpleTool{bin: "cosign", versionArgs: []string{"version"}}.Version(ctx)
}

func (t cosignTool) Run(ctx context.Context, in RunInput) (string, error) {
	tg := in.Target
	if tg == nil || (tg.Kind != "image" && tg.Kind != "artifact" && tg.Kind != "mobile-app") {
		return "only runs for container image, artifact and mobile app targets", nil
	}
	if tg.Signature == nil || tg.Signature.Mode == "" {
		return "signature verification is not configured for this target", nil
	}
	rep := verifySignature(ctx, cosignRunner, t.cfg.Offline, in, filepath.Dir(in.Out))
	b, err := json.Marshal(rep)
	if err != nil {
		return "", err
	}
	return "", os.WriteFile(in.Out, b, 0o600)
}

// runner executes cosign; tests replace it.
type runner func(ctx context.Context, env []string, args ...string) (stdout []byte, stderr string, err error)

func cosignRunner(ctx context.Context, env []string, args ...string) ([]byte, string, error) {
	var out bytes.Buffer
	stderr, err := commandTo(ctx, &limitedWriter{buf: &out, max: 8 << 20}, env, []int{0}, "cosign", args...)
	return out.Bytes(), string(stderr), err
}

// verifySignature builds the cosign command lines and interprets them.
func verifySignature(ctx context.Context, run runner, offline bool, in RunInput, dir string) scanners.SignatureReport {
	tg := in.Target
	sc := tg.Signature
	rep := scanners.SignatureReport{Version: 1, Subject: tg.Reference, Mode: sc.Mode, Required: sc.Require, Offline: offline}
	if tg.Kind == "artifact" || tg.Kind == "mobile-app" {
		rep.Subject = firstNonEmptyStr(tg.FileName, tg.Reference)
	}
	fail := func(status, detail string) scanners.SignatureReport {
		rep.Status, rep.Detail = status, truncateStr(detail, 1000)
		return rep
	}
	if offline && sc.Mode == "keyless" {
		return fail("skipped", "keyless verification needs the Sigstore public-good infrastructure (Fulcio, Rekor, TUF); PATHOS runs offline. Use key-based verification")
	}
	var flags []string
	switch sc.Mode {
	case "key":
		keyFile := filepath.Join(dir, "cosign.pub")
		if err := os.WriteFile(keyFile, []byte(sc.PublicKey), 0o600); err != nil {
			return fail("error", err.Error())
		}
		flags = append(flags, "--key", keyFile)
	case "keyless":
		if sc.IdentityRegexp != "" {
			flags = append(flags, "--certificate-identity-regexp", sc.IdentityRegexp)
		} else {
			flags = append(flags, "--certificate-identity", sc.Identity)
		}
		flags = append(flags, "--certificate-oidc-issuer", sc.Issuer)
	default:
		return fail("error", "unknown verification mode")
	}
	if offline || sc.IgnoreTlog {
		flags = append(flags, "--insecure-ignore-tlog=true")
	}
	env := []string{"HOME=" + filepath.Join(dir, "cosign-home")}
	if tg.Kind == "image" && tg.AuthType == "basic" && tg.Username != "" {
		cfgDir := filepath.Join(dir, "docker-config")
		if err := writeDockerConfig(cfgDir, tg.Reference, tg.Username, tg.Password); err != nil {
			return fail("error", err.Error())
		}
		env = append(env, "DOCKER_CONFIG="+cfgDir)
	}
	if tg.Kind == "artifact" || tg.Kind == "mobile-app" {
		file := artifactOriginal(in.TargetFile, tg.FileName)
		if file == "" {
			return fail("error", "the artifact file is not available")
		}
		if sc.Attestation != "" {
			// SLSA provenance of the artifact (cosign attest-blob),
			// verified independently of the detached signature.
			rep.Attestation = verifyBlobAttestation(ctx, run, env, flags, sc.Attestation, tg.ProvenanceMaterial, file, dir)
		}
		if strings.TrimSpace(tg.SignatureMaterial) == "" {
			return fail("unsigned", "no signature or Sigstore bundle was uploaded with the artifact")
		}
		args := append([]string{"verify-blob"}, flags...)
		mat := filepath.Join(dir, "artifact.sig")
		if json.Valid([]byte(tg.SignatureMaterial)) {
			mat = filepath.Join(dir, "artifact.sigstore.json")
			args = append(args, "--bundle", mat)
		} else {
			args = append(args, "--signature", mat)
		}
		if err := os.WriteFile(mat, []byte(tg.SignatureMaterial), 0o600); err != nil {
			return fail("error", err.Error())
		}
		_, stderr, err := run(ctx, env, append(args, file)...)
		if err != nil {
			st, msg := classifyCosign(stderr, err)
			return fail(st, msg)
		}
		rep.Status = "verified"
		return rep
	}
	out, stderr, err := run(ctx, env, append(append([]string{"verify"}, flags...), "--output", "json", tg.Reference)...)
	if err != nil {
		st, msg := classifyCosign(stderr, err)
		return fail(st, msg)
	}
	rep.Status = "verified"
	rep.Signatures = parseCosignVerify(out)
	if sc.Attestation != "" {
		a := &scanners.AttestationResult{Type: sc.Attestation}
		out, stderr, err := run(ctx, env, append(append([]string{"verify-attestation", "--type", sc.Attestation}, flags...), tg.Reference)...)
		if err != nil {
			st, msg := classifyCosign(stderr, err)
			switch {
			case strings.Contains(stderr, "no matching attestations") || st == "unsigned":
				a.Status = "missing"
			case st == "invalid":
				a.Status = "invalid"
			default:
				a.Status = "error"
			}
			a.Detail = truncateStr(msg, 1000)
		} else {
			a.Status = "verified"
			a.PredicateType, a.BuilderID, a.SourceRepo = parseAttestation(out)
		}
		rep.Attestation = a
	}
	return rep
}

// verifyBlobAttestation verifies an artifact's provenance attestation (a
// Sigstore bundle from cosign attest-blob) with cosign
// verify-blob-attestation and the target's key or identity policy.
func verifyBlobAttestation(ctx context.Context, run runner, env, flags []string, typ, material, file, dir string) *scanners.AttestationResult {
	a := &scanners.AttestationResult{Type: typ}
	if strings.TrimSpace(material) == "" {
		a.Status, a.Detail = "missing", "no provenance attestation was uploaded with the artifact"
		return a
	}
	bundle := filepath.Join(dir, "provenance.sigstore.json")
	if err := os.WriteFile(bundle, []byte(material), 0o600); err != nil {
		a.Status, a.Detail = "error", truncateStr(err.Error(), 1000)
		return a
	}
	args := append(append([]string{"verify-blob-attestation", "--bundle", bundle, "--type", typ}, flags...), file)
	if _, stderr, err := run(ctx, env, args...); err != nil {
		st, msg := classifyCosign(stderr, err)
		switch {
		case st == "unsigned":
			a.Status = "missing"
		case st == "invalid":
			a.Status = "invalid"
		default:
			a.Status = "error"
		}
		a.Detail = truncateStr(msg, 1000)
		return a
	}
	a.Status = "verified"
	var b struct {
		DSSEEnvelope json.RawMessage `json:"dsseEnvelope"`
	}
	var env1 bytes.Buffer
	if json.Unmarshal([]byte(material), &b) == nil && json.Compact(&env1, b.DSSEEnvelope) == nil {
		a.PredicateType, a.BuilderID, a.SourceRepo = parseAttestation(env1.Bytes())
	}
	return a
}

// classifyCosign maps cosign's error output to unsigned, invalid or error.
func classifyCosign(stderr string, err error) (string, string) {
	msg, identity := "", ""
	for _, l := range strings.Split(stderr, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "Error: "):
			msg = strings.TrimPrefix(l, "Error: ")
		case strings.Contains(l, "none of the expected identities") && identity == "":
			// Names the identities actually found: more useful than the
			// final error.
			identity = l
		}
	}
	if identity != "" {
		msg = identity
	}
	if msg == "" {
		msg = lastLine(firstNonEmptyStr(stderr, err.Error()))
	}
	low := strings.ToLower(stderr)
	switch {
	case strings.Contains(low, "no signatures found"):
		return "unsigned", msg
	case strings.Contains(low, "no matching signatures"), strings.Contains(low, "invalid signature"),
		strings.Contains(low, "none of the expected identities"), strings.Contains(low, "expected identities"),
		strings.Contains(low, "certificate"), strings.Contains(low, "verifying signature"), strings.Contains(low, "no matching attestations"):
		return "invalid", msg
	}
	return "error", msg
}

// parseCosignVerify reads `cosign verify --output json`.
func parseCosignVerify(out []byte) []scanners.SignatureIdentity {
	var sigs []struct {
		Critical struct {
			Image struct {
				Digest string `json:"docker-manifest-digest"`
			} `json:"image"`
		} `json:"critical"`
		Optional map[string]any `json:"optional"`
	}
	if err := json.Unmarshal(out, &sigs); err != nil {
		return nil
	}
	var res []scanners.SignatureIdentity
	for _, s := range sigs {
		id := scanners.SignatureIdentity{Digest: truncateStr(s.Critical.Image.Digest, 100)}
		if v, ok := s.Optional["Subject"].(string); ok {
			id.Identity = truncateStr(v, 500)
		}
		if v, ok := s.Optional["Issuer"].(string); ok {
			id.Issuer = truncateStr(v, 500)
		}
		res = append(res, id)
		if len(res) >= 20 {
			break
		}
	}
	return res
}

// parseAttestation reads the first in-toto statement of
// `cosign verify-attestation` (DSSE envelopes, one per line) and returns
// its predicate type, builder and source repository (SLSA v0.2 and v1).
func parseAttestation(out []byte) (predicateType, builder, source string) {
	for _, line := range bytes.Split(out, []byte("\n")) {
		var env struct {
			Payload string `json:"payload"`
		}
		if json.Unmarshal(bytes.TrimSpace(line), &env) != nil || env.Payload == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(env.Payload)
		if err != nil {
			continue
		}
		var st struct {
			PredicateType string `json:"predicateType"`
			Predicate     struct {
				Builder struct {
					ID string `json:"id"`
				} `json:"builder"`
				Invocation struct {
					ConfigSource struct {
						URI string `json:"uri"`
					} `json:"configSource"`
				} `json:"invocation"`
				RunDetails struct {
					Builder struct {
						ID string `json:"id"`
					} `json:"builder"`
				} `json:"runDetails"`
				BuildDefinition struct {
					ExternalParameters struct {
						Workflow struct {
							Repository string `json:"repository"`
						} `json:"workflow"`
					} `json:"externalParameters"`
				} `json:"buildDefinition"`
			} `json:"predicate"`
		}
		if json.Unmarshal(raw, &st) != nil {
			continue
		}
		p := st.Predicate
		return truncateStr(st.PredicateType, 300), truncateStr(firstNonEmptyStr(p.Builder.ID, p.RunDetails.Builder.ID), 500),
			truncateStr(firstNonEmptyStr(p.Invocation.ConfigSource.URI, p.BuildDefinition.ExternalParameters.Workflow.Repository), 500)
	}
	return "", "", ""
}

// writeDockerConfig writes registry credentials for cosign (never on its
// command line).
func writeDockerConfig(dir, ref, user, pass string) error {
	host := ref
	if i := strings.IndexByte(host, '/'); i > 0 && (strings.ContainsAny(host[:i], ".:") || host[:i] == "localhost") {
		host = host[:i]
	} else {
		host = "https://index.docker.io/v1/"
	}
	cfg := map[string]any{"auths": map[string]any{host: map[string]string{"auth": basicAuth(user, pass)}}}
	b, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "config.json"), b, 0o600)
}

// artifactOriginal is the uploaded artifact file as downloaded (archives
// are extracted next to it; other files are moved into the scan directory).
func artifactOriginal(scanDir, fileName string) string {
	if scanDir == "" {
		return ""
	}
	if p := filepath.Join(filepath.Dir(scanDir), "download"); fileExists(p) {
		return p
	}
	if p := filepath.Join(scanDir, artifactFileName(fileName)); fileExists(p) {
		return p
	}
	return ""
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

// artifactFileName is the name an artifact is scanned under.
func artifactFileName(name string) string {
	name = filepath.Base(name)
	if name == "" || name == "." || name == "/" || strings.HasPrefix(name, ".") {
		return "artifact.bin"
	}
	return name
}
