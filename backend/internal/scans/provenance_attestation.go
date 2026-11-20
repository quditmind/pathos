package scans

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

// Provenance attestations of build artifacts (PATHOS 3.0 M10). An artifact
// can carry an in-toto SLSA provenance statement signed with
// `cosign attest-blob --bundle` (a Sigstore bundle with a DSSE envelope).
// The worker verifies it with `cosign verify-blob-attestation` against the
// target's signature policy (the attestation type must be one of the
// slsaprovenance types) and records attestation_status in
// signature_verifications. Only a verified statement is trusted, and only
// when its subject digest is the artifact's SHA-256; reverse engineering
// then reads the source commit from it.

const maxProvenanceMaterial = 262144

// ValidProvenanceMaterial accepts a Sigstore bundle with a DSSE envelope
// whose payload is an in-toto statement.
func ValidProvenanceMaterial(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	if len(v) > maxProvenanceMaterial {
		return errors.New("the provenance attestation is limited to 256 KiB")
	}
	if _, err := ParseProvenance(v); err != nil {
		return err
	}
	return nil
}

// Provenance is what PATHOS reads from a provenance statement.
type Provenance struct {
	PredicateType string            `json:"predicate_type"`
	Builder       string            `json:"builder"`
	SourceRepo    string            `json:"source_repository"`
	Commit        string            `json:"commit"`
	Subjects      []ProvenanceEntry `json:"subjects"`
}

// ProvenanceEntry is a statement subject (name and SHA-256).
type ProvenanceEntry struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

var gitCommitRe = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// HasSubject reports whether the statement attests the given SHA-256.
func (p Provenance) HasSubject(sha256 string) bool {
	for _, s := range p.Subjects {
		if s.SHA256 != "" && strings.EqualFold(s.SHA256, sha256) {
			return true
		}
	}
	return false
}

// ParseProvenance decodes a Sigstore bundle (or a bare DSSE envelope) and
// reads its in-toto statement. It does not verify signatures: that is the
// worker's cosign check, recorded in signature_verifications.
func ParseProvenance(material string) (Provenance, error) {
	var out Provenance
	var b struct {
		MediaType    string `json:"mediaType"`
		DSSEEnvelope *struct {
			Payload     string `json:"payload"`
			PayloadType string `json:"payloadType"`
		} `json:"dsseEnvelope"`
		Payload     string `json:"payload"`
		PayloadType string `json:"payloadType"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(material)), &b); err != nil {
		return out, errors.New("the provenance attestation is not valid JSON (upload the Sigstore bundle of cosign attest-blob --bundle)")
	}
	payload := b.Payload
	if b.DSSEEnvelope != nil {
		payload = b.DSSEEnvelope.Payload
	}
	if payload == "" {
		return out, errors.New("the provenance attestation has no DSSE envelope (upload the Sigstore bundle of cosign attest-blob --bundle)")
	}
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		if raw, err = base64.RawURLEncoding.DecodeString(payload); err != nil {
			return out, errors.New("the provenance attestation payload is not base64")
		}
	}
	var st struct {
		Type    string `json:"_type"`
		Subject []struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
		PredicateType string `json:"predicateType"`
		Predicate     struct {
			Builder struct {
				ID string `json:"id"`
			} `json:"builder"`
			Invocation struct {
				ConfigSource struct {
					URI    string            `json:"uri"`
					Digest map[string]string `json:"digest"`
				} `json:"configSource"`
			} `json:"invocation"`
			Materials []struct {
				URI    string            `json:"uri"`
				Digest map[string]string `json:"digest"`
			} `json:"materials"`
			BuildDefinition struct {
				ExternalParameters struct {
					Workflow struct {
						Repository string `json:"repository"`
					} `json:"workflow"`
				} `json:"externalParameters"`
				ResolvedDependencies []struct {
					URI    string            `json:"uri"`
					Digest map[string]string `json:"digest"`
				} `json:"resolvedDependencies"`
			} `json:"buildDefinition"`
			RunDetails struct {
				Builder struct {
					ID string `json:"id"`
				} `json:"builder"`
			} `json:"runDetails"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(raw, &st); err != nil || !strings.HasPrefix(st.Type, "https://in-toto.io/Statement/") {
		return out, errors.New("the provenance attestation payload is not an in-toto statement")
	}
	if !strings.HasPrefix(st.PredicateType, "https://slsa.dev/provenance/") {
		return out, errors.New("the attestation is not SLSA provenance (predicate type https://slsa.dev/provenance/...)")
	}
	out.PredicateType = clipStr(st.PredicateType, 300)
	p := st.Predicate
	out.Builder = clipStr(firstNonEmpty(p.RunDetails.Builder.ID, p.Builder.ID), 500)
	out.SourceRepo = clipStr(firstNonEmpty(p.BuildDefinition.ExternalParameters.Workflow.Repository, p.Invocation.ConfigSource.URI), 500)
	commit := func(d map[string]string) string {
		for _, k := range []string{"gitCommit", "sha1"} {
			if v := strings.ToLower(d[k]); gitCommitRe.MatchString(v) {
				return v
			}
		}
		return ""
	}
	for _, d := range p.BuildDefinition.ResolvedDependencies {
		if out.Commit = commit(d.Digest); out.Commit != "" {
			if out.SourceRepo == "" {
				out.SourceRepo = clipStr(d.URI, 500)
			}
			break
		}
	}
	if out.Commit == "" {
		out.Commit = commit(p.Invocation.ConfigSource.Digest)
	}
	if out.Commit == "" {
		for _, m := range p.Materials {
			if out.Commit = commit(m.Digest); out.Commit != "" {
				break
			}
		}
	}
	for _, s := range st.Subject {
		if len(out.Subjects) >= 50 {
			break
		}
		out.Subjects = append(out.Subjects, ProvenanceEntry{Name: clipStr(s.Name, 300), SHA256: strings.ToLower(s.Digest["sha256"])})
	}
	if len(out.Subjects) == 0 {
		return out, errors.New("the provenance statement names no subject")
	}
	return out, nil
}

func clipStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
