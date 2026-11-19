package runtimectx

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Credentials reach one cluster's API server: a bearer token (service
// account) or a client certificate, and the CA bundle that signs the API
// server's certificate (the system roots when empty).
type Credentials struct {
	Server     string `json:"server"`
	CAData     string `json:"ca_data,omitempty"` // PEM
	Token      string `json:"token,omitempty"`
	ClientCert string `json:"client_cert,omitempty"` // PEM
	ClientKey  string `json:"client_key,omitempty"`  // PEM
}

// TLSConfig builds the client TLS configuration (TLS 1.2+, verified).
func (c Credentials) TLSConfig() (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if strings.TrimSpace(c.CAData) != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(c.CAData)) {
			return nil, errors.New("the CA certificate is not a PEM certificate")
		}
		cfg.RootCAs = pool
	}
	if c.ClientCert != "" || c.ClientKey != "" {
		pair, err := tls.X509KeyPair([]byte(c.ClientCert), []byte(c.ClientKey))
		if err != nil {
			return nil, fmt.Errorf("client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	return cfg, nil
}

// kubeconfig is the subset of the kubeconfig format PATHOS reads.
type kubeconfig struct {
	CurrentContext string `yaml:"current-context"`
	Clusters       []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server                   string `yaml:"server"`
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
			CertificateAuthority     string `yaml:"certificate-authority"`
			InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify"`
			ProxyURL                 string `yaml:"proxy-url"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster string `yaml:"cluster"`
			User    string `yaml:"user"`
		} `yaml:"context"`
	} `yaml:"contexts"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			Token                 string         `yaml:"token"`
			TokenFile             string         `yaml:"tokenFile"`
			ClientCertificateData string         `yaml:"client-certificate-data"`
			ClientKeyData         string         `yaml:"client-key-data"`
			ClientCertificate     string         `yaml:"client-certificate"`
			ClientKey             string         `yaml:"client-key"`
			Exec                  map[string]any `yaml:"exec"`
			AuthProvider          map[string]any `yaml:"auth-provider"`
			Username              string         `yaml:"username"`
		} `yaml:"user"`
	} `yaml:"users"`
}

// ParseKubeconfig reads the current context (or the named one) of a
// kubeconfig. Only inline credentials are accepted: PATHOS never reads
// files named in a kubeconfig and never runs exec or auth-provider
// plugins, and insecure-skip-tls-verify is refused.
func ParseKubeconfig(raw []byte, contextName string) (Credentials, error) {
	var kc kubeconfig
	if len(raw) > 256<<10 {
		return Credentials{}, errors.New("kubeconfig is larger than 256 KiB")
	}
	if err := yaml.Unmarshal(raw, &kc); err != nil {
		// kubeconfig is YAML; JSON is a subset.
		if jerr := json.Unmarshal(raw, &kc); jerr != nil {
			return Credentials{}, fmt.Errorf("kubeconfig: %w", err)
		}
	}
	name := strings.TrimSpace(contextName)
	if name == "" {
		name = kc.CurrentContext
	}
	if name == "" && len(kc.Contexts) == 1 {
		name = kc.Contexts[0].Name
	}
	var clusterName, userName string
	found := false
	for _, c := range kc.Contexts {
		if c.Name == name {
			clusterName, userName, found = c.Context.Cluster, c.Context.User, true
		}
	}
	if !found {
		return Credentials{}, fmt.Errorf("kubeconfig: context %q not found", name)
	}
	var out Credentials
	found = false
	for _, c := range kc.Clusters {
		if c.Name != clusterName {
			continue
		}
		found = true
		cl := c.Cluster
		if cl.InsecureSkipTLSVerify {
			return Credentials{}, errors.New("kubeconfig: insecure-skip-tls-verify is not allowed; provide certificate-authority-data")
		}
		if cl.CertificateAuthority != "" && cl.CertificateAuthorityData == "" {
			return Credentials{}, errors.New("kubeconfig: certificate-authority refers to a file; inline it as certificate-authority-data")
		}
		if cl.ProxyURL != "" {
			return Credentials{}, errors.New("kubeconfig: proxy-url is not supported (PATHOS uses PATHOS_HTTPS_PROXY)")
		}
		out.Server = strings.TrimRight(strings.TrimSpace(cl.Server), "/")
		if cl.CertificateAuthorityData != "" {
			ca, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cl.CertificateAuthorityData))
			if err != nil {
				return Credentials{}, errors.New("kubeconfig: certificate-authority-data is not base64")
			}
			out.CAData = string(ca)
		}
	}
	if !found {
		return Credentials{}, fmt.Errorf("kubeconfig: cluster %q not found", clusterName)
	}
	found = false
	for _, u := range kc.Users {
		if u.Name != userName {
			continue
		}
		found = true
		us := u.User
		switch {
		case len(us.Exec) > 0 || len(us.AuthProvider) > 0:
			return Credentials{}, errors.New("kubeconfig: exec and auth-provider plugins are not supported; use a service-account token")
		case us.TokenFile != "" || us.ClientCertificate != "" || us.ClientKey != "":
			return Credentials{}, errors.New("kubeconfig: credentials refer to files; inline them (token, client-certificate-data, client-key-data)")
		case us.Token != "":
			out.Token = strings.TrimSpace(us.Token)
		case us.ClientCertificateData != "" && us.ClientKeyData != "":
			cert, err1 := base64.StdEncoding.DecodeString(strings.TrimSpace(us.ClientCertificateData))
			key, err2 := base64.StdEncoding.DecodeString(strings.TrimSpace(us.ClientKeyData))
			if err1 != nil || err2 != nil {
				return Credentials{}, errors.New("kubeconfig: client certificate data is not base64")
			}
			out.ClientCert, out.ClientKey = string(cert), string(key)
		default:
			return Credentials{}, errors.New("kubeconfig: the user has no token or client certificate")
		}
	}
	if !found {
		return Credentials{}, fmt.Errorf("kubeconfig: user %q not found", userName)
	}
	if out.Server == "" {
		return Credentials{}, errors.New("kubeconfig: the cluster has no server")
	}
	if _, err := out.TLSConfig(); err != nil {
		return Credentials{}, fmt.Errorf("kubeconfig: %w", err)
	}
	return out, nil
}
