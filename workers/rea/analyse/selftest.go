package main

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"strings"
	"time"
)

// selftest is the isolation probe of the reverse-engineering e2e test: run
// through the sandbox runner, it records what an analysis process (or a
// parser exploit inside one) can see and do. The test expects: only the
// loopback interface, no DNS, no connection to the API, the egress proxy or
// the internet, no write to the root filesystem, no capabilities, UID
// 10002, no PATHOS_ variables and none of the worker's processes.
type selfReport struct {
	UID         int               `json:"uid"`
	GID         int               `json:"gid"`
	CapEff      string            `json:"cap_eff"`
	Interfaces  []string          `json:"interfaces"`
	DNSOK       bool              `json:"dns_ok"`
	Connect     map[string]string `json:"connect"`
	RootWrite   string            `json:"root_write"`
	EnvKeys     []string          `json:"env_keys"`
	ProcVisible int               `json:"proc_pids_visible"`
}

func selftest(out string) error {
	r := selfReport{UID: os.Getuid(), GID: os.Getgid(), Connect: map[string]string{}, EnvKeys: []string{}, Interfaces: []string{}}
	if f, err := os.Open("/proc/self/status"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if v, ok := strings.CutPrefix(sc.Text(), "CapEff:"); ok {
				r.CapEff = strings.TrimSpace(v)
			}
		}
		_ = f.Close()
	}
	if ifs, err := net.Interfaces(); err == nil {
		for _, i := range ifs {
			r.Interfaces = append(r.Interfaces, i.Name)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if addrs, err := net.DefaultResolver.LookupHost(ctx, "example.com"); err == nil && len(addrs) > 0 {
		r.DNSOK = true
	}
	for _, a := range []string{"api:8081", "egress:3128", "1.1.1.1:443", "172.17.0.1:80"} {
		c, err := net.DialTimeout("tcp", a, 3*time.Second)
		if err != nil {
			r.Connect[a] = err.Error()
			continue
		}
		_ = c.Close()
		r.Connect[a] = ""
	}
	if f, err := os.Create("/pathos-rea-selftest"); err != nil {
		r.RootWrite = err.Error()
	} else {
		_ = f.Close()
		_ = os.Remove("/pathos-rea-selftest")
	}
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		r.EnvKeys = append(r.EnvKeys, k)
	}
	if ents, err := os.ReadDir("/proc"); err == nil {
		for _, e := range ents {
			if e.IsDir() && strings.Trim(e.Name(), "0123456789") == "" {
				r.ProcVisible++
			}
		}
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	// #nosec G703 -- the output path is pathos-rea's argument, in the sandbox job directory
	return os.WriteFile(out, b, 0o600)
}
