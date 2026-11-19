package main

import (
	"bufio"
	"bytes"
	"path"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Containers and infrastructure as code: Dockerfiles, Docker Compose
// files, Kubernetes manifests and Terraform. Everything is read as text
// or YAML; nothing is built, rendered or applied.

// knownImages maps an image name to the datastore or queue it runs.
var knownImages = []struct{ sub, kind, tech string }{
	{"postgres", "datastore", "postgresql"}, {"postgis", "datastore", "postgresql"}, {"mysql", "datastore", "mysql"},
	{"mariadb", "datastore", "mysql"}, {"mongo", "datastore", "mongodb"}, {"redis", "datastore", "redis"},
	{"valkey", "datastore", "redis"}, {"memcached", "datastore", "memcached"}, {"elasticsearch", "datastore", "elasticsearch"},
	{"opensearch", "datastore", "elasticsearch"}, {"minio", "datastore", "s3"}, {"seaweedfs", "datastore", "s3"},
	{"cassandra", "datastore", "cassandra"}, {"mssql", "datastore", "sqlserver"}, {"clickhouse", "datastore", "clickhouse"},
	{"rabbitmq", "queue", "rabbitmq"}, {"kafka", "queue", "kafka"}, {"redpanda", "queue", "kafka"}, {"nats", "queue", "nats"},
	{"activemq", "queue", "activemq"}, {"pulsar", "queue", "pulsar"},
}

func imageService(image string) (kind, tech string) {
	name := strings.ToLower(image)
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	name = strings.SplitN(strings.SplitN(name, "@", 2)[0], ":", 2)[0]
	for _, k := range knownImages {
		if name == k.sub || strings.HasPrefix(name, k.sub+"-") || strings.HasSuffix(name, "-"+k.sub) || strings.HasPrefix(name, k.sub) {
			return k.kind, k.tech
		}
	}
	return "", ""
}

// serviceNode returns (creating) the datastore or queue node a known
// image provides.
func (p *project) serviceNode(kind, tech string) string {
	if kind == "datastore" {
		key := "ds:" + tech
		p.g.AddNode(key, "datastore", datastoreLabel(tech), "", map[string]any{"technology": tech})
		return key
	}
	key := "queue:" + tech
	p.g.AddNode(key, "queue", tech, "", map[string]any{"technology": tech})
	return key
}

func imageName(ref string) string {
	ref = strings.SplitN(ref, "@", 2)[0]
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref = ref[:i]
	}
	return ref
}

func isDockerfile(rel string) bool {
	b := strings.ToLower(path.Base(rel))
	return b == "dockerfile" || b == "containerfile" || strings.HasPrefix(b, "dockerfile.") || strings.HasSuffix(b, ".dockerfile")
}

func isCompose(rel string) bool {
	b := strings.ToLower(path.Base(rel))
	return (strings.HasPrefix(b, "docker-compose") || strings.HasPrefix(b, "compose")) && (strings.HasSuffix(b, ".yml") || strings.HasSuffix(b, ".yaml"))
}

var argRe = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)`)

func (p *project) extractDockerfiles() {
	for _, rel := range p.paths {
		if !isDockerfile(rel) {
			continue
		}
		data, err := p.read(rel)
		if err != nil {
			continue
		}
		var bases []string
		var expose []string
		user, lastFrom, fromLine := "", "", 0
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		ln := 0
		for sc.Scan() {
			ln++
			f := strings.Fields(sc.Text())
			if len(f) < 2 {
				continue
			}
			switch strings.ToUpper(f[0]) {
			case "FROM":
				img := f[1]
				for _, x := range f[1:] {
					if !strings.HasPrefix(x, "--") {
						img = x
						break
					}
				}
				bases = append(bases, img)
				lastFrom, fromLine, user = img, ln, ""
			case "EXPOSE":
				expose = append(expose, f[1:]...)
			case "USER":
				user = f[1]
			}
		}
		if lastFrom == "" {
			continue
		}
		fileKey := p.fileNode(rel, "")
		key := "container:dockerfile:" + rel
		dir := path.Dir(rel)
		label := path.Base(dir) + " image"
		if dir == "." {
			label = "repository image"
		}
		if !p.g.AddNode(key, "container", label, fileKey, map[string]any{"file": rel, "line": fromLine, "base_image": lastFrom,
			"stages": len(bases), "expose": strings.Join(expose, " "), "user": user, "technology": "docker"}) {
			continue
		}
		ev := fileLine(rel, fromLine, "FROM "+lastFrom)
		p.g.AddEdge(fileKey, "defines", key, ev)
		mod := "mod:" + dir
		if !p.g.Has(mod) {
			mod = p.moduleOf(rel, "")
		}
		p.g.AddEdge(mod, "deployed_as", key, fileLine(rel, fromLine, "image built from "+dir))
		// Base image as a dependency (not the stage names).
		if !argRe.MatchString(lastFrom) && !strings.EqualFold(lastFrom, "scratch") && !isStageName(lastFrom, data) {
			name := imageName(lastFrom)
			ck := "comp:pkg:oci/" + name
			p.g.AddNode(ck, "component", name, "", map[string]any{"ecosystem": "oci", "technology": "container image", "version": strings.TrimPrefix(lastFrom, name), "source": "dockerfile"})
			p.g.AddEdge(key, "depends_on", ck, ev)
		}
	}
}

func isStageName(img string, data []byte) bool {
	return regexp.MustCompile(`(?im)^\s*FROM\s+\S+\s+AS\s+` + regexp.QuoteMeta(img) + `\s*$`).Match(data)
}

// ---------------------------------------------------------------- compose

func (p *project) extractCompose() {
	for _, rel := range p.paths {
		if !isCompose(rel) {
			continue
		}
		data, err := p.read(rel)
		if err != nil {
			continue
		}
		var root yaml.Node
		if yaml.Unmarshal(data, &root) != nil || len(root.Content) == 0 {
			p.skip(rel, "compose file could not be parsed")
			continue
		}
		doc := root.Content[0]
		services := mapValue(doc, "services")
		if services == nil || services.Kind != yaml.MappingNode {
			continue
		}
		fileKey := p.fileNode(rel, "")
		dir := path.Dir(rel)
		keys := map[string]string{}
		type svcInfo struct {
			name string
			node *yaml.Node
			line int
		}
		var svcs []svcInfo
		for i := 0; i+1 < len(services.Content); i += 2 {
			name, sv := services.Content[i].Value, services.Content[i+1]
			key := "container:compose:" + rel + "#" + name
			image := ""
			if v := mapValue(sv, "image"); v != nil {
				image = v.Value
			}
			attrs := map[string]any{"file": rel, "line": services.Content[i].Line, "image": image, "technology": "docker compose", "service": name}
			if n := mapValue(sv, "network_mode"); n != nil {
				attrs["network_mode"] = n.Value
			}
			if !p.g.AddNode(key, "container", name, fileKey, attrs) {
				continue
			}
			keys[name] = key
			svcs = append(svcs, svcInfo{name, sv, services.Content[i].Line})
			p.g.AddEdge(fileKey, "defines", key, fileLine(rel, services.Content[i].Line, "service "+name))
		}
		for _, s := range svcs {
			key, sv := keys[s.name], s.node
			// Image of a known datastore or queue: the service runs it.
			if img := mapValue(sv, "image"); img != nil && !argRe.MatchString(imageName(img.Value)) {
				if kind, tech := imageService(img.Value); kind != "" {
					p.g.AddEdge(p.serviceNode(kind, tech), "deployed_as", key, fileLine(rel, img.Line, "image "+img.Value))
				}
			}
			// Build context: the Dockerfile's image runs as this service.
			if b := mapValue(sv, "build"); b != nil {
				ctx, df, line := "", "Dockerfile", b.Line
				if b.Kind == yaml.ScalarNode {
					ctx = b.Value
				} else {
					if c := mapValue(b, "context"); c != nil {
						ctx, line = c.Value, c.Line
					}
					if d := mapValue(b, "dockerfile"); d != nil {
						df = d.Value
					}
				}
				if ctx == "" {
					ctx = "."
				}
				dfRel := path.Clean(path.Join(dir, ctx, df))
				if !strings.HasPrefix(df, ".") && strings.Contains(df, "/") {
					// dockerfile relative to the context
					dfRel = path.Clean(path.Join(dir, ctx, df))
				}
				if ck := "container:dockerfile:" + dfRel; p.g.Has(ck) {
					p.g.AddEdge(ck, "deployed_as", key, fileLine(rel, line, "built from "+dfRel))
				}
			}
			// depends_on (list or map).
			if d := mapValue(sv, "depends_on"); d != nil {
				var deps []*yaml.Node
				if d.Kind == yaml.SequenceNode {
					deps = d.Content
				} else if d.Kind == yaml.MappingNode {
					for i := 0; i < len(d.Content); i += 2 {
						deps = append(deps, d.Content[i])
					}
				}
				for _, dn := range deps {
					if tk, ok := keys[dn.Value]; ok {
						p.g.AddEdge(key, "depends_on", tk, fileLine(rel, dn.Line, s.name+" depends on "+dn.Value))
					}
				}
			}
			// Published ports (not bound to the loopback address).
			if ports := mapValue(sv, "ports"); ports != nil && ports.Kind == yaml.SequenceNode {
				var pub []string
				for _, pn := range ports.Content {
					v := pn.Value
					if pn.Kind == yaml.MappingNode {
						if pp := mapValue(pn, "published"); pp != nil {
							v = pp.Value
						}
					}
					if v == "" || strings.HasPrefix(v, "127.") || strings.HasPrefix(v, "localhost") || strings.HasPrefix(v, "[::1]") ||
						strings.Contains(v, "127.0.0.1") {
						continue
					}
					pub = append(pub, v)
					p.boundary("tb:internet", "Internet")
					p.g.AddEdge(key, "crosses_boundary", "tb:internet", fileLine(rel, pn.Line, "published port "+v))
				}
				if n := p.g.Node(key); n != nil && len(pub) > 0 {
					n.Attrs["exposure"] = "published " + strings.Join(pub, ", ")
				}
			}
			// Secrets and credential-looking environment variables
			// (names only; values are never read).
			if sec := mapValue(sv, "secrets"); sec != nil && sec.Kind == yaml.SequenceNode {
				for _, sn := range sec.Content {
					name := sn.Value
					if sn.Kind == yaml.MappingNode {
						if src := mapValue(sn, "source"); src != nil {
							name = src.Value
						}
					}
					if name == "" {
						continue
					}
					sk := "secret:compose:" + name
					p.g.AddNode(sk, "secret_ref", name, "", map[string]any{"source": "compose secret", "file": rel, "line": sn.Line})
					p.g.AddEdge(key, "reads", sk, fileLine(rel, sn.Line, "secret "+name))
				}
			}
			if env := mapValue(sv, "environment"); env != nil {
				p.composeEnv(rel, key, env)
			}
		}
	}
}

func (p *project) composeEnv(rel, key string, env *yaml.Node) {
	add := func(name, value string, line int) {
		if credentialName(name) {
			sk := "secret:env:" + name
			p.g.AddNode(sk, "secret_ref", name, "", map[string]any{"source": "environment variable"})
			p.g.AddEdge(key, "reads", sk, fileLine(rel, line, "environment variable "+name))
		}
		p.configURL(rel, key, value, line)
	}
	switch env.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(env.Content); i += 2 {
			add(env.Content[i].Value, env.Content[i+1].Value, env.Content[i].Line)
		}
	case yaml.SequenceNode:
		for _, e := range env.Content {
			kv := strings.SplitN(e.Value, "=", 2)
			v := ""
			if len(kv) == 2 {
				v = kv[1]
			}
			add(kv[0], v, e.Line)
		}
	}
}

// ---------------------------------------------------------------- kubernetes

type k8sObj struct {
	kind, name, ns, key, rel string
	line                     int
	node                     *yaml.Node
	labels                   map[string]string
}

func (p *project) extractKubernetes() {
	var objs []*k8sObj
	for _, rel := range p.paths {
		ext := strings.ToLower(path.Ext(rel))
		if (ext != ".yaml" && ext != ".yml") || isCompose(rel) {
			continue
		}
		data, err := p.read(rel)
		if err != nil || !bytes.Contains(data, []byte("apiVersion")) || !bytes.Contains(data, []byte("kind")) {
			continue
		}
		if bytes.Contains(data, []byte("{{")) {
			p.skip(rel, "template (Helm or similar) not rendered")
			continue
		}
		for _, doc := range yamlDocs(data) {
			kind, api := mapValue(doc, "kind"), mapValue(doc, "apiVersion")
			md := mapValue(doc, "metadata")
			if kind == nil || api == nil || md == nil || kind.Kind != yaml.ScalarNode {
				continue
			}
			name := ""
			if n := mapValue(md, "name"); n != nil {
				name = n.Value
			}
			ns := ""
			if n := mapValue(md, "namespace"); n != nil {
				ns = n.Value
			}
			if name == "" || strings.HasPrefix(api.Value, "kustomize") || strings.Contains(api.Value, "openapi") {
				continue
			}
			o := &k8sObj{kind: kind.Value, name: name, ns: ns, rel: rel, line: kind.Line, node: doc, labels: map[string]string{}}
			o.key = "iac:k8s:" + o.kind + "/" + strings.TrimPrefix(ns+"/", "/") + name
			fileKey := p.fileNode(rel, "")
			if !p.g.AddNode(o.key, "iac_resource", o.kind+" "+name, fileKey, map[string]any{"file": rel, "line": o.line,
				"technology": "kubernetes", "kind": o.kind, "namespace": ns}) {
				continue
			}
			p.g.AddEdge(fileKey, "defines", o.key, fileLine(rel, o.line, o.kind+" "+name))
			objs = append(objs, o)
		}
	}
	for _, o := range objs {
		spec := mapValue(o.node, "spec")
		switch o.kind {
		case "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod", "ReplicaSet":
			pod := spec
			if o.kind == "CronJob" {
				pod = mapValue(mapValue(mapValue(spec, "jobTemplate"), "spec"), "template")
				pod = mapValue(pod, "spec")
			} else if o.kind != "Pod" {
				tpl := mapValue(spec, "template")
				if md := mapValue(tpl, "metadata"); md != nil {
					if lb := mapValue(md, "labels"); lb != nil {
						for i := 0; i+1 < len(lb.Content); i += 2 {
							o.labels[lb.Content[i].Value] = lb.Content[i+1].Value
						}
					}
				}
				pod = mapValue(tpl, "spec")
			}
			p.k8sPod(o, pod)
		}
	}
	for _, o := range objs {
		spec := mapValue(o.node, "spec")
		switch o.kind {
		case "Service":
			sel := mapValue(spec, "selector")
			if sel != nil && sel.Kind == yaml.MappingNode && len(sel.Content) > 0 {
				for _, w := range objs {
					if len(w.labels) == 0 || w.ns != o.ns {
						continue
					}
					match := true
					for i := 0; i+1 < len(sel.Content); i += 2 {
						if w.labels[sel.Content[i].Value] != sel.Content[i+1].Value {
							match = false
						}
					}
					if match {
						p.g.AddEdge(o.key, "exposes", w.key, fileLine(o.rel, sel.Line, "selector matches "+w.kind+" "+w.name))
					}
				}
			}
			if t := mapValue(spec, "type"); t != nil && (t.Value == "LoadBalancer" || t.Value == "NodePort") {
				p.boundary("tb:internet", "Internet")
				p.g.AddEdge(o.key, "crosses_boundary", "tb:internet", fileLine(o.rel, t.Line, "Service type "+t.Value))
				if n := p.g.Node(o.key); n != nil {
					n.Attrs["exposure"] = t.Value
				}
			}
		case "Ingress":
			p.boundary("tb:internet", "Internet")
			p.g.AddEdge(o.key, "crosses_boundary", "tb:internet", fileLine(o.rel, o.line, "Ingress "+o.name))
			if n := p.g.Node(o.key); n != nil {
				n.Attrs["exposure"] = "ingress"
			}
			walkYAML(spec, func(n *yaml.Node) {
				svc := mapValue(n, "service")
				if svc == nil {
					if sn := mapValue(n, "serviceName"); sn != nil { // networking/v1beta1
						p.linkService(o, sn.Value, sn.Line, objs)
					}
					return
				}
				if nm := mapValue(svc, "name"); nm != nil {
					p.linkService(o, nm.Value, nm.Line, objs)
				}
			})
		case "Secret":
			sk := "secret:k8s:" + o.name
			p.g.AddNode(sk, "secret_ref", o.name, "", map[string]any{"source": "Kubernetes Secret", "file": o.rel, "line": o.line})
			p.g.AddEdge(o.key, "deployed_as", sk, fileLine(o.rel, o.line, "Secret "+o.name+" (values not read)"))
		}
	}
}

func (p *project) linkService(o *k8sObj, name string, line int, objs []*k8sObj) {
	for _, s := range objs {
		if s.kind == "Service" && s.name == name && s.ns == o.ns {
			p.g.AddEdge(o.key, "exposes", s.key, fileLine(o.rel, line, "backend service "+name))
		}
	}
}

func walkYAML(n *yaml.Node, fn func(*yaml.Node)) {
	if n == nil {
		return
	}
	if n.Kind == yaml.MappingNode {
		fn(n)
	}
	for _, c := range n.Content {
		walkYAML(c, fn)
	}
}

func (p *project) k8sPod(o *k8sObj, pod *yaml.Node) {
	if pod == nil {
		return
	}
	for _, list := range []string{"containers", "initContainers"} {
		cs := mapValue(pod, list)
		if cs == nil || cs.Kind != yaml.SequenceNode {
			continue
		}
		for _, c := range cs.Content {
			img := mapValue(c, "image")
			if img == nil || img.Value == "" {
				continue
			}
			ck := p.containerForImage(img.Value)
			p.g.AddEdge(ck, "deployed_as", o.key, fileLine(o.rel, img.Line, "image "+img.Value))
			if kind, tech := imageService(img.Value); kind != "" {
				p.g.AddEdge(p.serviceNode(kind, tech), "deployed_as", o.key, fileLine(o.rel, img.Line, "image "+img.Value))
			}
		}
	}
	walkYAML(pod, func(n *yaml.Node) {
		for _, ref := range []string{"secretKeyRef", "secretRef"} {
			if sr := mapValue(n, ref); sr != nil {
				if nm := mapValue(sr, "name"); nm != nil {
					p.secretRef(o, nm.Value, nm.Line)
				}
			}
		}
		if sn := mapValue(n, "secretName"); sn != nil && sn.Kind == yaml.ScalarNode {
			p.secretRef(o, sn.Value, sn.Line)
		}
		if nm := mapValue(n, "name"); nm != nil && mapValue(n, "valueFrom") == nil && mapValue(n, "value") != nil && credentialName(nm.Value) {
			sk := "secret:env:" + nm.Value
			p.g.AddNode(sk, "secret_ref", nm.Value, "", map[string]any{"source": "environment variable"})
			p.g.AddEdge(o.key, "reads", sk, fileLine(o.rel, nm.Line, "environment variable "+nm.Value+" (literal value present, not stored)"))
		}
	})
}

func (p *project) secretRef(o *k8sObj, name string, line int) {
	if name == "" {
		return
	}
	sk := "secret:k8s:" + name
	p.g.AddNode(sk, "secret_ref", name, "", map[string]any{"source": "Kubernetes Secret"})
	p.g.AddEdge(o.key, "reads", sk, fileLine(o.rel, line, "Secret "+name))
}

// containerForImage returns the container node of an image: a compose
// service with that image, else an image node.
func (p *project) containerForImage(ref string) string {
	name := imageName(ref)
	for k, n := range p.g.nodes {
		if n.Type == "container" && strings.HasPrefix(k, "container:compose:") {
			if img, _ := n.Attrs["image"].(string); img != "" && imageName(img) == name {
				return k
			}
		}
	}
	key := "container:image:" + name
	p.g.AddNode(key, "container", path.Base(name), "", map[string]any{"image": ref, "technology": "container image"})
	if n := p.g.Node(key); n != nil && n.Parent == "" {
		n.Parent = "repository"
	}
	return key
}

// ---------------------------------------------------------------- terraform

var (
	tfResourceRe = regexp.MustCompile(`^\s*resource\s+"([A-Za-z0-9_-]+)"\s+"([A-Za-z0-9_-]+)"`)
	tfAttrRe     = regexp.MustCompile(`^\s*([A-Za-z0-9_]+)\s*=\s*"?([^"\n]*)"?`)
)

var tfServices = map[string]struct{ kind, tech string }{
	"aws_db_instance": {"datastore", ""}, "aws_rds_cluster": {"datastore", ""}, "google_sql_database_instance": {"datastore", ""},
	"azurerm_postgresql_server": {"datastore", "postgresql"}, "azurerm_postgresql_flexible_server": {"datastore", "postgresql"},
	"azurerm_mysql_server": {"datastore", "mysql"}, "azurerm_mssql_server": {"datastore", "sqlserver"},
	"aws_elasticache_cluster": {"datastore", "redis"}, "aws_elasticache_replication_group": {"datastore", "redis"},
	"google_redis_instance": {"datastore", "redis"}, "azurerm_redis_cache": {"datastore", "redis"},
	"aws_dynamodb_table": {"datastore", "dynamodb"}, "aws_s3_bucket": {"datastore", "s3"}, "google_storage_bucket": {"datastore", "s3"},
	"azurerm_storage_account": {"datastore", "s3"}, "aws_docdb_cluster": {"datastore", "mongodb"},
	"aws_sqs_queue": {"queue", "sqs"}, "aws_sns_topic": {"queue", "sns"}, "aws_msk_cluster": {"queue", "kafka"},
	"aws_mq_broker": {"queue", "rabbitmq"}, "google_pubsub_topic": {"queue", "pubsub"}, "azurerm_servicebus_queue": {"queue", "servicebus"},
	"azurerm_servicebus_topic": {"queue", "servicebus"}, "azurerm_eventhub": {"queue", "eventhub"},
}

var tfSecrets = set("aws_secretsmanager_secret", "google_secret_manager_secret", "azurerm_key_vault_secret", "vault_generic_secret",
	"vault_kv_secret_v2", "kubernetes_secret", "aws_ssm_parameter")

func (p *project) extractTerraform() {
	for _, rel := range p.paths {
		if !strings.HasSuffix(rel, ".tf") {
			continue
		}
		data, err := p.read(rel)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		fileKey := ""
		for i := 0; i < len(lines); i++ {
			m := tfResourceRe.FindStringSubmatch(lines[i])
			if m == nil {
				continue
			}
			typ, name, start := m[1], m[2], i+1
			// The block's top-level attributes (brace depth 1).
			attrs := map[string]string{}
			attrLine := map[string]int{}
			depth := strings.Count(lines[i], "{") - strings.Count(lines[i], "}")
			j := i + 1
			for ; j < len(lines) && depth > 0; j++ {
				if depth == 1 {
					if am := tfAttrRe.FindStringSubmatch(lines[j]); am != nil {
						attrs[am[1]] = strings.TrimSpace(am[2])
						attrLine[am[1]] = j + 1
					}
				}
				if strings.Contains(lines[j], "0.0.0.0/0") || strings.Contains(lines[j], "::/0") {
					attrs["_open_cidr"] = "yes"
					attrLine["_open_cidr"] = j + 1
				}
				depth += strings.Count(lines[j], "{") - strings.Count(lines[j], "}")
			}
			if fileKey == "" {
				fileKey = p.fileNode(rel, "")
			}
			key := "iac:tf:" + typ + "." + name
			provider := strings.SplitN(typ, "_", 2)[0]
			if !p.g.AddNode(key, "iac_resource", typ+"."+name, fileKey, map[string]any{"file": rel, "line": start, "end_line": j,
				"technology": "terraform", "provider": provider, "kind": typ}) {
				continue
			}
			ev := fileLine(rel, start, "resource "+typ+"."+name)
			p.g.AddEdge(fileKey, "defines", key, ev)
			if svc, ok := tfServices[typ]; ok {
				tech := svc.tech
				if tech == "" {
					tech = strings.ToLower(attrs["engine"])
					switch {
					case strings.Contains(tech, "postgres"):
						tech = "postgresql"
					case strings.Contains(tech, "mysql"), strings.Contains(tech, "maria"):
						tech = "mysql"
					case strings.Contains(attrs["database_version"], "POSTGRES"):
						tech = "postgresql"
					case strings.Contains(attrs["database_version"], "MYSQL"):
						tech = "mysql"
					case tech == "":
						tech = "sql"
					}
				}
				p.g.AddEdge(p.serviceNode(svc.kind, tech), "deployed_as", key, ev)
			}
			if tfSecrets[typ] {
				sk := "secret:tf:" + typ + "." + name
				p.g.AddNode(sk, "secret_ref", name, "", map[string]any{"source": "Terraform " + typ, "file": rel, "line": start})
				p.g.AddEdge(key, "deployed_as", sk, fileLine(rel, start, typ+" (values not read)"))
			}
			public := (attrs["internal"] == "false" && strings.HasSuffix(typ, "_lb")) || attrs["publicly_accessible"] == "true" ||
				attrs["_open_cidr"] == "yes" && (strings.Contains(typ, "security_group") || strings.Contains(typ, "firewall"))
			if public {
				l := attrLine["_open_cidr"]
				if l == 0 {
					l = attrLine["internal"] + attrLine["publicly_accessible"]
				}
				p.boundary("tb:internet", "Internet")
				p.g.AddEdge(key, "crosses_boundary", "tb:internet", fileLine(rel, l, typ+" open to the internet"))
				if n := p.g.Node(key); n != nil {
					n.Attrs["exposure"] = "internet"
				}
			}
			i = j - 1
		}
	}
}
