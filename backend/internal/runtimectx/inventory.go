package runtimectx

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// --- Kubernetes object subset ---------------------------------------------

type objectMeta struct {
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace"`
	Labels          map[string]string `json:"labels"`
	Annotations     map[string]string `json:"annotations"`
	OwnerReferences []struct {
		Kind       string `json:"kind"`
		Name       string `json:"name"`
		Controller *bool  `json:"controller"`
	} `json:"ownerReferences"`
}

// controller returns the controlling owner (kind, name).
func (m objectMeta) controller() (string, string) {
	for _, o := range m.OwnerReferences {
		if o.Controller != nil && *o.Controller {
			return o.Kind, o.Name
		}
	}
	if len(m.OwnerReferences) == 1 {
		return m.OwnerReferences[0].Kind, m.OwnerReferences[0].Name
	}
	return "", ""
}

type securityContext struct {
	Privileged   *bool  `json:"privileged"`
	RunAsUser    *int64 `json:"runAsUser"`
	RunAsNonRoot *bool  `json:"runAsNonRoot"`
}

type containerSpec struct {
	Name            string           `json:"name"`
	Image           string           `json:"image"`
	SecurityContext *securityContext `json:"securityContext"`
}

type podSpec struct {
	Containers      []containerSpec  `json:"containers"`
	InitContainers  []containerSpec  `json:"initContainers"`
	HostNetwork     bool             `json:"hostNetwork"`
	HostPID         bool             `json:"hostPID"`
	SecurityContext *securityContext `json:"securityContext"`
}

type podTemplate struct {
	Metadata objectMeta `json:"metadata"`
	Spec     podSpec    `json:"spec"`
}

type labelSelector struct {
	MatchLabels      map[string]string `json:"matchLabels"`
	MatchExpressions []struct {
		Key      string   `json:"key"`
		Operator string   `json:"operator"`
		Values   []string `json:"values"`
	} `json:"matchExpressions"`
}

// matches evaluates a label selector (an empty selector matches all).
func (s labelSelector) matches(labels map[string]string) bool {
	for k, v := range s.MatchLabels {
		if labels[k] != v {
			return false
		}
	}
	for _, e := range s.MatchExpressions {
		v, ok := labels[e.Key]
		switch e.Operator {
		case "In":
			if !ok || !slices.Contains(e.Values, v) {
				return false
			}
		case "NotIn":
			if ok && slices.Contains(e.Values, v) {
				return false
			}
		case "Exists":
			if !ok {
				return false
			}
		case "DoesNotExist":
			if ok {
				return false
			}
		default:
			return false
		}
	}
	return true
}

type controllerObj struct {
	Metadata objectMeta `json:"metadata"`
	Spec     struct {
		Replicas    *int        `json:"replicas"`
		Template    podTemplate `json:"template"`
		JobTemplate struct {
			Spec struct {
				Template podTemplate `json:"template"`
			} `json:"spec"`
		} `json:"jobTemplate"`
	} `json:"spec"`
	Status struct {
		Replicas               *int  `json:"replicas"`
		ReadyReplicas          *int  `json:"readyReplicas"`
		DesiredNumberScheduled *int  `json:"desiredNumberScheduled"`
		NumberReady            *int  `json:"numberReady"`
		Active                 []any `json:"active"`
	} `json:"status"`
}

type containerStatus struct {
	Name    string `json:"name"`
	Image   string `json:"image"`
	ImageID string `json:"imageID"`
}

type podObj struct {
	Metadata objectMeta `json:"metadata"`
	Spec     podSpec    `json:"spec"`
	Status   struct {
		Phase                 string            `json:"phase"`
		ContainerStatuses     []containerStatus `json:"containerStatuses"`
		InitContainerStatuses []containerStatus `json:"initContainerStatuses"`
	} `json:"status"`
}

type lbStatus struct {
	Ingress []struct {
		IP       string `json:"ip"`
		Hostname string `json:"hostname"`
	} `json:"ingress"`
}

type serviceObj struct {
	Metadata objectMeta `json:"metadata"`
	Spec     struct {
		Type     string            `json:"type"`
		Selector map[string]string `json:"selector"`
		Ports    []struct {
			Name     string `json:"name"`
			Port     int    `json:"port"`
			NodePort int    `json:"nodePort"`
			Protocol string `json:"protocol"`
		} `json:"ports"`
		ExternalIPs              []string `json:"externalIPs"`
		LoadBalancerSourceRanges []string `json:"loadBalancerSourceRanges"`
		LoadBalancerClass        *string  `json:"loadBalancerClass"`
	} `json:"spec"`
	Status struct {
		LoadBalancer lbStatus `json:"loadBalancer"`
	} `json:"status"`
}

type ingressBackend struct {
	Service *struct {
		Name string `json:"name"`
		Port struct {
			Number int    `json:"number"`
			Name   string `json:"name"`
		} `json:"port"`
	} `json:"service"`
}

type ingressObj struct {
	Metadata objectMeta `json:"metadata"`
	Spec     struct {
		IngressClassName *string         `json:"ingressClassName"`
		DefaultBackend   *ingressBackend `json:"defaultBackend"`
		TLS              []struct {
			Hosts []string `json:"hosts"`
		} `json:"tls"`
		Rules []struct {
			Host string `json:"host"`
			HTTP *struct {
				Paths []struct {
					Path    string         `json:"path"`
					Backend ingressBackend `json:"backend"`
				} `json:"paths"`
			} `json:"http"`
		} `json:"rules"`
	} `json:"spec"`
	Status struct {
		LoadBalancer lbStatus `json:"loadBalancer"`
	} `json:"status"`
}

type networkPolicyObj struct {
	Metadata objectMeta `json:"metadata"`
	Spec     struct {
		PodSelector labelSelector     `json:"podSelector"`
		PolicyTypes []string          `json:"policyTypes"`
		Ingress     []json.RawMessage `json:"ingress"`
		Egress      []json.RawMessage `json:"egress"`
	} `json:"spec"`
}

// --- inventory -------------------------------------------------------------

// Exposure is one way a workload can be reached from outside the cluster.
type Exposure struct {
	Via      string `json:"via"` // ingress | loadbalancer | nodeport | external_ip
	Service  string `json:"service"`
	Ingress  string `json:"ingress,omitempty"`
	Host     string `json:"host,omitempty"`
	Path     string `json:"path,omitempty"`
	Address  string `json:"address,omitempty"`
	Internet bool   `json:"internet"`
	Detail   string `json:"detail"`
}

// ContainerImage is one container's image in a workload (one entry per
// running digest).
type ContainerImage struct {
	Container string   `json:"container"`
	Init      bool     `json:"init"`
	Image     string   `json:"image"`
	Ref       ImageRef `json:"ref"`
}

// Workload is a controller (or a bare pod) with what PATHOS needs to know.
type Workload struct {
	Namespace       string            `json:"namespace"`
	Kind            string            `json:"kind"`
	Name            string            `json:"name"`
	Labels          map[string]string `json:"labels"`
	Replicas        *int              `json:"replicas"`
	Ready           *int              `json:"ready_replicas"`
	PodNames        []string          `json:"pod_names"`
	Privileged      bool              `json:"privileged"`
	HostNetwork     bool              `json:"host_network"`
	HostPID         bool              `json:"host_pid"`
	RunAsRoot       string            `json:"run_as_root"`
	Images          []ContainerImage  `json:"images"`
	Exposure        []Exposure        `json:"exposure"`
	InternetExposed bool              `json:"internet_exposed"`
	NetworkPolicies []string          `json:"network_policies"`
}

// Key identifies a workload in a cluster.
func (w Workload) Key() string { return w.Namespace + "/" + w.Kind + "/" + w.Name }

// NetworkObject is a Service, Ingress or NetworkPolicy summary.
type NetworkObject struct {
	Kind      string         `json:"kind"`
	Namespace string         `json:"namespace"`
	Name      string         `json:"name"`
	Data      map[string]any `json:"data"`
}

// Namespace is a namespace with its labels.
type Namespace struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
}

// Inventory is the processed content of one cluster.
type Inventory struct {
	Namespaces []Namespace
	Workloads  []Workload
	Network    []NetworkObject
	// Skipped counts objects that could not be decoded.
	Skipped int
}

// internalLBAnnotations mark cloud load balancers that are not public.
var internalLBAnnotations = map[string][]string{
	"service.beta.kubernetes.io/aws-load-balancer-internal":          {"true", "0.0.0.0/0"},
	"service.beta.kubernetes.io/aws-load-balancer-scheme":            {"internal"},
	"service.beta.kubernetes.io/azure-load-balancer-internal":        {"true"},
	"networking.gke.io/load-balancer-type":                           {"internal"},
	"cloud.google.com/load-balancer-type":                            {"internal"},
	"service.beta.kubernetes.io/oci-load-balancer-internal":          {"true"},
	"service.beta.kubernetes.io/openstack-internal-load-balancer":    {"true"},
	"service.beta.kubernetes.io/do-loadbalancer-internal":            {"true"},
	"service.kubernetes.io/ibm-load-balancer-cloud-provider-ip-type": {"private"},
}

// internalMarker returns the annotation that makes a load balancer
// internal ("" if none).
func internalMarker(ann map[string]string) string {
	for k, vals := range internalLBAnnotations {
		if v, ok := ann[k]; ok && slices.Contains(vals, strings.ToLower(strings.TrimSpace(v))) {
			return k + "=" + v
		}
	}
	return ""
}

func digestOf(imageID string) string {
	if r, ok := ParseImageRef(imageID); ok {
		return r.Digest
	}
	// "sha256:..." without a name.
	if i := strings.LastIndex(imageID, "sha256:"); i >= 0 && ValidDigest(imageID[i:]) {
		return imageID[i:]
	}
	return ""
}

func limitLabels(m map[string]string) map[string]string {
	out := map[string]string{}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if len(out) >= 64 || len(k) > 317 {
			continue
		}
		v := m[k]
		if len(v) > 63 {
			v = v[:63]
		}
		out[k] = v
	}
	return out
}

func decodeAll[T any](items []json.RawMessage, skipped *int) []T {
	out := make([]T, 0, len(items))
	for _, it := range items {
		var v T
		if err := json.Unmarshal(it, &v); err != nil {
			*skipped++
			continue
		}
		out = append(out, v)
	}
	return out
}

// runAsRoot evaluates the effective user of every container: yes when one
// runs as UID 0, no when all set runAsNonRoot or a non-zero runAsUser,
// unknown otherwise (the image's USER decides).
func runAsRoot(spec podSpec) string {
	all := append(append([]containerSpec{}, spec.InitContainers...), spec.Containers...)
	if len(all) == 0 {
		return "unknown"
	}
	verdict := "no"
	for _, c := range all {
		var uid *int64
		var nonRoot *bool
		if spec.SecurityContext != nil {
			uid, nonRoot = spec.SecurityContext.RunAsUser, spec.SecurityContext.RunAsNonRoot
		}
		if c.SecurityContext != nil {
			if c.SecurityContext.RunAsUser != nil {
				uid = c.SecurityContext.RunAsUser
			}
			if c.SecurityContext.RunAsNonRoot != nil {
				nonRoot = c.SecurityContext.RunAsNonRoot
			}
		}
		switch {
		case uid != nil && *uid == 0:
			return "yes"
		case uid != nil && *uid > 0, nonRoot != nil && *nonRoot:
		default:
			verdict = "unknown"
		}
	}
	return verdict
}

func privileged(spec podSpec) bool {
	for _, c := range append(append([]containerSpec{}, spec.InitContainers...), spec.Containers...) {
		if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			return true
		}
	}
	return false
}

func intp(v int) *int { return &v }

// Build turns the raw objects of a cluster into workloads with images,
// digests, exposure and security context.
func Build(raw Raw) Inventory {
	var inv Inventory
	for _, n := range decodeAll[struct {
		Metadata objectMeta `json:"metadata"`
	}](raw["Namespace"], &inv.Skipped) {
		if n.Metadata.Name != "" {
			inv.Namespaces = append(inv.Namespaces, Namespace{Name: n.Metadata.Name, Labels: limitLabels(n.Metadata.Labels)})
		}
	}

	type wl struct {
		w    *Workload
		spec podSpec
	}
	byKey := map[string]*wl{}
	var order []string
	addWorkload := func(kind string, o controllerObj, tpl podTemplate) {
		m := o.Metadata
		if m.Name == "" || m.Namespace == "" {
			inv.Skipped++
			return
		}
		w := &Workload{Namespace: m.Namespace, Kind: kind, Name: m.Name, Labels: limitLabels(tpl.Metadata.Labels)}
		switch kind {
		case "Deployment", "StatefulSet":
			w.Replicas, w.Ready = o.Spec.Replicas, o.Status.ReadyReplicas
			if w.Replicas == nil {
				w.Replicas = intp(1)
			}
			if w.Ready == nil {
				w.Ready = intp(0)
			}
		case "DaemonSet":
			w.Replicas, w.Ready = o.Status.DesiredNumberScheduled, o.Status.NumberReady
		case "CronJob":
			w.Ready = intp(len(o.Status.Active))
		}
		k := w.Key()
		if _, dup := byKey[k]; !dup {
			order = append(order, k)
		}
		byKey[k] = &wl{w: w, spec: tpl.Spec}
	}
	for _, kind := range []string{"Deployment", "StatefulSet", "DaemonSet"} {
		for _, o := range decodeAll[controllerObj](raw[kind], &inv.Skipped) {
			addWorkload(kind, o, o.Spec.Template)
		}
	}
	for _, o := range decodeAll[controllerObj](raw["CronJob"], &inv.Skipped) {
		addWorkload("CronJob", o, o.Spec.JobTemplate.Spec.Template)
	}
	// ReplicaSet → Deployment and Job → CronJob ownership.
	rsOwner := map[string]string{}
	for _, o := range decodeAll[controllerObj](raw["ReplicaSet"], &inv.Skipped) {
		if k, n := o.Metadata.controller(); k == "Deployment" {
			rsOwner[o.Metadata.Namespace+"/"+o.Metadata.Name] = n
		}
	}
	jobOwner := map[string]string{}
	for _, o := range decodeAll[controllerObj](raw["Job"], &inv.Skipped) {
		if k, n := o.Metadata.controller(); k == "CronJob" {
			jobOwner[o.Metadata.Namespace+"/"+o.Metadata.Name] = n
			continue
		}
		addWorkload("Job", o, o.Spec.Template)
	}

	// Pods: attach to their workload (digests of running containers, pod
	// names); pods without a known controller are workloads themselves.
	for _, p := range decodeAll[podObj](raw["Pod"], &inv.Skipped) {
		m := p.Metadata
		if m.Name == "" || m.Namespace == "" {
			inv.Skipped++
			continue
		}
		kind, name := m.controller()
		switch kind {
		case "ReplicaSet":
			if d, ok := rsOwner[m.Namespace+"/"+name]; ok {
				kind, name = "Deployment", d
			}
		case "Job":
			if c, ok := jobOwner[m.Namespace+"/"+name]; ok {
				kind, name = "CronJob", c
			}
		}
		e, ok := byKey[m.Namespace+"/"+kind+"/"+name]
		if !ok {
			// Bare pods, static pods (owner Node) and pods of controllers
			// PATHOS does not model.
			w := &Workload{Namespace: m.Namespace, Kind: "Pod", Name: m.Name, Labels: limitLabels(m.Labels)}
			ready := 0
			if p.Status.Phase == "Running" {
				ready = 1
			}
			w.Replicas, w.Ready = intp(1), intp(ready)
			e = &wl{w: w, spec: p.Spec}
			k := w.Key()
			if _, dup := byKey[k]; !dup {
				order = append(order, k)
			}
			byKey[k] = e
		}
		if len(e.w.PodNames) < 500 {
			e.w.PodNames = append(e.w.PodNames, m.Name)
		}
		// Running digests by container (one image entry per digest).
		for _, set := range []struct {
			init bool
			st   []containerStatus
		}{{false, p.Status.ContainerStatuses}, {true, p.Status.InitContainerStatuses}} {
			for _, cs := range set.st {
				d := digestOf(cs.ImageID)
				if d == "" {
					continue
				}
				img := specImage(e.spec, cs.Name)
				if img == "" {
					img = cs.Image
				}
				ref, ok := ParseImageRef(img)
				if !ok {
					continue
				}
				ref.Digest = d
				addImage(e.w, ContainerImage{Container: cs.Name, Init: set.init, Image: img, Ref: ref})
			}
		}
	}

	// Template images without a running digest (scaled to zero, idle
	// CronJobs, pending pods): the reference alone (digest only if pinned).
	for _, k := range order {
		e := byKey[k]
		for _, set := range []struct {
			init bool
			cs   []containerSpec
		}{{false, e.spec.Containers}, {true, e.spec.InitContainers}} {
			for _, c := range set.cs {
				if hasContainer(e.w, c.Name) {
					continue
				}
				if ref, ok := ParseImageRef(c.Image); ok {
					addImage(e.w, ContainerImage{Container: c.Name, Init: set.init, Image: c.Image, Ref: ref})
				}
			}
		}
		e.w.Privileged = privileged(e.spec)
		e.w.HostNetwork, e.w.HostPID = e.spec.HostNetwork, e.spec.HostPID
		e.w.RunAsRoot = runAsRoot(e.spec)
	}

	// Services → workloads (selector ⊆ pod template labels, same namespace).
	services := decodeAll[serviceObj](raw["Service"], &inv.Skipped)
	svcTargets := map[string][]*Workload{} // ns/name → workloads
	for _, s := range services {
		sk := s.Metadata.Namespace + "/" + s.Metadata.Name
		if len(s.Spec.Selector) > 0 {
			for _, k := range order {
				w := byKey[k].w
				if w.Namespace == s.Metadata.Namespace && (labelSelector{MatchLabels: s.Spec.Selector}).matches(w.Labels) {
					svcTargets[sk] = append(svcTargets[sk], w)
				}
			}
		}
		var ports []string
		for _, p := range s.Spec.Ports {
			if p.NodePort > 0 {
				ports = append(ports, fmt.Sprintf("%d→node %d", p.Port, p.NodePort))
			} else {
				ports = append(ports, fmt.Sprint(p.Port))
			}
		}
		addrs := lbAddresses(s.Status.LoadBalancer)
		data := map[string]any{"type": firstNonEmpty(s.Spec.Type, "ClusterIP"), "selector": s.Spec.Selector, "ports": ports}
		if len(addrs) > 0 {
			data["load_balancer"] = addrs
		}
		if m := internalMarker(s.Metadata.Annotations); m != "" {
			data["internal_annotation"] = m
		}
		if len(s.Spec.ExternalIPs) > 0 {
			data["external_ips"] = s.Spec.ExternalIPs
		}
		if len(s.Spec.LoadBalancerSourceRanges) > 0 {
			data["source_ranges"] = s.Spec.LoadBalancerSourceRanges
		}
		inv.Network = append(inv.Network, NetworkObject{Kind: "Service", Namespace: s.Metadata.Namespace, Name: s.Metadata.Name, Data: data})

		for _, w := range svcTargets[sk] {
			switch s.Spec.Type {
			case "LoadBalancer":
				x := Exposure{Via: "loadbalancer", Service: s.Metadata.Name, Address: strings.Join(addrs, ", "), Internet: true}
				switch m := internalMarker(s.Metadata.Annotations); {
				case m != "":
					x.Internet = false
					x.Detail = "internal load balancer (" + m + ")"
				case len(s.Spec.LoadBalancerSourceRanges) > 0 && !slices.Contains(s.Spec.LoadBalancerSourceRanges, "0.0.0.0/0"):
					x.Detail = "load balancer restricted to " + strings.Join(s.Spec.LoadBalancerSourceRanges, ", ")
				case len(addrs) == 0:
					x.Detail = "LoadBalancer Service (no address assigned yet)"
				default:
					x.Detail = "LoadBalancer Service at " + strings.Join(addrs, ", ")
				}
				addExposure(w, x)
			case "NodePort":
				addExposure(w, Exposure{Via: "nodeport", Service: s.Metadata.Name, Address: strings.Join(ports, ", "),
					Detail: "NodePort Service: reachable from outside the cluster wherever the nodes are reachable (not counted as internet exposure)"})
			}
			if len(s.Spec.ExternalIPs) > 0 {
				addExposure(w, Exposure{Via: "external_ip", Service: s.Metadata.Name, Address: strings.Join(s.Spec.ExternalIPs, ", "),
					Detail: "Service with externalIPs (not counted as internet exposure)"})
			}
		}
	}

	// Ingresses → Services → workloads.
	for _, ing := range decodeAll[ingressObj](raw["Ingress"], &inv.Skipped) {
		ns, name := ing.Metadata.Namespace, ing.Metadata.Name
		class := ""
		if ing.Spec.IngressClassName != nil {
			class = *ing.Spec.IngressClassName
		} else if c := ing.Metadata.Annotations["kubernetes.io/ingress.class"]; c != "" {
			class = c
		}
		internal := ""
		switch {
		case strings.Contains(strings.ToLower(class), "internal"):
			internal = "ingress class " + class
		case strings.EqualFold(ing.Metadata.Annotations["alb.ingress.kubernetes.io/scheme"], "internal"):
			internal = "alb.ingress.kubernetes.io/scheme=internal"
		}
		tlsHosts := map[string]bool{}
		for _, t := range ing.Spec.TLS {
			for _, h := range t.Hosts {
				tlsHosts[h] = true
			}
		}
		addrs := lbAddresses(ing.Status.LoadBalancer)
		var hosts []string
		expose := func(host, path string, b ingressBackend) {
			if b.Service == nil || b.Service.Name == "" {
				return
			}
			for _, w := range svcTargets[ns+"/"+b.Service.Name] {
				x := Exposure{Via: "ingress", Service: b.Service.Name, Ingress: name, Host: host, Path: path, Address: strings.Join(addrs, ", "), Internet: internal == ""}
				scheme := "http"
				if tlsHosts[host] {
					scheme = "https"
				}
				switch {
				case internal != "":
					x.Detail = "internal Ingress (" + internal + ")"
				case host == "":
					x.Detail = "Ingress " + name + " without a host (every host name of the ingress controller)"
				default:
					x.Detail = fmt.Sprintf("Ingress %s routes %s://%s%s", name, scheme, host, path)
				}
				addExposure(w, x)
			}
		}
		if ing.Spec.DefaultBackend != nil {
			expose("", "", *ing.Spec.DefaultBackend)
		}
		for _, r := range ing.Spec.Rules {
			if r.Host != "" && !slices.Contains(hosts, r.Host) {
				hosts = append(hosts, r.Host)
			}
			if r.HTTP == nil {
				continue
			}
			for _, p := range r.HTTP.Paths {
				expose(r.Host, p.Path, p.Backend)
			}
		}
		data := map[string]any{"class": class, "hosts": hosts}
		if internal != "" {
			data["internal"] = internal
		}
		if len(addrs) > 0 {
			data["load_balancer"] = addrs
		}
		inv.Network = append(inv.Network, NetworkObject{Kind: "Ingress", Namespace: ns, Name: name, Data: data})
	}

	// NetworkPolicies that select each workload (evidence only).
	for _, np := range decodeAll[networkPolicyObj](raw["NetworkPolicy"], &inv.Skipped) {
		types := np.Spec.PolicyTypes
		if len(types) == 0 {
			types = []string{"Ingress"}
		}
		data := map[string]any{"policy_types": types, "pod_selector": np.Spec.PodSelector.MatchLabels,
			"ingress_rules": len(np.Spec.Ingress), "egress_rules": len(np.Spec.Egress)}
		inv.Network = append(inv.Network, NetworkObject{Kind: "NetworkPolicy", Namespace: np.Metadata.Namespace, Name: np.Metadata.Name, Data: data})
		for _, k := range order {
			w := byKey[k].w
			if w.Namespace == np.Metadata.Namespace && np.Spec.PodSelector.matches(w.Labels) && len(w.NetworkPolicies) < 200 {
				w.NetworkPolicies = append(w.NetworkPolicies, np.Metadata.Name)
			}
		}
	}

	for _, k := range order {
		w := byKey[k].w
		for _, x := range w.Exposure {
			w.InternetExposed = w.InternetExposed || x.Internet
		}
		if w.PodNames == nil {
			w.PodNames = []string{}
		}
		if w.NetworkPolicies == nil {
			w.NetworkPolicies = []string{}
		}
		if w.Exposure == nil {
			w.Exposure = []Exposure{}
		}
		inv.Workloads = append(inv.Workloads, *w)
	}
	return inv
}

func specImage(spec podSpec, container string) string {
	for _, c := range append(append([]containerSpec{}, spec.Containers...), spec.InitContainers...) {
		if c.Name == container {
			return c.Image
		}
	}
	return ""
}

func hasContainer(w *Workload, name string) bool {
	for _, i := range w.Images {
		if i.Container == name {
			return true
		}
	}
	return false
}

func addImage(w *Workload, ci ContainerImage) {
	for _, i := range w.Images {
		if i.Container == ci.Container && i.Image == ci.Image && i.Ref.Digest == ci.Ref.Digest {
			return
		}
	}
	if len(w.Images) < 200 {
		w.Images = append(w.Images, ci)
	}
}

func addExposure(w *Workload, x Exposure) {
	for _, e := range w.Exposure {
		if e == x {
			return
		}
	}
	if len(w.Exposure) < 100 {
		w.Exposure = append(w.Exposure, x)
	}
}

func lbAddresses(s lbStatus) []string {
	var out []string
	for _, i := range s.Ingress {
		if a := firstNonEmpty(i.Hostname, i.IP); a != "" {
			out = append(out, a)
		}
	}
	return out
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
