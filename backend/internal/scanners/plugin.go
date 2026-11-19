package scanners

import (
	"regexp"
	"slices"
	"strings"
)

// Declarative scanner adapters ("plugins") are defined by the operator in
// files on a worker (see worker.LoadPlugins). Their keys carry their
// category, like imported tools: plugin-<category>-<name>. A plugin key is
// usable once a worker that defines it has registered (the catalog row is
// created then); its output is SARIF unless its definition names another
// parser (see ToolParser).
var pluginKeyRe = regexp.MustCompile(`^plugin-(` + strings.Join(ToolCategories, "|") + `)-([a-z0-9][a-z0-9-]{0,22})$`)

// ToolCategories are the categories a declarative adapter or an imported
// tool may declare: every finding category except eol (end-of-life
// findings come from the intelligence feed only). Migration 00029 lists
// the same values in the registration functions' key patterns.
var ToolCategories = slices.DeleteFunc(slices.Clone(FindingCategories), func(c string) bool { return c == "eol" })

// IsPluginKey reports whether key names a declarative adapter.
func IsPluginKey(key string) bool { return pluginKeyRe.MatchString(key) }

// PluginKey builds the key of a plugin.
func PluginKey(category, name string) string { return "plugin-" + category + "-" + name }

// ResolvePlugin returns the synthetic catalog entry of a plugin key.
func ResolvePlugin(key string) (Scanner, bool) {
	m := pluginKeyRe.FindStringSubmatch(key)
	if m == nil {
		return Scanner{}, false
	}
	return Scanner{Key: key, Name: m[2] + " (plugin)", Category: m[1], Decision: "use", Family: "plugin", AdapterAvailable: true,
		OutputFormat: "sarif", Network: "none", Notes: "Declarative adapter defined on a worker"}, true
}

// ManifestRouted reports whether key is run by a tool manifest (an
// operator plugin or a first-party manifest of a family worker image)
// rather than by the core worker's built-in adapters. Scan jobs that use
// such a tool go to the workers that advertise it.
func ManifestRouted(key string) bool {
	if IsPluginKey(key) {
		return true
	}
	sc, ok := Lookup(key)
	return ok && sc.Family != "core" && sc.Family != "intel"
}

// RoutedCatalogKeys lists the catalog keys that ManifestRouted accepts.
func RoutedCatalogKeys() []string {
	var out []string
	for _, sc := range Catalog {
		if ManifestRouted(sc.Key) {
			out = append(out, sc.Key)
		}
	}
	return out
}
