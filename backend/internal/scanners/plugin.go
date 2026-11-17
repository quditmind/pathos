package scanners

import "regexp"

// Declarative scanner adapters ("plugins") are defined by the operator in
// files on a worker (see worker.LoadPlugins). Their keys carry their
// category, like imported tools: plugin-<category>-<name>. A plugin key is
// usable once a worker that defines it has registered (the catalog row is
// created then); its output is SARIF.
var pluginKeyRe = regexp.MustCompile(`^plugin-(sast|sca|secrets|iac|container|license|dast|other)-([a-z0-9][a-z0-9-]{0,22})$`)

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
		OutputFormat: "sarif", Notes: "Declarative adapter defined on a worker"}, true
}
