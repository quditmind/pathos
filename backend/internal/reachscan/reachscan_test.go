package reachscan

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func scanFiles(t *testing.T, files map[string]string) *Report {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// uses lists "module:symbol:kind" (plus " test" for test-only uses).
func uses(r *Report) []string {
	var out []string
	for _, u := range r.Uses {
		s := u.Module + ":" + u.Symbol + ":" + u.Kind
		if u.Test {
			s += " test"
		}
		out = append(out, s)
	}
	return out
}

func dynamics(r *Report) []string {
	var out []string
	for _, d := range r.Dynamic {
		out = append(out, d.Module+": "+d.Reason)
	}
	return out
}

func wantUses(t *testing.T, r *Report, want ...string) {
	t.Helper()
	got := uses(r)
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("use %q missing; got %v", w, got)
		}
	}
}

func noUse(t *testing.T, r *Report, prefix string) {
	t.Helper()
	for _, u := range uses(r) {
		if strings.HasPrefix(u, prefix) {
			t.Errorf("unexpected use %q", u)
		}
	}
}

func TestJavaScriptBindings(t *testing.T) {
	r := scanFiles(t, map[string]string{
		"src/a.js": `
import _ from "lodash";
import * as fp from "lodash/fp";
import { merge as deepMerge, get } from "lodash";
import tpl from "lodash/template";
const { escape, unescape: unesc } = require("lodash");
const yaml = require("js-yaml");
const pick = require("lodash").pick;
const ax = await import("axios");

export async function run(x) {
  _.zip(x);
  fp.map(x);
  deepMerge({}, x);
  tpl("x")(x);
  escape(x);
  unesc(x);
  pick(x, "a");
  yaml.load(x);
  [1, 2].map(get);
  const s = new yaml.Schema();
  s.extend([]);
  ax.default.get("/");
}
`,
	})
	wantUses(t, r, "lodash:zip:call", "lodash:fp.map:call", "lodash:merge:call", "lodash:template:call", "lodash:escape:call",
		"lodash:unescape:call", "lodash:pick:call", "js-yaml:load:call", "lodash:get:ref", "js-yaml:Schema:call",
		"js-yaml:Schema.extend:call", "axios:default.get:call")
	if len(r.Dynamic) != 0 {
		t.Errorf("no dynamic constructs expected: %v", dynamics(r))
	}
}

// Re-exports through the repository's own modules: ES modules, export *,
// CommonJS module.exports and index files.
func TestJavaScriptReexports(t *testing.T) {
	r := scanFiles(t, map[string]string{
		"lib/index.ts":   `export * from "./strings";` + "\n" + `export { default as tmpl } from "./tmpl";`,
		"lib/strings.ts": `export { template as compile, capitalize } from "lodash";`,
		"lib/tmpl.js":    `module.exports = require("underscore").template;`,
		"lib/cjs.js":     `const m = require("minimist");` + "\nmodule.exports = { parse: m };",
		"app.tsx": `import { compile, tmpl } from "./lib";
import * as cjs from "./lib/cjs";
function App(): JSX.Element {
  const t = compile("<p>Don't</p>");
  return <div>{tmpl("y")} {cjs.parse(process.argv)}</div>;
}`,
	})
	wantUses(t, r, "lodash:template:call", "underscore:template:call", "minimist:default:call")
	noUse(t, r, "lodash:capitalize")
}

func TestJavaScriptDynamic(t *testing.T) {
	r := scanFiles(t, map[string]string{
		"a.js": `const u = require("underscore");
const name = process.env.MOD;
const m = require(name);
function f(op) { return u[op]("x"); }
register(u);
u["template"]("literal is fine");
`,
	})
	d := dynamics(r)
	for _, w := range []string{": require() of a computed module name", "underscore: member selected by a computed name",
		"underscore: the module is passed around as a value"} {
		if !slices.Contains(d, w) {
			t.Errorf("dynamic %q missing: %v", w, d)
		}
	}
	wantUses(t, r, "underscore:template:call")
}

func TestPythonBindings(t *testing.T) {
	r := scanFiles(t, map[string]string{
		"pkg/__init__.py": "from .helpers import load_all\n",
		"pkg/helpers.py":  "import yaml\nfrom yaml import load_all\n",
		"app/main.py": `import os.path
import xml.etree.ElementTree as ET
import jinja2.sandbox
from jinja2 import Environment, Template as T
from pkg import load_all
from requests import *
import importlib

lxml = importlib.import_module("lxml.etree")

class Renderer:
    def __init__(self, src):
        self.tpl = T(src)

    def render(self, **kw):
        return self.tpl.render(**kw)

def main(path):
    env = jinja2.sandbox.SandboxedEnvironment()
    env.from_string("{{ x }}")
    for doc in load_all(open(path)):
        print(f"{ET.fromstring(doc)!r}")
    get("https://example.invalid")
    lxml.parse(path)
    with Environment() as e:
        e.compile("x")
`,
		"tests/test_main.py": "import yaml\n\ndef test_x():\n    yaml.safe_load('a: 1')\n",
	})
	wantUses(t, r, "jinja2:sandbox.SandboxedEnvironment:call", "jinja2:Template.render:call", "jinja2:Template:call",
		"yaml:load_all:call", "requests:get:call", "lxml:etree.parse:call", "xml:etree.ElementTree.fromstring:call",
		"jinja2:Environment.compile:call", "jinja2:sandbox.SandboxedEnvironment.from_string:call", "yaml:safe_load:call test")
	noUse(t, r, "requests:print")
	noUse(t, r, "pkg:")
}

func TestPythonDynamic(t *testing.T) {
	r := scanFiles(t, map[string]string{
		"a.py": `import importlib
import requests
import yaml

def f(name, url):
    getattr(requests, name)(url)
    getattr(yaml, "load")(url)
    importlib.import_module(name)
    handlers = {"y": yaml}
    eval(name)
`,
	})
	d := dynamics(r)
	for _, w := range []string{"requests: member selected by a computed name", ": importlib.import_module() of a computed module name",
		"yaml: the module is passed around as a value", ": eval()"} {
		if !slices.Contains(d, w) {
			t.Errorf("dynamic %q missing: %v", w, d)
		}
	}
	wantUses(t, r, "yaml:load:call")
	// a subscript indexes a value: not a dynamic member
	r = scanFiles(t, map[string]string{"b.py": "import sys\nprint(sys.argv[1])\n"})
	if len(r.Dynamic) != 0 {
		t.Errorf("subscript is not dynamic: %v", dynamics(r))
	}
}

func TestJavaBindings(t *testing.T) {
	r := scanFiles(t, map[string]string{
		"src/main/java/com/example/A.java": `package com.example;

import java.util.*;
import org.apache.commons.text.StringSubstitutor;
import org.yaml.snakeyaml.*;
import static org.apache.commons.lang3.StringUtils.isBlank;

public class A {
    private StringSubstitutor sub;
    private String name;

    public A(Map<String, String> values) throws Exception {
        this.sub = new StringSubstitutor(values);
    }

    String run(String in) {
        Yaml y = new Yaml();
        Object o = y.load(in);
        var x = new StringSubstitutor();
        x.setEnableSubstitutionInVariables(true);
        if (isBlank(in)) { return name.replace("a", "b"); }
        com.fasterxml.jackson.databind.ObjectMapper.class.getName();
        return this.sub.replace(in) + org.apache.commons.io.FileUtils.readFileToString(null);
    }
}`,
	})
	wantUses(t, r, "org.apache.commons.text:StringSubstitutor:call", "org.apache.commons.text:StringSubstitutor.replace:call",
		"org.apache.commons.text:StringSubstitutor.setEnableSubstitutionInVariables:call", "org.yaml.snakeyaml:Yaml:call",
		"org.yaml.snakeyaml:Yaml.load:call", "org.apache.commons.lang3:StringUtils.isBlank:call",
		"org.apache.commons.io:FileUtils.readFileToString:call")
	// name is a String: its replace is not an untyped method call
	for _, m := range r.Methods {
		if m.Name == "replace" {
			t.Errorf("typed String.replace reported as untyped: %+v", m)
		}
	}
}

func TestJavaReflection(t *testing.T) {
	r := scanFiles(t, map[string]string{
		"P.java": `class P {
  Object a(String c) throws Exception { return Class.forName(c); }
  Object b() throws Exception { return Class.forName("org.apache.commons.text.StringSubstitutor"); }
  Object m(Class<?> k) throws Exception { return k.getMethod("replace", String.class); }
}`,
	})
	if d := dynamics(r); !slices.Contains(d, ": Class.forName() with a computed class name") || len(d) != 1 {
		t.Errorf("dynamic: %v", d)
	}
	wantUses(t, r, "org.apache.commons.text:StringSubstitutor:ref")
	if !slices.ContainsFunc(r.Methods, func(m MethodUse) bool { return m.Name == "replace" }) {
		t.Errorf("getMethod(\"replace\") is a method use: %+v", r.Methods)
	}
}

func TestGoReflection(t *testing.T) {
	r := scanFiles(t, map[string]string{
		"cmd/a/main.go": "package main\n\nimport (\n\t\"reflect\"\n\tx \"golang.org/x/text/unicode/norm\"\n)\n\nfunc main() { reflect.ValueOf(x.NFC).MethodByName(\"String\") }\n",
		"cmd/b/main.go": "package main\n\nimport \"golang.org/x/text/language\"\n\nfunc main() { language.Make(\"en\") }\n",
	})
	if d := dynamics(r); len(d) != 1 || d[0] != "golang.org/x/text/unicode/norm: methods called through reflect (MethodByName)" {
		t.Errorf("dynamic: %v", d)
	}
	if len(r.Imports) != 2 {
		t.Errorf("imports: %+v", r.Imports)
	}
}

// Call paths go from a function nobody calls to the call site.
func TestCallPaths(t *testing.T) {
	r := scanFiles(t, map[string]string{
		"a.py": "import yaml\n\ndef parse(s):\n    return yaml.load(s)\n\ndef handler(req):\n    return parse(req.body)\n\ndef route():\n    return handler(None)\n",
	})
	for _, u := range r.Uses {
		if u.Symbol == "load" {
			if len(u.Paths) != 1 {
				t.Fatalf("paths: %+v", u.Paths)
			}
			var fns []string
			for _, f := range u.Paths[0] {
				fns = append(fns, f.Function)
			}
			if strings.Join(fns, ">") != "route>handler>parse" {
				t.Errorf("path %v", fns)
			}
			return
		}
	}
	t.Fatal("yaml.load not found")
}

func TestLexers(t *testing.T) {
	js := lexJS("const a = `x ${f(`y`)} z`; const r = /ab'c/g; // it's\nb('s');")
	var ids []string
	for _, tk := range js {
		if tk.kind == tIdent {
			ids = append(ids, tk.text)
		}
	}
	if strings.Join(ids, ",") != "const,a,f,const,r,b" {
		t.Errorf("js idents %v", ids)
	}
	py := lexPython("x = '''a\nb'''\nif y:\n    z(f\"{w(1)}\")\n")
	var lines []int
	for _, tk := range py {
		if tk.kind == tIdent && (tk.text == "w" || tk.text == "z") {
			lines = append(lines, tk.line)
		}
	}
	if !slices.Equal(lines, []int{4, 4}) {
		t.Errorf("python lines %v", lines)
	}
	java := lexJava("String s = \"\"\"\n  a \"b\"\n\"\"\"; char c = '\\''; f();")
	if last := java[len(java)-4]; last.text != "f" || last.line != 3 {
		t.Errorf("java token %+v", last)
	}
}

func TestTestPaths(t *testing.T) {
	for _, p := range []string{"src/test/java/x/AT.java", "a/tests/x.py", "test_x.py", "x_test.py", "a.spec.ts", "a.test.js", "__tests__/a.js", "XTest.java"} {
		if !isTestPath(p) {
			t.Errorf("%s is a test", p)
		}
	}
	for _, p := range []string{"src/main/java/x/A.java", "app/latest.py", "contest.js"} {
		if isTestPath(p) {
			t.Errorf("%s is not a test", p)
		}
	}
}
