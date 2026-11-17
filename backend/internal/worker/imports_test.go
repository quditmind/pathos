package worker

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestCollectImports(t *testing.T) {
	dir := t.TempDir()
	write := func(p, s string) {
		full := filepath.Join(dir, p)
		_ = os.MkdirAll(filepath.Dir(full), 0o700)
		if err := os.WriteFile(full, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("app.js", `const express = require('express');
import _ from "lodash/fp";
import { x } from '@babel/core/lib/x';
const y = await import("./local");
const fs = require("node:fs");
app.set('view engine', 'ejs');
export { z } from 'zod';`)
	write("node_modules/evil/index.js", `require('should-not-appear')`)
	write("svc/main.py", "import os, yaml\nfrom django.db import models\nfrom . import sibling\nINSTALLED_APPS = ['rest_framework']\n")
	write("cmd/main.go", "package main\n\nimport (\n\t\"fmt\"\n\t\"github.com/gin-gonic/gin/binding\"\n)\n\nimport \"golang.org/x/text/language\"\n\nfunc main() { _ = \"github.com/not/imported\" }\n")
	write("views/layout.ejs", `<script src="/js/jquery-1.8.3.min.js"></script><script src="/node_modules/@popperjs/core/dist/popper.js"></script>
<link href="https://cdn.example/bootstrap.min.css" rel="stylesheet">`)
	inv := collectImports(dir)
	for _, want := range []string{"jquery", "@popperjs/core", "bootstrap"} {
		if !slices.Contains(inv.Strings["npm"], want) {
			t.Errorf("browser asset %s missing: %v", want, inv.Strings["npm"])
		}
	}
	if inv.FilesScanned != 4 {
		t.Errorf("files scanned: %d", inv.FilesScanned)
	}
	for _, want := range []string{"express", "lodash", "@babel/core", "zod"} {
		if !slices.Contains(inv.Imports["npm"], want) {
			t.Errorf("npm import %s missing: %v", want, inv.Imports["npm"])
		}
	}
	for _, not := range []string{"should-not-appear", "fs", "node:fs", ""} {
		if slices.Contains(inv.Imports["npm"], not) {
			t.Errorf("unexpected npm import %q", not)
		}
	}
	if !slices.Contains(inv.Strings["npm"], "ejs") {
		t.Errorf("packages named in strings (view engines) are recorded: %v", inv.Strings["npm"])
	}
	for _, want := range []string{"os", "yaml", "django"} {
		if !slices.Contains(inv.Imports["pypi"], want) {
			t.Errorf("python import %s missing: %v", want, inv.Imports["pypi"])
		}
	}
	if !slices.Contains(inv.Strings["pypi"], "rest_framework") {
		t.Errorf("python string literals: %v", inv.Strings["pypi"])
	}
	if !slices.Equal(inv.Imports["go"], []string{"github.com/gin-gonic/gin/binding", "golang.org/x/text/language"}) {
		t.Errorf("go imports: %v", inv.Imports["go"])
	}
}

func TestJSPackage(t *testing.T) {
	for in, want := range map[string]string{"lodash/fp": "lodash", "@scope/pkg/deep": "@scope/pkg", "./x": "", "/abs": "", "node:path": "",
		"https://cdn.example/x.js": "", "Express": "express", "@scope": ""} {
		if got := jsPackage(in); got != want {
			t.Errorf("%s: %q, want %q", in, got, want)
		}
	}
}

func TestAssetPackages(t *testing.T) {
	for in, want := range map[string][]string{
		"/js/jquery-1.8.3.min.js":                      {"jquery"},
		"/node_modules/moment/min/moment.min.js":       {"moment", "moment"},
		"https://cdn.example/lodash@4.17.21/lodash.js": {"lodash"},
		"/static/app.css?v=3":                          {"app"},
		"/images/logo.png":                             nil,
	} {
		if got := assetPackages(in); !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", in, got, want)
		}
	}
}
