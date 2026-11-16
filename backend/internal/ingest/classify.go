package ingest

import (
	"path"
	"strings"
)

// MaxManifests caps Result.Manifests.
const MaxManifests = 500

var languageByExt = map[string]string{
	".go":   "Go",
	".java": "Java",
	".kt":   "Kotlin", ".kts": "Kotlin",
	".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
	".ts": "TypeScript", ".tsx": "TypeScript", ".mts": "TypeScript", ".cts": "TypeScript",
	".py": "Python", ".pyi": "Python", ".pyw": "Python",
	".cs": "C#",
	".c":  "C", ".h": "C",
	".cc": "C++", ".cpp": "C++", ".cxx": "C++", ".c++": "C++", ".hh": "C++", ".hpp": "C++", ".hxx": "C++",
	".php": "PHP",
	".rb":  "Ruby", ".rake": "Ruby", ".gemspec": "Ruby",
	".rs":    "Rust",
	".swift": "Swift",
	".scala": "Scala", ".sc": "Scala",
	".sh": "Shell", ".bash": "Shell", ".zsh": "Shell", ".ksh": "Shell",
	".ps1": "PowerShell", ".psm1": "PowerShell", ".psd1": "PowerShell",
	".tf": "HCL/Terraform", ".tfvars": "HCL/Terraform", ".hcl": "HCL/Terraform",
	".yml": "YAML", ".yaml": "YAML",
	".dockerfile": "Dockerfile",
	".sql":        "SQL",
	".html":       "HTML", ".htm": "HTML",
	".css": "CSS", ".scss": "CSS", ".sass": "CSS", ".less": "CSS",
	".dart": "Dart",
	".m":    "Objective-C", ".mm": "Objective-C",
	".groovy": "Groovy", ".gradle": "Groovy",
	".ex": "Elixir", ".exs": "Elixir",
	".lua": "Lua",
	".r":   "R",
}

// languageOf classifies a file by name ("" when unknown).
func languageOf(p string) string {
	base := path.Base(p)
	lower := strings.ToLower(base)
	if lower == "dockerfile" || lower == "containerfile" || strings.HasPrefix(lower, "dockerfile.") {
		return "Dockerfile"
	}
	if strings.HasSuffix(lower, ".gradle.kts") {
		return "Kotlin"
	}
	return languageByExt[strings.ToLower(path.Ext(base))]
}

var manifestNames = map[string]bool{
	"package.json": true, "package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true,
	"go.mod": true, "go.sum": true,
	"pom.xml": true, "build.gradle": true, "build.gradle.kts": true,
	"Pipfile": true, "Pipfile.lock": true, "pyproject.toml": true, "poetry.lock": true,
	"Gemfile": true, "Gemfile.lock": true,
	"composer.json": true, "composer.lock": true,
	"Cargo.toml": true, "Cargo.lock": true,
	"packages.config": true, "Package.swift": true, "pubspec.yaml": true, "mix.exs": true,
	"Dockerfile": true, "Chart.yaml": true,
}

// isManifest reports whether a file is a dependency or infrastructure
// manifest worth surfacing.
func isManifest(p string) bool {
	base := path.Base(p)
	if manifestNames[base] {
		return true
	}
	switch {
	case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
		return true
	case strings.HasSuffix(base, ".csproj"), strings.HasSuffix(base, ".tf"):
		return true
	case strings.HasPrefix(base, "docker-compose") && (strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")):
		return true
	}
	return false
}
