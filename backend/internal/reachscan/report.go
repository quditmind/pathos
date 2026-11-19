// Package reachscan is PATHOS' static analysis for function-level
// reachability of dependency vulnerabilities in JavaScript/TypeScript,
// Python and Java code (Go is covered by govulncheck). It reads source
// files only and never runs or builds repository code.
//
// For every file it resolves the names bound by imports (aliases, default
// and named imports, CommonJS require, destructuring, re-exports through
// the repository's own modules, Python star imports, Java single-type,
// static and wildcard imports) and records which members of each external
// module the code calls or references, with the call site and a chain of
// callers inside the repository (name-resolved, so a chain shows one
// plausible way in, not every one).
//
// It does not see the code of the dependencies, so a call to another
// function of a package that calls the vulnerable one internally is not a
// call to the vulnerable function here. Values whose origin it cannot
// follow are reported instead of guessed: method calls on objects of
// unknown type (Methods), and dynamic constructs — computed member access
// on a module, a module passed around as a value, require/import of a
// computed name, getattr with a computed name, eval, Java reflection, Go
// reflect method lookups — (Dynamic). The server turns these into
// "unknown", never into "not reachable".
package reachscan

// Schema is the report format version.
const Schema = 1

// Report is the output of an analysis.
type Report struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
	Schema  int    `json:"schema"`
	// Languages has an entry per ecosystem analysed (npm, pypi, maven, go).
	Languages map[string]*LangStats `json:"languages"`
	// Truncated: a limit was reached (files, uses, methods); what is not
	// listed was not analysed.
	Truncated bool        `json:"truncated"`
	Uses      []Use       `json:"uses"`
	Methods   []MethodUse `json:"methods"`
	Dynamic   []Dynamic   `json:"dynamic"`
	Imports   []Import    `json:"imports"`
}

// LangStats counts what was analysed in one ecosystem.
type LangStats struct {
	Files     int `json:"files"`
	TestFiles int `json:"test_files"`
	Functions int `json:"functions"`
	Calls     int `json:"calls"`
	// Skipped files were too large or unreadable.
	Skipped int `json:"skipped"`
}

// Frame is one step of a call chain: a call at file:line inside function.
type Frame struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Function string `json:"function"`
}

// Use is a member of an external module that the code calls or
// references.
//
//	Kind call    the member is called (a function, a constructor, or a
//	             method of an instance whose class is known: "Class.method")
//	Kind ref     the member is referenced without a visible call (passed as
//	             a callback, stored): treated like a call
//	Kind method  a method called on a value obtained from the module whose
//	             class is not known (Symbol is the method name only)
//
// Symbol is the member path inside the module ("template",
// "sandbox.SandboxedEnvironment", "Template.render"; "default" for calling
// the module itself). For Java, Module is the package and Symbol starts
// with the class.
type Use struct {
	Ecosystem string `json:"ecosystem"`
	Module    string `json:"module"`
	Symbol    string `json:"symbol"`
	Kind      string `json:"kind"`
	// Test: every site is in test code.
	Test  bool    `json:"test"`
	Count int     `json:"count"`
	Sites []Frame `json:"sites"`
	// Paths are caller chains ending at a site, outermost caller first.
	Paths [][]Frame `json:"paths"`
}

// MethodUse is a method called on a value whose type the analysis could
// not resolve (any class's method of that name may be meant).
type MethodUse struct {
	Ecosystem string  `json:"ecosystem"`
	Name      string  `json:"name"`
	Count     int     `json:"count"`
	Test      bool    `json:"test"`
	Sites     []Frame `json:"sites"`
}

// Dynamic is a construct that can reach module members the analysis
// cannot name. Module "" means any module of the ecosystem.
type Dynamic struct {
	Ecosystem string `json:"ecosystem"`
	Module    string `json:"module"`
	Reason    string `json:"reason"`
	File      string `json:"file"`
	Line      int    `json:"line"`
	Test      bool   `json:"test"`
}

// Import is an external module the code imports.
type Import struct {
	Ecosystem string `json:"ecosystem"`
	Module    string `json:"module"`
	Files     int    `json:"files"`
	// TestOnly: only test code imports it.
	TestOnly bool  `json:"test_only"`
	First    Frame `json:"first"`
}

// Limits of a report.
const (
	MaxFiles       = 50000
	MaxFileBytes   = 1 << 20
	MaxUses        = 50000
	MaxMethods     = 30000
	MaxDynamic     = 2000
	MaxSites       = 5
	MaxPaths       = 3
	MaxPathFrames  = 12
	MaxMethodSites = 3
)
