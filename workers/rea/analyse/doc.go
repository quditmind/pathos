package main

// Schema is the analysis document schema (contract with the API,
// docs/aspm/PATHOS_REVERSE_ENGINEERING.md).
const Schema = "pathos.rea/v1"

// Doc is the analysis document pathos-rea writes.
type Doc struct {
	Schema    string                `json:"schema"`
	Generator map[string]string     `json:"generator"`
	Artifact  Artifact              `json:"artifact"`
	Tools     map[string]*ToolState `json:"tools"`
	Sections  []Section             `json:"sections"`
	Functions []Function            `json:"functions"`
	Imports   []Import              `json:"imports"`
	Exports   []Export              `json:"exports"`
	Strings   []String              `json:"strings"`
	Calls     []Ref                 `json:"calls"`
	StrRefs   []Ref                 `json:"string_refs"`
	Go        *GoInfo               `json:"go"`
	Firmware  *Firmware             `json:"firmware"`
	Code      []Code                `json:"code"`
	Stats     map[string]any        `json:"stats"`
}

// Artifact describes the analysed file.
type Artifact struct {
	FileName string `json:"file_name"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	Format   string `json:"format"`
	Arch     string `json:"arch"`
	Bits     int    `json:"bits"`
	OS       string `json:"os"`
	Language string `json:"language"`
	Stripped bool   `json:"stripped"`
	Entry    string `json:"entry"`
	BuildID  string `json:"build_id"`
}

// ToolState is one tool's run.
type ToolState struct {
	Version    string `json:"version"`
	Status     string `json:"status"` // succeeded | failed | skipped | timed_out
	Detail     string `json:"detail"`
	DurationMS int64  `json:"duration_ms"`
}

// Section is a section (or segment) of the file.
type Section struct {
	Name    string  `json:"name"`
	Offset  int64   `json:"offset"`
	VAddr   string  `json:"vaddr"`
	Size    int64   `json:"size"`
	VSize   int64   `json:"vsize"`
	Perm    string  `json:"perm"`
	Entropy float64 `json:"entropy"`
	Tool    string  `json:"tool"`
}

// Function is a function found in the binary.
type Function struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Addr    string `json:"addr"`
	Offset  int64  `json:"offset"`
	Size    int64  `json:"size"`
	Section string `json:"section"`
	Tool    string `json:"tool"`
	Library bool   `json:"library"`
	Package string `json:"package"`
}

// Import is an imported symbol or (Go) a linked package.
type Import struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Library string `json:"library"`
	Kind    string `json:"kind"` // function | package | object
	Addr    string `json:"addr"`
	Offset  int64  `json:"offset"`
	Tool    string `json:"tool"`
}

// Export is an exported symbol.
type Export struct {
	Name   string `json:"name"`
	Addr   string `json:"addr"`
	Offset int64  `json:"offset"`
	Tool   string `json:"tool"`
}

// String is a string found in the binary (secrets redacted).
type String struct {
	ID       string `json:"id"`
	Value    string `json:"value"`
	Offset   int64  `json:"offset"`
	VAddr    string `json:"vaddr"`
	Section  string `json:"section"`
	Kind     string `json:"kind"` // text | url | path | route | secret | format
	Redacted bool   `json:"redacted"`
	Tool     string `json:"tool"`
}

// Ref is a call (from a function to a function or import) or a string
// reference (from a function to a string); Offset is the file offset of
// the referencing instruction.
type Ref struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Offset int64  `json:"offset"`
	Tool   string `json:"tool"`
}

// GoInfo is the Go build information embedded in a Go binary.
type GoInfo struct {
	GoVersion  string            `json:"go_version"`
	Path       string            `json:"path"`
	MainModule Module            `json:"main_module"`
	Deps       []Module          `json:"deps"`
	Settings   map[string]string `json:"settings"`
}

// Module is a Go module.
type Module struct {
	Path    string `json:"path"`
	Version string `json:"version"`
}

// Firmware is the firmware extraction result.
type Firmware struct {
	Entries []FirmwareEntry `json:"entries"`
	Files   []FirmwareFile  `json:"files"`
}

// FirmwareEntry is one signature binwalk found.
type FirmwareEntry struct {
	Offset      int64  `json:"offset"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Size        int64  `json:"size"`
	Extracted   bool   `json:"extracted"`
}

// FirmwareFile is one extracted file.
type FirmwareFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Type   string `json:"type"`
	SHA256 string `json:"sha256"`
}

// Code is the disassembly or decompiled code of a function.
type Code struct {
	Function string `json:"function"`
	Tool     string `json:"tool"`
	Kind     string `json:"kind"` // pseudo_c | disassembly | java | csharp
	Text     string `json:"text"`
}

// Config is the analysis configuration (worker.REAConfig).
type Config struct {
	Tools          []string `json:"tools"`
	MemoryMB       int      `json:"memory_mb"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	MaxFunctions   int      `json:"max_functions"`
	MaxStrings     int      `json:"max_strings"`
	MaxCode        int      `json:"max_code"`
}

func (c *Config) enabled(tool string) bool {
	for _, t := range c.Tools {
		if t == tool {
			return true
		}
	}
	return false
}

func (c *Config) normalise() {
	if len(c.Tools) == 0 {
		c.Tools = []string{"radare2", "binwalk"}
	}
	if c.MemoryMB < 256 || c.MemoryMB > 65536 {
		c.MemoryMB = 4096
	}
	if c.TimeoutSeconds < 60 || c.TimeoutSeconds > 6*3600 {
		c.TimeoutSeconds = 1800
	}
	if c.MaxFunctions <= 0 || c.MaxFunctions > 100000 {
		c.MaxFunctions = 20000
	}
	if c.MaxStrings <= 0 || c.MaxStrings > 100000 {
		c.MaxStrings = 20000
	}
	if c.MaxCode < 0 || c.MaxCode > 1000 {
		c.MaxCode = 200
	}
}

// Limits of the document besides the configured ones.
const (
	maxCalls      = 50000
	maxStrRefs    = 50000
	maxCodeBytes  = 16 << 10
	maxStringLen  = 512
	maxImports    = 20000
	maxExports    = 20000
	maxSections   = 1000
	maxFwEntries  = 2000
	maxFwFiles    = 5000
	maxNameLength = 400
)
