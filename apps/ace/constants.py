# OSV ecosystem strings to normalized ecosystem identifiers
OSV_ECOSYSTEM_MAP: dict[str, str] = {
    "maven": "maven",
    "pypi": "pypi",
    "npm": "npm",
    "crates.io": "cargo",
    "go": "golang",
    "rubygems": "gem",
    "nuget": "nuget",
    "packagist": "generic",
    "hex": "generic",
    "pub": "generic",
    "hackage": "generic",
    "bioconductor": "generic",
    "cran": "generic",
    "github actions": "generic",
}

# From https://pkg.go.dev/std
GO_STDLIB_PACKAGES = frozenset(
    {
        "archive",
        "bufio",
        "builtin",
        "bytes",
        "cmp",
        "compress",
        "container",
        "context",
        "crypto",
        "database",
        "debug",
        "embed",
        "encoding",
        "errors",
        "expvar",
        "flag",
        "fmt",
        "go",
        "hash",
        "html",
        "image",
        "index",
        "internal",
        "io",
        "iter",
        "log",
        "maps",
        "math",
        "mime",
        "net",
        "os",
        "path",
        "plugin",
        "reflect",
        "regexp",
        "runtime",
        "slices",
        "sort",
        "strconv",
        "strings",
        "structs",
        "sync",
        "syscall",
        "testing",
        "text",
        "time",
        "unicode",
        "unique",
        "unsafe",
        "weak",
    }
)

CHROMIUM_NAMES = frozenset(
    {
        "chromium",
        "chromium-browser",
        "chrome",
        "google-chrome",
    }
)

# Labels applied by ACE pre-filter
LABEL_AUTO_REJECTED = "auto-rejected"
LABEL_MANUAL_TRIAGE = "manual-triage"
LABEL_AUTO_AFFECTS = "auto-affects"
LABEL_POTENTIAL_REJECTION = "potential-rejection"
