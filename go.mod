module github.com/sentinel-cli/sentinel

go 1.22

require (
	github.com/fatih/color v1.17.0
	github.com/spf13/cobra v1.8.1
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	golang.org/x/sys v0.21.0 // indirect
)

// Retract v1.0.2–v1.0.5 (including this version).
// These tags were published during a history-cleanup operation and carry
// no meaningful changes over v1.0.1. After this retraction is indexed,
// `go install ...@latest` resolves back to v1.0.1.
retract [v1.0.2, v1.0.5]
