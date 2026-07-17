package scanner

import (
	"bytes"
	"testing"
)

func TestSeverityWeight(t *testing.T) {
	cases := []struct {
		sev  string
		want int
	}{
		{"CRITICAL", 4},
		{"HIGH", 3},
		{"MEDIUM", 2},
		{"LOW", 1},
		{"UNKNOWN", 0},
		{"critical", 4},
	}
	for _, tc := range cases {
		if got := severityWeight(tc.sev); got != tc.want {
			t.Errorf("severityWeight(%q) = %d; want %d", tc.sev, got, tc.want)
		}
	}
}

func TestEntropySeverity(t *testing.T) {
	cases := []struct {
		entropy float64
		want    string
	}{
		{7.5, "CRITICAL"},
		{6.5, "HIGH"},
		{5.5, "MEDIUM"},
		{4.5, "LOW"},
	}
	for _, tc := range cases {
		if got := entropySeverity(tc.entropy); got != tc.want {
			t.Errorf("entropySeverity(%f) = %q; want %q", tc.entropy, got, tc.want)
		}
	}
}

func TestIsKnownSafeFile(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"test.gdnsuppress", true},
		{"test.snyk", true},
		{"test.dotsettings", true},
		{"doc.go", true},
		{"api.pb.go", true},
		{"api.pb.gw.go", true},
		{"api_pb2.py", true},
		{"api_pb2_grpc.py", true},
		{"zz_generated.go", true},
		{"cgmanifest.json", true},
		{".git-blame-ignore-revs", true},
		{"product.json", true},
		{".terraform.lock.hcl", true},
		{"normal.go", false},
	}
	for _, tc := range cases {
		if got := isKnownSafeFile(tc.path); got != tc.want {
			t.Errorf("isKnownSafeFile(%q) = %t; want %t", tc.path, got, tc.want)
		}
	}
}

func TestIsSourceCodeFile(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"main.go", true},
		{"main.rb", true},
		{"main.js", true},
		{"main.ts", true},
		{"main.jsx", true},
		{"main.tsx", true},
		{"main.py", true},
		{"main.java", true},
		{"main.scala", true},
		{"main.kt", true},
		{"main.c", true},
		{"main.cpp", true},
		{"main.h", true},
		{"main.cs", true},
		{"main.php", true},
		{"main.pl", true},
		{"main.sh", true},
		{"main.bash", true},
		{"main.zsh", true},
		{"main.txt", false},
	}
	for _, tc := range cases {
		if got := isSourceCodeFile(tc.path); got != tc.want {
			t.Errorf("isSourceCodeFile(%q) = %t; want %t", tc.path, got, tc.want)
		}
	}
}

func TestIsPureIdentifier(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"ACAccountSID", true},
		{"SKStatusCode", true},
		{"SK_Status", false},
		{"SK-Status", false},
	}
	for _, tc := range cases {
		if got := isPureIdentifier(tc.s); got != tc.want {
			t.Errorf("isPureIdentifier(%q) = %t; want %t", tc.s, got, tc.want)
		}
	}
}

func TestIsPlausibleSecretToken(t *testing.T) {
	// Let's test URL schemes
	if isPlausibleSecretToken("https://google.com", "", "generic-key", 20) {
		t.Error("expected URL to be implausible")
	}
	// Check minLen
	if isPlausibleSecretToken("short", "", "generic-key", 20) {
		t.Error("expected short token to be implausible")
	}
	// Check parentheses
	if isPlausibleSecretToken("token()", "", "generic-key", 20) {
		t.Error("expected function call to be implausible")
	}
	// Check env references
	if isPlausibleSecretToken("config.PASSWORD", "", "generic-key", 20) {
		t.Error("expected config reference to be implausible")
	}
	// Check all-caps snake case
	if isPlausibleSecretToken("CALIBRATION_PROMPTS_FILE", "", "generic-key", 20) {
		t.Error("expected all caps constant to be implausible")
	}
	// Check common dummy passwords
	if isPlausibleSecretToken("password123", "", "generic-password", 8) {
		t.Error("expected dummy password to be implausible")
	}
}

func TestExtractRHS(t *testing.T) {
	cases := []struct {
		line []byte
		want []byte
		ok   bool
	}{
		{[]byte("key := \"value\""), []byte("\"value\""), true},
		{[]byte("key == \"value\""), nil, false},
		{[]byte("key = \"value\""), []byte("\"value\""), true},
		{[]byte("key: value"), []byte("value"), true},
	}
	for _, tc := range cases {
		got, ok := extractRHS(tc.line)
		if ok != tc.ok || !bytes.Equal(got, tc.want) {
			t.Errorf("extractRHS(%q) = (%q, %t); want (%q, %t)", tc.line, got, ok, tc.want, tc.ok)
		}
	}
}
