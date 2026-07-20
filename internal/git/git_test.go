package git

import (
	"bytes"
	"testing"
)

func TestParseStagedFiles(t *testing.T) {
	raw := []byte("M\tmodified_file.go\nA\tnew_file.txt\nR100\told_name.go\tnew_name.go\n")
	expected := []StagedFile{
		{Status: "M", Path: "modified_file.go"},
		{Status: "A", Path: "new_file.txt"},
		{Status: "R100", Path: "new_name.go"}, // Keeps the full status text
	}

	result := parseStagedFiles(raw)

	if len(result) != len(expected) {
		t.Fatalf("expected %d staged files, got %d", len(expected), len(result))
	}

	for i := range expected {
		if result[i].Status != expected[i].Status || result[i].Path != expected[i].Path {
			t.Errorf("expected %+v, got %+v", expected[i], result[i])
		}
	}
}

func TestFilterAddedLines(t *testing.T) {
	diff := []byte(`
diff --git a/test.go b/test.go
index 83db48f..1234567 100644
--- a/test.go
+++ b/test.go
@@ -1,3 +1,4 @@
 func main() {
-	fmt.Println("Old")
+	fmt.Println("New")
+	secret := "AKIAIOSFODNN7EXAMPLE"
 }
`)
	expected := []byte("\tfmt.Println(\"New\")\n\tsecret := \"AKIAIOSFODNN7EXAMPLE\"\n")

	result := FilterAddedLines(diff)
	if !bytes.Equal(result, expected) {
		t.Errorf("expected %q, got %q", string(expected), string(result))
	}
}
