// Package git provides interoperability with the local git binary: listing
// staged files and retrieving their diff content as it will be committed.
package git

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// StagedFile represents a single file that has changes staged for commit.
type StagedFile struct {
	// Path is the repo-relative path of the file.
	Path string

	// Status is the single-letter git status code: A (added), M (modified),
	// D (deleted), R (renamed), C (copied), etc.
	Status string
}

// ListStagedFiles returns all files currently staged for the next commit.
// It runs `git diff --cached --name-status` and parses the output.
// Files with status "D" (deleted) are excluded — there is nothing to scan.
func ListStagedFiles() ([]StagedFile, error) {
	out, err := runGit("diff", "--cached", "--name-status", "--diff-filter=ACRM")
	if err != nil {
		return nil, fmt.Errorf("git diff: %w", err)
	}

	return parseStagedFiles(out), nil
}

// GetStagedDiff returns the unified diff of staged changes for the given path.
// Only the added lines (lines beginning with '+') are returned, because those
// represent new content being introduced into the repository.
func GetStagedDiff(path string) ([]byte, error) {
	out, err := runGit("diff", "--cached", "--", path)
	if err != nil {
		return nil, fmt.Errorf("git diff for %q: %w", path, err)
	}
	return filterAddedLines(out), nil
}

// GetStagedContent returns the full staged blob content for a file.
// This is used for newly added files (status "A") where there is no base to
// diff against.
func GetStagedContent(path string) ([]byte, error) {
	// Use :path notation to reference the staged (index) version.
	out, err := runGit("show", ":"+path)
	if err != nil {
		return nil, fmt.Errorf("git show staged %q: %w", path, err)
	}
	return out, nil
}

// RepoRoot returns the absolute path to the top-level repository directory.
func RepoRoot() (string, error) {
	out, err := runGit("rev-parse", "--show-toplevel")
	if err != nil {
		return "", fmt.Errorf("git rev-parse: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// IsInsideWorkTree returns true when the current directory is inside a git repo.
func IsInsideWorkTree() bool {
	out, err := runGit("rev-parse", "--is-inside-work-tree")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "true"
}

// runGit executes git with the supplied arguments and returns combined output.
func runGit(args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w — stderr: %s", err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// parseStagedFiles splits the raw `git diff --name-status` output into
// StagedFile records.  Rename/copy entries have two paths separated by a tab;
// we take the destination path.
func parseStagedFiles(raw []byte) []StagedFile {
	var files []StagedFile
	lines := bytes.Split(raw, []byte("\n"))
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		// Format: STATUS\tPATH  or  STATUS\tSRC\tDST (for renames/copies)
		parts := bytes.SplitN(line, []byte("\t"), 3)
		if len(parts) < 2 {
			continue
		}
		status := strings.TrimSpace(string(parts[0]))
		// For renames: R100\told\tnew — pick destination.
		path := strings.TrimSpace(string(parts[len(parts)-1]))

		files = append(files, StagedFile{
			Path:   path,
			Status: status,
		})
	}
	return files
}

// filterAddedLines extracts only the lines introduced by the diff (those
// starting with '+') excluding the diff header lines ('+++').
func filterAddedLines(diff []byte) []byte {
	var buf bytes.Buffer
	lines := bytes.Split(diff, []byte("\n"))
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		if line[0] == '+' && (len(line) < 3 || string(line[:3]) != "+++") {
			// Strip the leading '+' so the scanner sees the raw content.
			buf.Write(line[1:])
			buf.WriteByte('\n')
		}
	}
	return buf.Bytes()
}
