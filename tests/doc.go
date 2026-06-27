// Package tests contains integration and benchmark tests for the Sentinel
// detection pipeline.  Each test file imports the package under test directly
// to exercise public APIs from the outside.
//
// Test files:
//   - trie_test.go    : Aho-Corasick Tier 1 engine tests
//   - entropy_test.go : Shannon entropy Tier 2 engine tests
//   - context_test.go : Context filter Tier 3 engine tests
//   - scanner_test.go : Full three-tier pipeline integration tests
package tests
