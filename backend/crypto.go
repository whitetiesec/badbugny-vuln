package main

import (
	"crypto/md5"
	"encoding/hex"
)

// VULN: MD5 used for password hashing (CWE-327, CWE-916).
// Trivial to brute-force / rainbow-table.
func md5hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

// VULN: homemade XOR "encryption" (CWE-327).
// Demonstrates a custom-crypto smell that AI-based reviewers spot
// easily but pattern-based SAST often misses.
func xorEncrypt(plain, key string) string {
	out := make([]byte, len(plain))
	for i := 0; i < len(plain); i++ {
		out[i] = plain[i] ^ key[i%len(key)]
	}
	return hex.EncodeToString(out)
}
