package store

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func NewID(prefix string) string {
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	return fmt.Sprintf("%s_%s", prefix, hex.EncodeToString(buf[:]))
}

func NewAPIKey() string {
	var buf [24]byte
	_, _ = rand.Read(buf[:])
	return "vs_" + hex.EncodeToString(buf[:])
}
