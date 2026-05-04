// Copyright 2025 snaart
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package phantomcore

import (
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	proto2 "phantom/proto"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode5"
)

// Test DB helpers

// NewTestKeyStore creates a KeyStore with a file-based database in a temp dir
// configured for concurrency using WAL mode.
func NewTestKeyStore(t *testing.T) *KeyStore {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), fmt.Sprintf("ks_%d.db", time.Now().UnixNano()))

	ks, err := NewKeyStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create test keystore: %v", err)
	}

	// Enable WAL mode for concurrency and reduced cache size for memory
	if _, err := ks.db.Exec("PRAGMA journal_mode=WAL; PRAGMA cache_size = -2000; PRAGMA synchronous = NORMAL;"); err != nil {
		t.Fatalf("Failed to set pragmas: %v", err)
	}

	if err := ks.Initialize("testpin"); err != nil {
		t.Fatalf("Failed to initialize keystore: %v", err)
	}

	if err := ks.CreateAccount(); err != nil {
		t.Fatalf("Failed to create account: %v", err)
	}

	t.Cleanup(func() {
		ks.Close()
	})

	return ks
}

// NewTestMessageStore creates a MessageStore with a file-based database
func NewTestMessageStore(t *testing.T) *MessageStore {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), fmt.Sprintf("ms_%d.db", time.Now().UnixNano()))
	ms, err := NewMessageStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create test messagestore: %v", err)
	}

	// Enable WAL mode for concurrency and reduced cache size for memory
	if _, err := ms.db.Exec("PRAGMA journal_mode=WAL; PRAGMA cache_size = -2000; PRAGMA synchronous = NORMAL;"); err != nil {
		t.Fatalf("Failed to set pragmas: %v", err)
	}

	if err := ms.Initialize("testpin"); err != nil {
		t.Fatalf("Failed to initialize messagestore: %v", err)
	}

	t.Cleanup(func() {
		ms.Close()
	})

	return ms
}

func randomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// Concurrency test helpers

// RunConcurrent executes fn in n goroutines concurrently and waits for completion
func RunConcurrent(n int, fn func(id int)) error {
	var wg sync.WaitGroup
	errChan := make(chan error, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					errChan <- fmt.Errorf("panic in goroutine %d: %v", id, r)
				}
			}()
			fn(id)
		}(i)
	}

	wg.Wait()
	close(errChan)

	// Collect any errors
	for err := range errChan {
		if err != nil {
			return err
		}
	}
	return nil
}

// DetectDeadlock runs fn with a timeout, returns error if deadlock detected
func DetectDeadlock(timeout time.Duration, fn func()) error {
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-time.After(timeout):
		return errors.New("potential deadlock detected: operation timed out")
	}
}

// AssertNoGoroutineLeak checks that no goroutines leaked after running fn
func AssertNoGoroutineLeak(t *testing.T, fn func()) {
	t.Helper()
	before := runtime.NumGoroutine()

	fn()

	// Give goroutines time to cleanup
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	time.Sleep(50 * time.Millisecond)

	after := runtime.NumGoroutine()

	// Allow some tolerance (background goroutines)
	if after > before+2 {
		t.Errorf("Goroutine leak detected: before=%d, after=%d, leaked=%d", before, after, after-before)
	}
}

// MeasureGoroutines returns goroutine count before and after fn execution
func MeasureGoroutines(fn func()) (before, after int) {
	before = runtime.NumGoroutine()
	fn()
	time.Sleep(50 * time.Millisecond)
	after = runtime.NumGoroutine()
	return
}

// WaitForCondition waits for condition to become true, or timeout
func WaitForCondition(timeout time.Duration, condition func() bool) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return errors.New("condition not met within timeout")
}

// Attack simulation helpers

// GenerateMalformedPacket creates a packet with specific malformation
func GenerateMalformedPacket(malformationType string) *proto2.Packet {
	packet := &proto2.Packet{}

	switch malformationType {
	case "no_signature":
		packet.RoutingToken = make([]byte, 32)
		rand.Read(packet.RoutingToken)
		packet.Signature = nil
		packet.Payload = &proto2.Packet_EncryptedMessage{
			EncryptedMessage: &proto2.EncryptedMessage{
				Ciphertext: []byte("fake ciphertext"),
			},
		}

	case "invalid_sender_key":
		packet.RoutingToken = make([]byte, 32)
		rand.Read(packet.RoutingToken)
		packet.SenderIdentityKey = []byte("invalid key data")
		packet.Signature = make([]byte, mode5.SignatureSize)

	case "corrupted_ciphertext":
		packet.RoutingToken = make([]byte, 32)
		rand.Read(packet.RoutingToken)
		packet.Payload = &proto2.Packet_EncryptedMessage{
			EncryptedMessage: &proto2.EncryptedMessage{
				RatchetHeader: make([]byte, 100),
				Ciphertext:    []byte{0xFF, 0xFF, 0xFF}, // Corrupted
			},
		}

	case "wrong_routing_token":
		packet.RoutingToken = make([]byte, 32)
		// All zeros - invalid
		packet.Payload = &proto2.Packet_EncryptedMessage{
			EncryptedMessage: &proto2.EncryptedMessage{
				Ciphertext: []byte("data"),
			},
		}

	case "oversized_message":
		packet.RoutingToken = make([]byte, 32)
		rand.Read(packet.RoutingToken)
		// Create message larger than MaxMessageSize
		packet.Payload = &proto2.Packet_EncryptedMessage{
			EncryptedMessage: &proto2.EncryptedMessage{
				Ciphertext: make([]byte, MaxMessageSize+1000),
			},
		}
	}

	return packet
}

// CorruptCiphertext modifies ciphertext to simulate corruption
func CorruptCiphertext(ciphertext []byte) []byte {
	if len(ciphertext) == 0 {
		return ciphertext
	}
	corrupted := make([]byte, len(ciphertext))
	copy(corrupted, ciphertext)
	// Flip random bits
	corrupted[0] ^= 0xFF
	if len(corrupted) > 1 {
		corrupted[len(corrupted)-1] ^= 0xFF
	}
	return corrupted
}

// ForgeSignature creates an invalid signature
func ForgeSignature() []byte {
	sig := make([]byte, mode5.SignatureSize)
	rand.Read(sig)
	return sig
}

// ModifyInvite creates an invite with tampered signature
func ModifyInvite(invite *proto2.Invite) *proto2.Invite {
	tampered := &proto2.Invite{
		IdentityKeyDilithium:     invite.IdentityKeyDilithium,
		IdentityKeyKyber:         invite.IdentityKeyKyber,
		SignedPrekeyKyber:        invite.SignedPrekeyKyber,
		SignedPrekeyX25519:       invite.SignedPrekeyX25519,
		IdentityKeyX25519:        invite.IdentityKeyX25519,
		PrekeySignatureDilithium: ForgeSignature(), // Forged!
		RoutingToken:             invite.RoutingToken,
		DisplayName:              invite.DisplayName,
	}
	return tampered
}

// Metrics and monitoring helpers

// MemoryStats captures memory statistics
type MemoryStats struct {
	AllocBytes      uint64
	TotalAllocBytes uint64
	NumGC           uint32
}

// MeasureMemory captures memory before and after fn execution
func MeasureMemory(fn func()) (before, after MemoryStats) {
	var m runtime.MemStats

	runtime.GC()
	runtime.ReadMemStats(&m)
	before = MemoryStats{
		AllocBytes:      m.Alloc,
		TotalAllocBytes: m.TotalAlloc,
		NumGC:           m.NumGC,
	}

	fn()

	runtime.GC()
	runtime.ReadMemStats(&m)
	after = MemoryStats{
		AllocBytes:      m.Alloc,
		TotalAllocBytes: m.TotalAlloc,
		NumGC:           m.NumGC,
	}

	return
}

// AssertMemoryBound checks that memory usage stays within bounds
func AssertMemoryBound(t *testing.T, maxAllocMB uint64, fn func()) {
	t.Helper()
	before, after := MeasureMemory(fn)

	allocatedMB := (after.AllocBytes - before.AllocBytes) / (1024 * 1024)
	if allocatedMB > maxAllocMB {
		t.Errorf("Memory usage exceeded bound: allocated %d MB, max %d MB", allocatedMB, maxAllocMB)
	}
}

// ConcurrentCounter is a thread-safe counter for testing
type ConcurrentCounter struct {
	mu    sync.Mutex
	count int
}

func (c *ConcurrentCounter) Increment() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count++
}

func (c *ConcurrentCounter) Get() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

// RaceDetector helps detect race conditions in tests
type RaceDetector struct {
	mu       sync.Mutex
	accessed bool
	raced    bool
}

func (r *RaceDetector) Access() {
	if r.accessed && !r.raced {
		// Potential race detected
		r.raced = true
	}
	r.accessed = true
}

func (r *RaceDetector) DidRace() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.raced
}

// ErrorCollector collects errors from multiple goroutines
type ErrorCollector struct {
	mu     sync.Mutex
	errors []error
}

func (e *ErrorCollector) Add(err error) {
	if err == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.errors = append(e.errors, err)
}

func (e *ErrorCollector) Errors() []error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]error(nil), e.errors...)
}

func (e *ErrorCollector) HasErrors() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.errors) > 0
}

// Barrier synchronization primitive for coordinating goroutines
type Barrier struct {
	mu      sync.Mutex
	cond    *sync.Cond
	count   int
	waiting int
}

func NewBarrier(count int) *Barrier {
	b := &Barrier{count: count}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (b *Barrier) Wait() {
	b.mu.Lock()
	b.waiting++
	if b.waiting >= b.count {
		b.cond.Broadcast()
		b.mu.Unlock()
		return
	}
	b.cond.Wait()
	b.mu.Unlock()
}
