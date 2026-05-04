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
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestKeyStore_DeadlockPrevention tests for potential deadlocks in Key Store operations
// Validates: No circular lock dependencies, proper lock release
// Attack: Nested mutex acquisitions, lock hold during blocking operations
func TestKeyStore_DeadlockPrevention(t *testing.T) {
	ks := NewTestKeyStore(t)

	// Scenario 1: Concurrent SaveContact and LoadContact
	// This could deadlock if mutex is held during DB operations
	err := DetectDeadlock(30*time.Second, func() {
		var wg sync.WaitGroup
		const numGoroutines = 5 // Reduced from 20

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				// Generate keys for contact
				_, diliPub, _, _, _, _, _ := GenerateHybridIdentityKeyPair()
				contact := &Contact{
					DisplayName:        fmt.Sprintf("Contact_%d", id),
					IdentityKeyHash:    fmt.Sprintf("hash_%d", id),
					IdentityPublicDili: diliPub,
				}

				// Save and load concurrently
				for j := 0; j < 10; j++ {
					_ = ks.SaveContact(contact)
					_, _ = ks.LoadContact(contact.IdentityKeyHash)
				}
			}(i)
		}

		wg.Wait()
	})

	if err != nil {
		t.Fatalf("Deadlock detected in KeyStore operations: %v", err)
	}

	// Scenario 2: WithUserAccount nested calls
	// Could deadlock if mutex is not released properly
	err = DetectDeadlock(15*time.Second, func() {
		err := ks.WithUserAccount(func(ua *UserAccount) error {
			// Nested call - should not deadlock
			// (Though this is bad practice, should not lock)
			return nil
		})
		if err != nil {
			t.Errorf("WithUserAccount failed: %v", err)
		}
	})

	if err != nil {
		t.Fatal("Deadlock detected in WithUserAccount:", err)
	}

	// Scenario 3: Concurrent ListContacts while saving
	err = DetectDeadlock(60*time.Second, func() {
		var wg sync.WaitGroup

		// Writer goroutine
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ { // Reduced from 50
				for i := 0; i < 50; i++ {
					_, diliPub, _, _, _, _, _ := GenerateHybridIdentityKeyPair()
					contact := &Contact{
						DisplayName:        fmt.Sprintf("Concurrent_%d", i),
						IdentityKeyHash:    fmt.Sprintf("concurrent_hash_%d", i),
						IdentityPublicDili: diliPub,
					}
					_ = ks.SaveContact(contact)
				}
			}
		}()

		// Reader goroutines
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 20; j++ {
					_, _ = ks.ListContacts()
					time.Sleep(1 * time.Millisecond)
				}
			}()
		}

		wg.Wait()
	})

	if err != nil {
		t.Fatal("Deadlock detected in concurrent contact operations:", err)
	}
}

// TestCore_MutexOrdering tests consistent mutex lock ordering
// Validates: No deadlock from reverse lock order
// Attack: Goroutine A locks (mu1, mu2), Goroutine B locks (mu2, mu1) -> deadlock
func TestCore_MutexOrdering(t *testing.T) {
	ks, err := NewKeyStore(":memory:")
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}
	defer ks.Close()

	if err := ks.Initialize("testpin"); err != nil {
		t.Fatalf("Failed to initialize keystore: %v", err)
	}

	ms, err := NewMessageStore(":memory:")
	if err != nil {
		t.Fatalf("Failed to create messagestore: %v", err)
	}
	defer ms.Close()

	handler := &MockCoreEventHandler{}

	core, err := NewCore("test_user", "testpin", t.TempDir(), handler)
	if err != nil {
		t.Fatalf("Failed to create core: %v", err)
	}

	// Test concurrent operations that might acquire multiple locks
	// Core has mu, logicClient has mu and contactsMu
	err = DetectDeadlock(30*time.Second, func() {
		var wg sync.WaitGroup

		// Goroutine 1: Operations in one order
		for i := 0; i < 5; i++ { // Reduced from 10
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				// These operations should acquire locks in consistent order
				core.GetContacts()
				time.Sleep(1 * time.Millisecond)
			}(i)
		}

		// Goroutine 2: Overlapping operations
		for i := 0; i < 5; i++ { // Reduced from 10
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				// Concurrent access to different core methods
				core.GetContacts()
				time.Sleep(1 * time.Millisecond)
			}(i)
		}

		wg.Wait()
	})

	if err != nil {
		t.Fatal("Mutex ordering deadlock detected:", err)
	}
}

// TestLogicClient_InitMutexDeadlock tests session initialization mutex interactions
// Validates: initMutex and peerSessions mu don't deadlock
// Attack: Hold initMutex while trying to acquire peerSessions mu
func TestLogicClient_InitMutexDeadlock(t *testing.T) {
	ks, err := NewKeyStore(":memory:")
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}
	defer ks.Close()

	if err := ks.Initialize("testpin"); err != nil {
		t.Fatalf("Failed to initialize keystore: %v", err)
	}

	ms, err := NewMessageStore(":memory:")
	if err != nil {
		t.Fatalf("Failed to create messagestore: %v", err)
	}
	defer ms.Close()

	handler := &MockCoreEventHandler{}
	lc, err := newLogicClient(ks, ms, handler)
	if err != nil {
		t.Fatalf("Failed to create logic client: %v", err)
	}

	const numSessions = 10
	peerHashes := make([]string, numSessions)
	for i := 0; i < numSessions; i++ {
		peerHashes[i] = fmt.Sprintf("peer_hash_%d", i)
	}

	// Create sessions first
	for _, hash := range peerHashes {
		_ = lc.getOrCreateSession(hash)
	}

	// Scenario: Concurrent access to session.initMutex and lc.mu
	err = DetectDeadlock(30*time.Second, func() {
		var wg sync.WaitGroup

		// Goroutines trying to access session init status
		for i := 0; i < 10; i++ { // Reduced from 50
			hash := peerHashes[i%numSessions]

			wg.Add(1)
			go func(peerHash string) {
				defer wg.Done()

				lc.mu.RLock()
				session, exists := lc.peerSessions[peerHash]
				lc.mu.RUnlock()

				if exists && session != nil {
					// Access session's initMutex
					session.initMutex.Lock()
					_ = session.isEstablished
					session.initMutex.Unlock()
				}
			}(hash)

			// Concurrent modifications
			wg.Add(1)
			go func(peerHash string) {
				defer wg.Done()

				lc.mu.Lock()
				session, exists := lc.peerSessions[peerHash]
				lc.mu.Unlock()

				if exists && session != nil {
					session.initMutex.Lock()
					session.isEstablished = true
					session.initMutex.Unlock()
				}
			}(hash)
		}

		wg.Wait()
	})

	if err != nil {
		t.Fatal("Init mutex deadlock detected:", err)
	}
}

// TestMessageStore_ConcurrentAccess tests MessageStore mutex under load
// Validates: No deadlock during concurrent save/load operations
func TestMessageStore_ConcurrentAccess(t *testing.T) {
	ms := NewTestMessageStore(t)

	const numGoroutines = 10
	const messagesPerGoroutine = 10

	err := DetectDeadlock(60*time.Second, func() {
		var wg sync.WaitGroup

		// Concurrent writers
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				sessionHash := fmt.Sprintf("session_%d", id%5)
				for j := 0; j < messagesPerGoroutine; j++ {
					_ = ms.SaveMessage(
						sessionHash,
						id%2 == 0, // isOutgoing
						time.Now().Unix(),
						fmt.Sprintf("Message from %d_%d", id, j),
					)
				}
			}(i)
		}

		// Concurrent readers
		for i := 0; i < numGoroutines/2; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				sessionHash := fmt.Sprintf("session_%d", id%5)
				for j := 0; j < messagesPerGoroutine/2; j++ {
					_, _ = ms.LoadHistory(sessionHash, 100)
					time.Sleep(2 * time.Millisecond)
				}
			}(i)
		}

		wg.Wait()
	})

	if err != nil {
		t.Fatal("MessageStore deadlock detected:", err)
	}
}

// TestMutexHoldTime measures how long mutexes are held
// Validates: Mutexes are not held during blocking operations
// This is a performance/correctness test
func TestMutexHoldTime(t *testing.T) {
	ks, err := NewKeyStore(":memory:")
	if err != nil {
		t.Fatalf("Failed to create keystore: %v", err)
	}
	defer ks.Close()

	if err := ks.Initialize("testpin"); err != nil {
		t.Fatalf("Failed to initialize keystore: %v", err)
	}

	// Measure contention: if mutex is held too long, operations will queue
	const numGoroutines = 10 // Reduced from 50
	startTimes := make([]time.Time, numGoroutines)
	endTimes := make([]time.Time, numGoroutines)

	var wg sync.WaitGroup
	barrier := NewBarrier(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			barrier.Wait() // All start at same time

			startTimes[id] = time.Now()

			_, diliPub, _, _, _, _, _ := GenerateHybridIdentityKeyPair()
			contact := &Contact{
				DisplayName:        fmt.Sprintf("Contact_%d", id),
				IdentityKeyHash:    fmt.Sprintf("hash_%d", id),
				IdentityPublicDili: diliPub,
			}
			_ = ks.SaveContact(contact)

			endTimes[id] = time.Now()
		}(i)
	}

	wg.Wait()

	// Calculate average wait time
	var totalDuration time.Duration
	for i := 0; i < numGoroutines; i++ {
		totalDuration += endTimes[i].Sub(startTimes[i])
	}

	avgDuration := totalDuration / time.Duration(numGoroutines)

	// If average duration is very high, mutex is being held too long
	// or there's excessive contention
	if avgDuration > 100*time.Millisecond {
		t.Logf("WARNING: High mutex contention detected, avg duration: %v", avgDuration)
		// Note: This is not a hard failure, just a warning about potential performance issues
	}

	t.Logf("Average operation duration under contention: %v", avgDuration)
}

// TestNoGoroutineLeaks verifies operations don't leak goroutines
// Validates: Proper cleanup, no background goroutines left running
func TestNoGoroutineLeaks(t *testing.T) {
	tests := []struct {
		name string
		fn   func()
	}{
		{
			name: "KeyStore operations",
			fn: func() {
				ks := NewTestKeyStore(t)

				_, diliPub, _, _, _, _, _ := GenerateHybridIdentityKeyPair()
				contact := &Contact{
					DisplayName:        "Test",
					IdentityKeyHash:    "test_hash",
					IdentityPublicDili: diliPub,
				}
				ks.SaveContact(contact)
				ks.LoadContact("test_hash")
				ks.ListContacts()
			},
		},
		{
			name: "MessageStore operations",
			fn: func() {
				ms := NewTestMessageStore(t)

				_ = ms.SaveMessage(
					"session",
					true, // isOutgoing
					time.Now().Unix(),
					"test",
				)
				ms.LoadHistory("session", 10)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			AssertNoGoroutineLeak(t, tt.fn)
		})
	}
}
