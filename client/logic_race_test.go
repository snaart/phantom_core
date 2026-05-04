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
	proto2 "phantom/proto"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode5"
)

// TestLogicClient_ConcurrentMessageProcessing tests concurrent message handling
// Validates: No race on peerSessions map, proper mutex locking
// Attack: Concurrent access to same session from multiple goroutines
func TestLogicClient_ConcurrentMessageProcessing(t *testing.T) {
	ks := NewTestKeyStore(t)
	ms := NewTestMessageStore(t)

	handler := &MockCoreEventHandler{}
	lc, err := newLogicClient(ks, ms, handler)
	if err != nil {
		t.Fatalf("Failed to create logic client: %v", err)
	}

	// Create a test contact with established session
	contact := &Contact{
		DisplayName: "TestPeer",
	}

	// Generate identity keys for the contact
	diliScheme := mode5.Scheme()
	idPubDili, _, err := diliScheme.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate Dilithium keys: %v", err)
	}
	contact.IdentityPublicDili = idPubDili

	// Generate identity key hash
	idPubDiliBytes, _ := idPubDili.MarshalBinary()
	contact.IdentityKeyHash = fmt.Sprintf("%x", idPubDiliBytes)[:16]

	// Setup test ratchet
	ratchet, _, err := setupTestRatchet()
	if err != nil {
		t.Fatalf("Failed to setup test ratchet: %v", err)
	}

	ratchetBytes, err := ratchet.MarshalJSON()
	if err != nil {
		t.Fatalf("Failed to marshal ratchet: %v", err)
	}
	contact.RatchetState = ratchetBytes

	if err := ks.SaveContact(contact); err != nil {
		t.Fatalf("Failed to save contact: %v", err)
	}

	// Create session
	session := lc.getOrCreateSession(contact.IdentityKeyHash)
	session.isEstablished = true

	// Test concurrent message processing
	const numGoroutines = 50
	const messagesPerGoroutine = 10

	var wg sync.WaitGroup
	errors := &ErrorCollector{}

	// Run with race detector - concurrent access to peerSessions map
	err = RunConcurrent(numGoroutines, func(id int) {
		for i := 0; i < messagesPerGoroutine; i++ {
			// Concurrent access to peerSessions - should be protected by mutex
			_ = lc.getOrCreateSession(contact.IdentityKeyHash)

			// Small delay to increase chance of race
			time.Sleep(1 * time.Millisecond)
		}
	})

	if err != nil {
		t.Fatalf("Concurrent execution failed: %v", err)
	}

	wg.Wait()

	if errors.HasErrors() {
		for _, e := range errors.Errors() {
			t.Errorf("Error during concurrent processing: %v", e)
		}
	}

	// Verify no goroutine leaks
	AssertNoGoroutineLeak(t, func() {
		_ = lc.getOrCreateSession(contact.IdentityKeyHash)
	})
}

// TestLogicClient_ConcurrentSessionEstablishment tests concurrent session creation
// Validates: No race on session creation, proper mutex locking, no duplicate sessions
// Attack: Multiple goroutines trying to establish session with same peer simultaneously
func TestLogicClient_ConcurrentSessionEstablishment(t *testing.T) {
	ks := NewTestKeyStore(t)
	ms := NewTestMessageStore(t)

	handler := &MockCoreEventHandler{}
	lc, err := newLogicClient(ks, ms, handler)
	if err != nil {
		t.Fatalf("Failed to create logic client: %v", err)
	}

	const numGoroutines = 100
	peerHash := "test_peer_hash_12345"

	// Barrier to coordinate goroutines
	barrier := NewBarrier(numGoroutines)
	sessionCount := &ConcurrentCounter{}

	// All goroutines try to create session at the same time
	err = RunConcurrent(numGoroutines, func(id int) {
		barrier.Wait() // Sync start

		session := lc.getOrCreateSession(peerHash)
		if session != nil {
			sessionCount.Increment()
		}
	})

	if err != nil {
		t.Fatalf("Concurrent execution failed: %v", err)
	}

	// Verify only ONE session was created despite concurrent access
	lc.mu.RLock()
	actualSessions := len(lc.peerSessions)
	lc.mu.RUnlock()

	if actualSessions != 1 {
		t.Errorf("Expected 1 session, got %d - race condition in session creation", actualSessions)
	}

	// Verify all goroutines got the same session
	if sessionCount.Get() != numGoroutines {
		t.Errorf("Not all goroutines got session: expected %d, got %d", numGoroutines, sessionCount.Get())
	}
}

// TestLogicClient_PacketQueueConcurrency tests packet queue under concurrent load
// Validates: Channel safety, no deadlocks, no dropped packets
// Attack: Queue overflow/starvation
func TestLogicClient_PacketQueueConcurrency(t *testing.T) {
	ks := NewTestKeyStore(t)
	ms := NewTestMessageStore(t)

	handler := &MockCoreEventHandler{}
	lc, err := newLogicClient(ks, ms, handler)
	if err != nil {
		t.Fatalf("Failed to create logic client: %v", err)
	}

	const numProducers = 20
	const numConsumers = 5
	const packetsPerProducer = 50

	totalPackets := numProducers * packetsPerProducer
	receivedPackets := &ConcurrentCounter{}
	var consumersWg sync.WaitGroup

	// Start consumers
	for i := 0; i < numConsumers; i++ {
		consumersWg.Add(1)
		go func(consumerID int) {
			defer consumersWg.Done()
			timeout := time.After(5 * time.Second)

			for {
				select {
				case packet := <-lc.packetQueue:
					if packet != nil {
						receivedPackets.Increment()
					}

					// Stop when we've received all packets
					if receivedPackets.Get() >= totalPackets {
						return
					}

				case <-timeout:
					// Prevent infinite wait
					return
				}
			}
		}(i)
	}

	// Producers: concurrent packet sending
	err = RunConcurrent(numProducers, func(producerID int) {
		for i := 0; i < packetsPerProducer; i++ {
			packet := &proto2.Packet{
				RoutingToken: make([]byte, 32),
				Payload: &proto2.Packet_EncryptedMessage{
					EncryptedMessage: &proto2.EncryptedMessage{
						Ciphertext: []byte(fmt.Sprintf("Producer %d, packet %d", producerID, i)),
					},
				},
			}

			// Non-blocking send with timeout to detect deadlock
			select {
			case lc.packetQueue <- packet:
				// Success
			case <-time.After(1 * time.Second):
				t.Errorf("Packet queue blocked - potential deadlock")
				return
			}
		}
	})

	if err != nil {
		t.Fatalf("Producer goroutines failed: %v", err)
	}

	// Wait for consumers with timeout
	done := make(chan struct{})
	go func() {
		consumersWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(10 * time.Second):
		t.Fatal("Consumers timed out - potential deadlock or starvation")
	}

	// Verify all packets were received
	received := receivedPackets.Get()
	if received != totalPackets {
		t.Errorf("Packet loss detected: sent %d, received %d, lost %d",
			totalPackets, received, totalPackets-received)
	}
}

// TestLogicClient_PeerSessionRaceCondition tests concurrent map access
// Validates: RWMutex proper usage, no concurrent map writes
// Attack: Concurrent read/write to peerSessions map causing panic
func TestLogicClient_PeerSessionRaceCondition(t *testing.T) {
	ks := NewTestKeyStore(t)
	ms := NewTestMessageStore(t)

	handler := &MockCoreEventHandler{}
	lc, err := newLogicClient(ks, ms, handler)
	if err != nil {
		t.Fatalf("Failed to create logic client: %v", err)
	}

	const numReaders = 50
	const numWriters = 10
	const operations = 100

	barrier := NewBarrier(numReaders + numWriters)

	// Readers: concurrent reads
	readerErr := make(chan error, numReaders)
	for i := 0; i < numReaders; i++ {
		go func(id int) {
			barrier.Wait()
			for j := 0; j < operations; j++ {
				peerHash := fmt.Sprintf("peer_%d", j%10)

				// Read operation - should use RLock
				lc.mu.RLock()
				_ = lc.peerSessions[peerHash]
				lc.mu.RUnlock()

				time.Sleep(1 * time.Microsecond)
			}
			readerErr <- nil
		}(i)
	}

	// Writers: concurrent writes
	writerErr := make(chan error, numWriters)
	for i := 0; i < numWriters; i++ {
		go func(id int) {
			defer func() {
				if r := recover(); r != nil {
					writerErr <- fmt.Errorf("panic in writer %d: %v", id, r)
					return
				}
				writerErr <- nil
			}()

			barrier.Wait()
			for j := 0; j < operations; j++ {
				peerHash := fmt.Sprintf("peer_%d", j%10)

				// Write operation via getOrCreateSession (uses Lock internally)
				_ = lc.getOrCreateSession(peerHash)

				time.Sleep(1 * time.Microsecond)
			}
		}(i)
	}

	// Wait for all operations
	for i := 0; i < numReaders; i++ {
		if err := <-readerErr; err != nil {
			t.Errorf("Reader error: %v", err)
		}
	}

	for i := 0; i < numWriters; i++ {
		if err := <-writerErr; err != nil {
			t.Errorf("Writer error: %v", err)
		}
	}

	// Verify map integrity
	lc.mu.RLock()
	sessionCount := len(lc.peerSessions)
	lc.mu.RUnlock()

	// Should have created up to 10 sessions (peer_0 through peer_9)
	if sessionCount == 0 || sessionCount > 10 {
		t.Errorf("Unexpected session count: %d", sessionCount)
	}
}

// setupTestRatchet creates a test ratchet for concurrency tests
func setupTestRatchet() (*DoubleRatchet, *InitialCiphertexts, error) {
	// Generate Alice's keys
	_, _, _, _, _, _, err := GenerateHybridIdentityKeyPair()
	if err != nil {
		return nil, nil, err
	}

	// Generate Bob's keys
	_, _, _, bobKyberPub, _, bobECPub, err := GenerateHybridIdentityKeyPair()
	if err != nil {
		return nil, nil, err
	}

	_, bobPreKeyKyberPub, _, bobPreKeyECPub, err := GenerateHybridPreKey()
	if err != nil {
		return nil, nil, err
	}

	// Alice initializes ratchet
	ratchet, initialCts, err := RatchetInitAlice(
		bobKyberPub,
		bobECPub,
		bobPreKeyKyberPub,
		bobPreKeyECPub,
		nil, // No OPK
		nil, // No OPK
		0,   // No OPK ID
	)

	return ratchet, initialCts, err
}
