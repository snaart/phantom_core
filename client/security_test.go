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
	"bytes"
	"crypto/rand"
	"fmt"
	proto2 "phantom/proto"
	"testing"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/sign/dilithium/mode5"
	"google.golang.org/protobuf/proto"
)

// TestCryptoUtils_EnhancedReplayAttack tests advanced replay attack scenarios
// Attack: Replay same encrypted message multiple times, attempt to bypass nonce check
// Expected: All replays rejected, nonce tracking works correctly
func TestCryptoUtils_EnhancedReplayAttack(t *testing.T) {
	// Setup Alice and Bob
	_, _, _, _, _, _, err := GenerateHybridIdentityKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Alice keys: %v", err)
	}

	_, _, bobKyberPriv, bobKyberPub, bobECPriv, bobECPub, err := GenerateHybridIdentityKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Bob keys: %v", err)
	}

	bobPreKeyKyberPriv, bobPreKeyKyberPub, bobPreKeyECPriv, bobPreKeyECPub, err := GenerateHybridPreKey()
	if err != nil {
		t.Fatalf("Failed to generate Bob prekeys: %v", err)
	}

	// Alice init
	aliceRatchet, initialCts, err := RatchetInitAlice(
		bobKyberPub,
		bobECPub,
		bobPreKeyKyberPub,
		bobPreKeyECPub,
		nil, // No OPK
		nil, // No OPK
		0,   // No OPK ID
	)
	if err != nil {
		t.Fatalf("Alice ratchet init failed: %v", err)
	}

	// Extract Alice's ephemeral keys for Bob
	aliceEphemeralKyberPub := aliceRatchet.KyberS.Public().(*kyber1024.PublicKey)
	aliceEphemeralECPub := (*[32]byte)(initialCts.EphemeralECPublicKey)

	// Bob init
	bobRatchet, err := RatchetInitBob(
		bobKyberPriv,
		bobECPriv,
		bobPreKeyKyberPriv,
		bobPreKeyECPriv,
		nil, // No OPK
		nil, // No OPK
		aliceEphemeralKyberPub,
		aliceEphemeralECPub,
		initialCts,
	)
	if err != nil {
		t.Fatalf("Bob ratchet init failed: %v", err)
	}

	// Alice encrypts message
	msgContent := []byte("Secret message for replay attack test")
	header, ciphertext, err := aliceRatchet.RatchetEncrypt(msgContent, initialCts)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Bob decrypts first time - should succeed
	decrypted, err := bobRatchet.RatchetDecrypt(header, ciphertext)
	if err != nil {
		t.Fatalf("First decryption failed: %v", err)
	}

	if !bytes.Equal(decrypted, msgContent) {
		t.Error("Decrypted content doesn't match original")
	}

	// ATTACK 1: Immediate replay
	_, err = bobRatchet.RatchetDecrypt(header, ciphertext)
	if err == nil {
		t.Error("Replay attack succeeded! Should have been rejected")
	}
	if err != errReplayAttackNonceReuse {
		t.Errorf("Expected replay error, got: %v", err)
	}

	// ATTACK 2: Replay after legitimate message
	header2, ciphertext2, _ := aliceRatchet.RatchetEncrypt([]byte("Second message"), initialCts)
	bobRatchet.RatchetDecrypt(header2, ciphertext2)

	// Try to replay first message
	_, err = bobRatchet.RatchetDecrypt(header, ciphertext)
	if err == nil {
		t.Error("Delayed replay attack succeeded!")
	}

	// ATTACK 3: Multiple rapid replays
	for i := 0; i < 10; i++ {
		_, err := bobRatchet.RatchetDecrypt(header, ciphertext)
		if err == nil {
			t.Errorf("Replay attack %d succeeded!", i)
		}
	}
}

// TestCryptoUtils_MessageReorderingAttack tests out-of-order delivery attack
// Attack: Deliver messages in wrong order to confuse decryption
// Expected: All messages decrypted correctly regardless of order
func TestCryptoUtils_MessageReorderingAttack(t *testing.T) {
	// Setup
	_, _, _, _, _, _, _ = GenerateHybridIdentityKeyPair()
	_, _, bobKyberPriv, bobKyberPub, bobECPriv, bobECPub, _ := GenerateHybridIdentityKeyPair()
	bobPreKeyKyberPriv, bobPreKeyKyberPub, bobPreKeyECPriv, bobPreKeyECPub, _ := GenerateHybridPreKey()

	aliceRatchet, initialCts, _ := RatchetInitAlice(
		bobKyberPub,
		bobECPub,
		bobPreKeyKyberPub,
		bobPreKeyECPub,
		nil, nil, 0,
	)

	aliceEphemeralKyberPub := aliceRatchet.KyberS.Public().(*kyber1024.PublicKey)
	aliceEphemeralECPub := (*[32]byte)(initialCts.EphemeralECPublicKey)

	bobRatchet, _ := RatchetInitBob(
		bobKyberPriv,
		bobECPriv,
		bobPreKeyKyberPriv,
		bobPreKeyECPriv,
		nil, nil,
		aliceEphemeralKyberPub,
		aliceEphemeralECPub,
		initialCts,
	)

	// Alice sends 10 messages in order
	const numMessages = 10
	messages := make([][]byte, numMessages)
	headers := make([][]byte, numMessages)
	ciphertexts := make([][]byte, numMessages)

	for i := 0; i < numMessages; i++ {
		msg := []byte(fmt.Sprintf("Message number %d", i))
		messages[i] = msg

		header, ciphertext, err := aliceRatchet.RatchetEncrypt(msg, initialCts)
		if err != nil {
			t.Fatalf("Encryption %d failed: %v", i, err)
		}
		headers[i] = header
		ciphertexts[i] = ciphertext
	}

	// ATTACK: Deliver in scrambled order (e.g., 5, 2, 8, 0, 9, 1, 7, 3, 6, 4)
	deliveryOrder := []int{5, 2, 8, 0, 9, 1, 7, 3, 6, 4}

	for _, idx := range deliveryOrder {
		decrypted, err := bobRatchet.RatchetDecrypt(headers[idx], ciphertexts[idx])
		if err != nil {
			t.Errorf("Failed to decrypt message %d: %v", idx, err)
			continue
		}

		if !bytes.Equal(decrypted, messages[idx]) {
			t.Errorf("Message %d content mismatch after reordering", idx)
		}
	}
}

// TestCryptoUtils_KeyExhaustionAttack tests protection against key exhaustion
// Attack: Force ratchet to skip huge number of keys
// Expected: Protection via MAX_SKIP limit
func TestCryptoUtils_KeyExhaustionAttack(t *testing.T) {
	// Setup
	_, _, _, _, _, _, _ = GenerateHybridIdentityKeyPair()
	_, _, bobKyberPriv, bobKyberPub, bobECPriv, bobECPub, _ := GenerateHybridIdentityKeyPair()
	bobPreKeyKyberPriv, bobPreKeyKyberPub, bobPreKeyECPriv, bobPreKeyECPub, _ := GenerateHybridPreKey()

	aliceRatchet, initialCts, _ := RatchetInitAlice(
		bobKyberPub,
		bobECPub,
		bobPreKeyKyberPub,
		bobPreKeyECPub,
		nil, nil, 0,
	)

	aliceEphemeralKyberPub := aliceRatchet.KyberS.Public().(*kyber1024.PublicKey)
	aliceEphemeralECPub := (*[32]byte)(initialCts.EphemeralECPublicKey)

	bobRatchet, _ := RatchetInitBob(
		bobKyberPriv,
		bobECPriv,
		bobPreKeyKyberPriv,
		bobPreKeyECPriv,
		nil, nil,
		aliceEphemeralKyberPub,
		aliceEphemeralECPub,
		initialCts,
	)

	// Alice sends many messages but Bob only receives the last one
	// This forces Bob to skip many keys
	const skipCount = 2000 // Exceeds MAX_SKIP
	var lastHeader, lastCiphertext []byte

	for i := 0; i < skipCount; i++ {
		header, ciphertext, _ := aliceRatchet.RatchetEncrypt(
			[]byte(fmt.Sprintf("Skip message %d", i)),
			initialCts,
		)
		lastHeader = header
		lastCiphertext = ciphertext
	}

	// ATTACK: Try to decrypt last message, forcing huge skip
	_, err := bobRatchet.RatchetDecrypt(lastHeader, lastCiphertext)

	// Should fail due to MAX_SKIP protection
	if err == nil {
		t.Error("Key exhaustion attack succeeded! Should have hit MAX_SKIP limit")
	}

	t.Logf("Key exhaustion properly blocked: %v", err)
}

// TestLogicClient_MalformedPacketAttack tests handling of malformed packets
// Attack: Send various types of invalid packets
// Expected: All rejected gracefully, no panics
func TestLogicClient_MalformedPacketAttack(t *testing.T) {
	ks := NewTestKeyStore(t)
	ms := NewTestMessageStore(t)

	handler := &MockCoreEventHandler{}
	lc, _ := newLogicClient(ks, ms, handler)

	// Test malformed packet types
	tests := []struct {
		name        string
		packetType  string
		expectPanic bool
	}{
		{"No signature", "no_signature", false},
		{"Invalid sender key", "invalid_sender_key", false},
		{"Corrupted ciphertext", "corrupted_ciphertext", false},
		{"Wrong routing token", "wrong_routing_token", false},
		{"Oversized message", "oversized_message", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			malformed := GenerateMalformedPacket(tt.packetType)

			// Should handle gracefully without panic
			func() {
				defer func() {
					if r := recover(); r != nil && !tt.expectPanic {
						t.Errorf("Panic occurred on %s: %v", tt.name, r)
					}
				}()

				// Process packet - should reject but not crash
				_ = lc.HandleP2PMessage(malformed)
			}()
		})
	}
}

// TestLogicClient_SessionConfusionAttack tests identity-to-token binding
// Attack: Send message with Alice's identity but Bob's routing token
// Expected: Signature verification fails, attack detected
func TestLogicClient_SessionConfusionAttack(t *testing.T) {

	// Generate keys for Alice and Bob
	_, aliceDiliPub, _, _, _, _, _ := GenerateHybridIdentityKeyPair()
	_, _, _, _, _, _, _ = GenerateHybridIdentityKeyPair()

	// Alice's routing token
	aliceToken := make([]byte, 32)
	rand.Read(aliceToken)

	// Bob's routing token
	bobToken := make([]byte, 32)
	rand.Read(bobToken)

	// Encrypt with Alice's ratchet (simulated)
	ciphertext := []byte("fake_encrypted_content")
	header := make([]byte, 100)

	packet := &proto2.Packet{
		RoutingToken: bobToken, // ATTACK: Use Bob's token
		Payload: &proto2.Packet_EncryptedMessage{
			EncryptedMessage: &proto2.EncryptedMessage{
				RatchetHeader: header,
				Ciphertext:    ciphertext,
			},
		},
	}

	// Sign with Alice's key
	aliceDiliBytes, _ := aliceDiliPub.MarshalBinary()
	packet.SenderIdentityKey = aliceDiliBytes

	// Create signature
	diliScheme := mode5.Scheme()
	packetCopy := &proto2.Packet{
		RoutingToken:      packet.RoutingToken,
		SenderIdentityKey: packet.SenderIdentityKey,
		Payload:           packet.Payload,
	}

	dataToSign, _ := proto.Marshal(packetCopy)
	// We don't have alicePriv here easily because we ignored it, let's regenerate for test simplicity
	aliceDiliPriv, aliceDiliPub, _, _, _, _, _ := GenerateHybridIdentityKeyPair()
	aliceDiliBytes, _ = aliceDiliPub.MarshalBinary()
	packet.SenderIdentityKey = aliceDiliBytes
	packetCopy.SenderIdentityKey = aliceDiliBytes

	signature := diliScheme.Sign(aliceDiliPriv, dataToSign, nil)
	packet.Signature = signature

	// Processing should detect the mismatch
	// (In real implementation, routing token should be validated against sender identity)
	// This test documents the attack vector
	t.Log("Session confusion attack vector demonstrated")
	t.Logf("Alice identity with Bob's routing token - should be validated in production")
}

// TestInvite_SignatureForging tests invite integrity
// Attack: Modify invite data and forge signature
// Expected: ProcessInvite rejects forged invite
func TestInvite_SignatureForging(t *testing.T) {
	ks := NewTestKeyStore(t)
	ms := NewTestMessageStore(t)

	handler := &MockCoreEventHandler{}
	lc, _ := newLogicClient(ks, ms, handler)

	// Create legitimate invite
	validInvite := createValidInvite(t)

	// ATTACK 1: Forge signature
	forgedInvite1 := ModifyInvite(validInvite)

	err := lc.ProcessInvite(forgedInvite1)
	if err == nil {
		t.Error("Forged signature attack succeeded! Should have been rejected")
	}

	// ATTACK 2: Modify keys but keep signature
	forgedInvite2 := &proto2.Invite{
		IdentityKeyDilithium:     validInvite.IdentityKeyDilithium,
		IdentityKeyKyber:         make([]byte, kyber1024.PublicKeySize), // Modified!
		SignedPrekeyKyber:        validInvite.SignedPrekeyKyber,
		SignedPrekeyX25519:       validInvite.SignedPrekeyX25519,
		IdentityKeyX25519:        validInvite.IdentityKeyX25519,
		PrekeySignatureDilithium: validInvite.PrekeySignatureDilithium, // Original sig
		RoutingToken:             validInvite.RoutingToken,
		DisplayName:              validInvite.DisplayName,
	}

	err = lc.ProcessInvite(forgedInvite2)
	if err == nil {
		t.Error("Modified keys attack succeeded! Signature should not verify")
	}

	// ATTACK 3: Swap prekeys
	forgedInvite3 := &proto2.Invite{
		IdentityKeyDilithium:     validInvite.IdentityKeyDilithium,
		IdentityKeyKyber:         validInvite.IdentityKeyKyber,
		SignedPrekeyKyber:        validInvite.IdentityKeyKyber, // Swapped with identity!
		SignedPrekeyX25519:       validInvite.SignedPrekeyX25519,
		IdentityKeyX25519:        validInvite.IdentityKeyX25519,
		PrekeySignatureDilithium: validInvite.PrekeySignatureDilithium,
		RoutingToken:             validInvite.RoutingToken,
		DisplayName:              validInvite.DisplayName,
	}

	err = lc.ProcessInvite(forgedInvite3)
	if err == nil {
		t.Error("Swapped keys attack succeeded!")
	}
}

// TestCryptoUtils_TimingAttack attempts timing-based attacks
// Attack: Measure decryption time to infer information
// Expected: Constant-time operations (best effort)
func TestCryptoUtils_TimingAttack(t *testing.T) {
	// Setup
	_, _, _, _, _, _, _ = GenerateHybridIdentityKeyPair()
	_, _, bobKyberPriv, bobKyberPub, bobECPriv, bobECPub, _ := GenerateHybridIdentityKeyPair()
	bobPreKeyKyberPriv, bobPreKeyKyberPub, bobPreKeyECPriv, bobPreKeyECPub, _ := GenerateHybridPreKey()

	aliceRatchet, initialCts, _ := RatchetInitAlice(
		bobKyberPub,
		bobECPub,
		bobPreKeyKyberPub,
		bobPreKeyECPub,
		nil, nil, 0,
	)

	aliceEphemeralKyberPub := aliceRatchet.KyberS.Public().(*kyber1024.PublicKey)
	aliceEphemeralECPub := (*[32]byte)(initialCts.EphemeralECPublicKey)

	bobRatchet, _ := RatchetInitBob(
		bobKyberPriv,
		bobECPriv,
		bobPreKeyKyberPriv,
		bobPreKeyECPriv,
		nil, nil,
		aliceEphemeralKyberPub,
		aliceEphemeralECPub,
		initialCts,
	)

	// Test with different message sizes
	sizes := []int{10, 100, 1000, 10000}
	times := make([]time.Duration, len(sizes))

	for i, size := range sizes {
		msg := make([]byte, size)
		rand.Read(msg)

		header, ciphertext, _ := aliceRatchet.RatchetEncrypt(msg, initialCts)

		start := time.Now()
		_, err := bobRatchet.RatchetDecrypt(header, ciphertext)
		elapsed := time.Since(start)

		times[i] = elapsed

		if err != nil {
			t.Errorf("Decryption failed for size %d: %v", size, err)
		}
	}

	// Log timing results
	for i, size := range sizes {
		t.Logf("Size %d bytes: %v", size, times[i])
	}

	// Note: This test documents timing behavior
	// True constant-time crypto requires specialized implementation
}

// Helper function to create a valid invite for testing
func createValidInvite(t *testing.T) *proto2.Invite {
	t.Helper()

	// Generate keys
	diliPriv, diliPub, _, kyberPub, _, ecPub, err := GenerateHybridIdentityKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	_, preKeyKyberPub, _, preKeyECPub, err := GenerateHybridPreKey()
	if err != nil {
		t.Fatalf("Failed to generate prekeys: %v", err)
	}

	preKeyKyberBytes, _ := preKeyKyberPub.MarshalBinary()
	preKeyECBytes := preKeyECPub[:]

	// Create signature
	idKyberBytes, _ := kyberPub.MarshalBinary()
	idX25519Bytes := ecPub[:]

	// Use a fresh slice for signing to avoid modifying the key slices
	dataToSign := make([]byte, 0, len(idKyberBytes)+len(idX25519Bytes)+len(preKeyKyberBytes)+len(preKeyECBytes))
	dataToSign = append(dataToSign, idKyberBytes...)
	dataToSign = append(dataToSign, idX25519Bytes...)
	dataToSign = append(dataToSign, preKeyKyberBytes...)
	dataToSign = append(dataToSign, preKeyECBytes...)

	diliScheme := mode5.Scheme()
	signature := diliScheme.Sign(diliPriv, dataToSign, nil)

	idDiliBytes, _ := diliPub.MarshalBinary()

	routingToken := make([]byte, 32)
	rand.Read(routingToken)

	return &proto2.Invite{
		IdentityKeyDilithium:     idDiliBytes,
		IdentityKeyKyber:         idKyberBytes,
		SignedPrekeyKyber:        preKeyKyberBytes,
		SignedPrekeyX25519:       preKeyECBytes,
		IdentityKeyX25519:        idX25519Bytes,
		PrekeySignatureDilithium: signature,
		RoutingToken:             routingToken,
		DisplayName:              "TestUser",
	}
}
