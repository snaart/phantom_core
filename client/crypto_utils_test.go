package phantomcore

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
)

func TestGenerateHybridIdentityKeyPair(t *testing.T) {
	diliPriv, diliPub, kyberPriv, kyberPub, ecPriv, ecPub, err := GenerateHybridIdentityKeyPair()
	if err != nil {
		t.Fatalf("GenerateHybridIdentityKeyPair failed: %v", err)
	}
	if diliPriv == nil || diliPub == nil {
		t.Error("Dilithium keys are nil")
	}
	if kyberPriv == nil || kyberPub == nil {
		t.Error("Kyber keys are nil")
	}
	if ecPriv == nil || ecPub == nil {
		t.Error("EC keys are nil")
	}
}

func TestGenerateHybridPreKey(t *testing.T) {
	kyberPriv, kyberPub, ecPriv, ecPub, err := GenerateHybridPreKey()
	if err != nil {
		t.Fatalf("GenerateHybridPreKey failed: %v", err)
	}
	if kyberPriv == nil || kyberPub == nil {
		t.Error("Kyber keys are nil")
	}
	if ecPriv == nil || ecPub == nil {
		t.Error("EC keys are nil")
	}
}

func TestRatchetInitAndExchange(t *testing.T) {
	// 1. Setup Alice and Bob Identity and PreKeys
	_, _, _, _, _, _, err := GenerateHybridIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, _, bobIDKyberPriv, bobIDKyberPub, bobIDECPriv, bobIDECPub, err := GenerateHybridIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	bobSPKyberPriv, bobSPKyberPub, bobSPECPriv, bobSPECPub, err := GenerateHybridPreKey()
	if err != nil {
		t.Fatal(err)
	}

	bobOPKyberPriv, bobOPKyberPub, bobOPECPriv, bobOPECPub, err := GenerateHybridPreKey()
	if err != nil {
		t.Fatal(err)
	}
	opkID := uint32(1)

	// 2. Alice initializes Ratchet
	aliceRatchet, initialCts, err := RatchetInitAlice(
		bobIDKyberPub, bobIDECPub,
		bobSPKyberPub, bobSPECPub,
		bobOPKyberPub, bobOPECPub,
		opkID,
	)
	if err != nil {
		t.Fatalf("RatchetInitAlice failed: %v", err)
	}

	// 3. Bob initializes Ratchet
	// Alice's ephemeral key is in her KyberS (private). We need the public part.
	aliceEphemeralPub := aliceRatchet.KyberS.Public().(*kyber1024.PublicKey)

	bobRatchet, err := RatchetInitBob(
		bobIDKyberPriv, bobIDECPriv,
		bobSPKyberPriv, bobSPECPriv,
		bobOPKyberPriv, bobOPECPriv, // Use bobOPECPriv here
		aliceEphemeralPub,
		(*[32]byte)(initialCts.EphemeralECPublicKey),
		initialCts,
	)
	if err != nil {
		t.Fatalf("RatchetInitBob failed: %v", err)
	}

	// 4. Verify Root Keys match
	if !bytes.Equal(aliceRatchet.RK, bobRatchet.RK) {
		t.Error("Root Keys do not match")
	}

	// 5. Alice sends message to Bob
	msg1 := []byte("Hello Bob!")
	header1, ct1, err := aliceRatchet.RatchetEncrypt(msg1, initialCts) // First message carries initialCts
	if err != nil {
		t.Fatalf("Alice failed to encrypt msg1: %v", err)
	}

	decrypted1, err := bobRatchet.RatchetDecrypt(header1, ct1)
	if err != nil {
		t.Fatalf("Bob failed to decrypt msg1: %v", err)
	}
	if !bytes.Equal(msg1, decrypted1) {
		t.Errorf("Decrypted msg1 mismatch: got %s, want %s", decrypted1, msg1)
	}

	// 6. Bob sends message to Alice
	msg2 := []byte("Hello Alice!")
	header2, ct2, err := bobRatchet.RatchetEncrypt(msg2, nil)
	if err != nil {
		t.Fatalf("Bob failed to encrypt msg2: %v", err)
	}

	decrypted2, err := aliceRatchet.RatchetDecrypt(header2, ct2)
	if err != nil {
		t.Fatalf("Alice failed to decrypt msg2: %v", err)
	}
	if !bytes.Equal(msg2, decrypted2) {
		t.Errorf("Decrypted msg2 mismatch: got %s, want %s", decrypted2, msg2)
	}

	// 7. Ping-Pong
	msg3 := []byte("How are you?")
	header3, ct3, err := aliceRatchet.RatchetEncrypt(msg3, nil)
	if err != nil {
		t.Fatal(err)
	}
	decrypted3, err := bobRatchet.RatchetDecrypt(header3, ct3)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg3, decrypted3) {
		t.Error("Mismatch msg3")
	}
}

func TestRatchetSerialization(t *testing.T) {
	// Setup minimal ratchet
	dr := &DoubleRatchet{
		RK:             make([]byte, 32),
		CKs:            make([]byte, 32),
		CKr:            make([]byte, 32),
		Ns:             1,
		Nr:             2,
		PN:             3,
		MKSKIPPED:      make(map[string][]byte),
		ReceivedNonces: make(map[string]time.Time),
	}
	// Generate dummy keys for serialization
	kemScheme := kyber1024.Scheme()
	pk, sk, _ := kemScheme.GenerateKeyPair()
	dr.KyberS = sk.(*kyber1024.PrivateKey)
	dr.KyberR = pk.(*kyber1024.PublicKey)
	dr.ECS = new([32]byte)
	dr.ECSPub = new([32]byte)
	dr.ECR = new([32]byte)

	data, err := json.Marshal(dr)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var dr2 DoubleRatchet
	if err := json.Unmarshal(data, &dr2); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if dr.Ns != dr2.Ns || dr.Nr != dr2.Nr {
		t.Error("Fields mismatch after serialization")
	}
}

func TestZeroize(t *testing.T) {
	dr := &DoubleRatchet{
		RK:  make([]byte, 32),
		CKs: make([]byte, 32),
	}
	dr.Zeroize()
	if dr.RK != nil || dr.CKs != nil {
		t.Error("Zeroize failed to clear fields")
	}
}

func TestReplayProtection(t *testing.T) {
	// Setup Alice and Bob
	_, _, _, _, _, _, err := GenerateHybridIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Mocking a ratchet state for decryption
	_ = &DoubleRatchet{
		ReceivedNonces: make(map[string]time.Time),
	}

	// Create a dummy header
	header := RatchetHeader{
		Timestamp: time.Now().Unix(),
		Nonce:     make([]byte, 16),
	}
	rand.Read(header.Nonce)

	headerBytes, _ := json.Marshal(header)

	// We need a valid ciphertext structure to pass the initial checks in RatchetDecrypt
	// But RatchetDecrypt does replay check BEFORE decryption logic.
	// However, it parses header first.

	// To test strictly ReplayProtection without full crypto setup, we might need to mock or rely on the fact that it returns specific errors.

	// Let's use a full setup to be safe.
	aliceRatchet, bobRatchet, _ := setupSession(t)

	msg := []byte("test")
	headerBytes, ct, err := aliceRatchet.RatchetEncrypt(msg, nil)
	if err != nil {
		t.Fatal(err)
	}

	// 1. First decrypt should succeed
	_, err = bobRatchet.RatchetDecrypt(headerBytes, ct)
	if err != nil {
		t.Fatalf("First decrypt failed: %v", err)
	}

	// 2. Second decrypt of SAME message should fail
	_, err = bobRatchet.RatchetDecrypt(headerBytes, ct)
	if err != errReplayAttackNonceReuse {
		t.Errorf("Expected replay error, got: %v", err)
	}
}

func TestMessageOrdering(t *testing.T) {
	aliceRatchet, bobRatchet, _ := setupSession(t)

	// Alice sends 3 messages
	h1, ct1, _ := aliceRatchet.RatchetEncrypt([]byte("1"), nil)
	h2, ct2, _ := aliceRatchet.RatchetEncrypt([]byte("2"), nil)
	h3, ct3, _ := aliceRatchet.RatchetEncrypt([]byte("3"), nil)

	// Bob receives 3, then 1 (2 is skipped/lost)

	// Receive 3
	d3, err := bobRatchet.RatchetDecrypt(h3, ct3)
	if err != nil {
		t.Fatalf("Failed to decrypt 3: %v", err)
	}
	if string(d3) != "3" {
		t.Error("Wrong content 3")
	}

	// Receive 1 (should be in skipped keys)
	d1, err := bobRatchet.RatchetDecrypt(h1, ct1)
	if err != nil {
		t.Fatalf("Failed to decrypt 1: %v", err)
	}
	if string(d1) != "1" {
		t.Error("Wrong content 1")
	}

	// Receive 2 (should be in skipped keys)
	d2, err := bobRatchet.RatchetDecrypt(h2, ct2)
	if err != nil {
		t.Fatalf("Failed to decrypt 2: %v", err)
	}
	if string(d2) != "2" {
		t.Error("Wrong content 2")
	}
}

// Helper to setup session
func setupSession(t *testing.T) (*DoubleRatchet, *DoubleRatchet, *InitialCiphertexts) {
	_, _, _, _, _, _, _ = GenerateHybridIdentityKeyPair()
	_, _, bobIDKyberPriv, bobIDKyberPub, bobIDECPriv, bobIDECPub, _ := GenerateHybridIdentityKeyPair()
	bobSPKyberPriv, bobSPKyberPub, bobSPECPriv, bobSPECPub, _ := GenerateHybridPreKey()
	bobOPKyberPriv, bobOPKyberPub, bobOPECPriv, bobOPECPub, _ := GenerateHybridPreKey()

	aliceRatchet, initialCts, err := RatchetInitAlice(
		bobIDKyberPub, bobIDECPub,
		bobSPKyberPub, bobSPECPub,
		bobOPKyberPub, bobOPECPub,
		1,
	)
	if err != nil {
		t.Fatal(err)
	}

	aliceEphemeralPub := aliceRatchet.KyberS.Public().(*kyber1024.PublicKey)

	bobRatchet, err := RatchetInitBob(
		bobIDKyberPriv, bobIDECPriv,
		bobSPKyberPriv, bobSPECPriv,
		bobOPKyberPriv, bobOPECPriv, // Use bobOPECPriv here
		aliceEphemeralPub,
		(*[32]byte)(initialCts.EphemeralECPublicKey),
		initialCts,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Fix: Alice needs her own private keys in the ratchet to decrypt Bob's replies
	// RatchetInitAlice sets KyberS and ECS (ephemeral).
	// But for RatchetInitAlice, she is the initiator.

	return aliceRatchet, bobRatchet, initialCts
}
