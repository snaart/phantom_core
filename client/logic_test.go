package phantomcore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"testing"

	pb "phantom/proto"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/sign/dilithium/mode5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// MockCoreEventHandler implements CoreEventHandler
type MockCoreEventHandler struct {
	Logs []string
	mu   sync.Mutex
}

func (m *MockCoreEventHandler) OnLog(level LogLevel, msg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Logs = append(m.Logs, msg)
}

func (m *MockCoreEventHandler) OnMessageReceived(message StoredMessage)          {}
func (m *MockCoreEventHandler) OnContactListUpdated(contacts []ContactInfo)      {}
func (m *MockCoreEventHandler) OnConnectionStateChanged(state string, err error) {}
func (m *MockCoreEventHandler) OnSessionEstablished(peerHash string)             {}
func (m *MockCoreEventHandler) OnShutdown(message string)                        {}
func (m *MockCoreEventHandler) OnP2PStateChanged(isActive bool, peers []string)  {}

// MockTransmitClient implements pb.Phantom_TransmitClient
type MockTransmitClient struct {
	grpc.ClientStream
	SentPackets []*pb.Packet
	RecvPackets []*pb.Packet
	RecvIndex   int
}

func (m *MockTransmitClient) Send(p *pb.Packet) error {
	m.SentPackets = append(m.SentPackets, p)
	return nil
}

func (m *MockTransmitClient) Recv() (*pb.Packet, error) {
	if m.RecvIndex >= len(m.RecvPackets) {
		return nil, io.EOF
	}
	p := m.RecvPackets[m.RecvIndex]
	m.RecvIndex++
	return p, nil
}

func (m *MockTransmitClient) CloseSend() error {
	return nil
}

func (m *MockTransmitClient) Context() context.Context {
	return context.Background()
}

func (m *MockTransmitClient) Header() (metadata.MD, error) {
	return nil, nil
}

func (m *MockTransmitClient) Trailer() metadata.MD {
	return nil
}

func (m *MockTransmitClient) RecvMsg(m_ interface{}) error {
	return nil
}

func (m *MockTransmitClient) SendMsg(m_ interface{}) error {
	return nil
}

func TestLogicClient_ProcessInvite(t *testing.T) {
	// 1. Setup
	tempDir := t.TempDir()
	ksPath := filepath.Join(tempDir, "keystore.db")
	msPath := filepath.Join(tempDir, "messages.db")

	ks, _ := NewKeyStore(ksPath)
	ms, _ := NewMessageStore(msPath)

	pin := "1234"
	ks.Initialize(pin)
	ks.CreateAccount()
	ms.Initialize(pin)
	ms.Unlock(pin)

	handler := &MockCoreEventHandler{}
	lc, err := newLogicClient(ks, ms, handler)
	if err != nil {
		t.Fatalf("newLogicClient failed: %v", err)
	}

	// 2. Create a valid Invite
	// Generate Alice's keys
	aliceIDPub, aliceIDPriv, _ := mode5.GenerateKey(nil)
	aliceKyberPub, _, _ := kyber1024.GenerateKeyPair(nil)

	// Sign the Kyber + X25519 keys
	var kyberBytes [kyber1024.PublicKeySize]byte
	aliceKyberPub.Pack(kyberBytes[:])

	// Generate X25519 keys (dummy for test, but needed for signature)
	var x25519Pub [32]byte
	// Fill with zeros or random

	// Signature covers: IdentityKeyKyber || IdentityKeyX25519 || SignedPrekeyKyber || SignedPrekeyX25519
	// We use the same keys for identity and prekeys in this simple test
	msg := make([]byte, 0, len(kyberBytes)+len(x25519Pub)+len(kyberBytes)+len(x25519Pub))
	msg = append(msg, kyberBytes[:]...)
	msg = append(msg, x25519Pub[:]...)
	msg = append(msg, kyberBytes[:]...) // SignedPrekeyKyber
	msg = append(msg, x25519Pub[:]...)  // SignedPrekeyX25519

	signature := mode5.Scheme().Sign(aliceIDPriv, msg, nil)

	invite := &pb.Invite{
		IdentityKeyDilithium:     make([]byte, mode5.PublicKeySize),
		IdentityKeyKyber:         kyberBytes[:],
		IdentityKeyX25519:        x25519Pub[:],
		SignedPrekeyKyber:        kyberBytes[:], // Using same key for simplicity or generate new
		SignedPrekeyX25519:       x25519Pub[:],
		PrekeySignatureDilithium: signature,
	}

	var diliOut [mode5.PublicKeySize]byte
	aliceIDPub.Pack(&diliOut)
	invite.IdentityKeyDilithium = diliOut[:]

	// 3. Process Invite
	err = lc.ProcessInvite(invite)
	if err != nil {
		t.Fatalf("ProcessInvite failed: %v", err)
	}

	// 4. Verify Contact Saved
	contacts, _ := ks.ListContacts()
	if len(contacts) != 1 {
		t.Errorf("Expected 1 contact, got %d", len(contacts))
	}
}

func TestLogicClient_Register(t *testing.T) {
	// 1. Setup
	tempDir := t.TempDir()
	ksPath := filepath.Join(tempDir, "keystore_reg.db")
	msPath := filepath.Join(tempDir, "messages_reg.db")

	ks, _ := NewKeyStore(ksPath)
	ms, _ := NewMessageStore(msPath)

	pin := "1234"
	ks.Initialize(pin)
	ks.CreateAccount()

	handler := &MockCoreEventHandler{}
	lc, _ := newLogicClient(ks, ms, handler)

	mockStream := &MockTransmitClient{}
	lc.stream = mockStream

	// 2. Register
	err := lc.register()
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	// 3. Verify Packet Sent
	if len(mockStream.SentPackets) != 1 {
		t.Fatalf("Expected 1 packet sent, got %d", len(mockStream.SentPackets))
	}

	packet := mockStream.SentPackets[0]
	if packet.GetRegistrationRequest() == nil {
		t.Error("Expected RegistrationRequest payload")
	}
	// Verify ListenTokens are present
	if len(packet.GetRegistrationRequest().ListenTokens) == 0 {
		t.Error("Expected ListenTokens in RegistrationRequest")
	}
}

func TestLogicClient_SendMessage_NoSession(t *testing.T) {
	// Test sending a message when no session exists

	tempDir := t.TempDir()
	ksPath := filepath.Join(tempDir, "keystore_msg.db")
	msPath := filepath.Join(tempDir, "messages_msg.db")

	ks, _ := NewKeyStore(ksPath)
	ms, _ := NewMessageStore(msPath)

	pin := "1234"
	ks.Initialize(pin)
	ks.CreateAccount()
	ms.Initialize(pin)
	ms.Unlock(pin)

	handler := &MockCoreEventHandler{}
	lc, _ := newLogicClient(ks, ms, handler)

	// Create a dummy contact
	pubKey, _, _ := mode5.GenerateKey(nil)
	contact := &Contact{
		IdentityKeyHash:      "dest_hash",
		DisplayName:          "Bob",
		OutboundRoutingToken: []byte("bob_token"),
		IdentityPublicDili:   pubKey,
	}
	ks.SaveContact(contact)

	// Mock stream
	mockStream := &MockTransmitClient{}
	lc.stream = mockStream

	// Send Message
	err := lc.sendMessage("dest_hash", "Hello Bob")

	if err == nil {
		t.Fatal("Expected error due to missing keys, got nil")
	}
}
func TestLogicClient_EstablishSessionAndReceive(t *testing.T) {
	// 1. Setup Bob (LogicClient)
	tempDir := t.TempDir()
	ksPath := filepath.Join(tempDir, "keystore_bob.db")
	msPath := filepath.Join(tempDir, "messages_bob.db")

	ks, _ := NewKeyStore(ksPath)
	ms, _ := NewMessageStore(msPath)

	pin := "1234"
	ks.Initialize(pin)
	ks.CreateAccount()
	ms.Initialize(pin)
	ms.Unlock(pin)

	handler := &MockCoreEventHandler{}
	lc, _ := newLogicClient(ks, ms, handler)
	lc.stream = &MockTransmitClient{}

	// 2. Setup Alice (Initiator)
	// We need Alice's keys to generate the initial message
	_, _, _, _, _, _, _ = GenerateHybridIdentityKeyPair() // Ignore Alice's keys for now, we generate them as needed
	// We need Bob's public keys (from KeyStore)
	var bobIDKyberPub *kyber1024.PublicKey
	var bobIDECPub *[32]byte
	var bobSPKyberPub *kyber1024.PublicKey
	var bobSPECPub *[32]byte
	var bobOPKyberPub *kyber1024.PublicKey
	var bobOPECPub *[32]byte
	var opkID uint32

	ks.WithUserAccount(func(ua *UserAccount) error {
		bobIDKyberPub = ua.IdentityPublicKyber
		bobIDECPub = ua.IdentityPublicX25519
		bobSPKyberPub = ua.PreKeyPublicKyber
		bobSPECPub = ua.PreKeyPublicX25519
		// Generate an OPK for Bob
		ks.ReplenishOPKs(ua)
		for id, key := range ua.OneTimePreKeys {
			opkID = id
			bobOPKyberPub = key.PublicKeyKyber
			bobOPECPub = key.PublicKeyX25519
			break
		}
		return nil
	})

	// 3. Alice initializes Ratchet and encrypts message
	aliceRatchet, initialCts, err := RatchetInitAlice(
		bobIDKyberPub, bobIDECPub,
		bobSPKyberPub, bobSPECPub,
		bobOPKyberPub, bobOPECPub,
		opkID,
	)
	if err != nil {
		t.Fatalf("RatchetInitAlice failed: %v", err)
	}

	msgContent := []byte("Hello Bob, it's Alice!")
	headerBytes, ciphertext, err := aliceRatchet.RatchetEncrypt(msgContent, initialCts)
	if err != nil {
		t.Fatalf("RatchetEncrypt failed: %v", err)
	}

	// 4. Construct Packet
	// We need Alice's Identity Key (Dilithium) for the packet
	aliceDiliPub, _, _ := mode5.GenerateKey(nil)
	var aliceDiliPubBytes [mode5.PublicKeySize]byte
	aliceDiliPub.Pack(&aliceDiliPubBytes)

	packet := &pb.Packet{
		SenderIdentityKey: aliceDiliPubBytes[:],
		Payload: &pb.Packet_EncryptedMessage{
			EncryptedMessage: &pb.EncryptedMessage{
				RatchetHeader: headerBytes,
				Ciphertext:    ciphertext,
			},
		},
	}

	// 5. Call tryEstablishSessionAsBob
	// We need a peerHash. In reality, it's derived from SenderIdentityKey.
	// SaveContact derives hash from the key, so we must use that hash for lookup.
	peerHash := fmt.Sprintf("%x", aliceDiliPubBytes)

	success := lc.tryEstablishSessionAsBob(peerHash, packet)
	if !success {
		t.Fatal("tryEstablishSessionAsBob returned false")
	}

	// 6. Verify Session Established
	// Check if contact exists and has RatchetState
	contact, err := ks.LoadContact(peerHash)
	if err != nil {
		t.Fatalf("Failed to load contact: %v", err)
	}
	if contact == nil {
		t.Fatal("Contact not created")
	}
	if len(contact.RatchetState) == 0 {
		t.Fatal("RatchetState is empty")
	}
	contactDiliBytes, _ := contact.IdentityPublicDili.MarshalBinary()
	if !bytes.Equal(contactDiliBytes, aliceDiliPubBytes[:]) {
		t.Error("Identity Key mismatch")
	}

	// 7. Verify Message Decryption
	var bobRatchet DoubleRatchet
	json.Unmarshal(contact.RatchetState, &bobRatchet)

	// Bob's ratchet should be able to decrypt the message
	decrypted, err := bobRatchet.RatchetDecrypt(headerBytes, ciphertext)
	if err != nil {
		t.Fatalf("Manual decryption failed: %v", err)
	}
	if !bytes.Equal(decrypted, msgContent) {
		t.Errorf("Decrypted content mismatch: got %s, want %s", decrypted, msgContent)
	}
}
