package tests

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	phantomcore "phantom/client"
)

// TestIntegration performs a full end-to-end test.
func TestIntegration(t *testing.T) {
	// 1. Build Server
	serverBin := filepath.Join(os.TempDir(), "phantom_server_test")
	cmdBuild := exec.Command("go", "build", "-o", serverBin, "../server")
	if out, err := cmdBuild.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build server: %v\n%s", err, out)
	}
	defer os.Remove(serverBin)

	// 2. Start Server
	// Server listens on 0.0.0.0:50051 by default (hardcoded in main.go)
	port := "50051"
	serverAddr := "localhost:" + port

	// Set required env var
	os.Setenv("PHANTOM_PRIVATE_SALT", "test-private-salt-32-bytes-long-exactly")

	// Create a temp dir for server execution to avoid key conflicts
	serverDir, err := os.MkdirTemp("", "phantom_server_exec")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(serverDir)

	cmdServer := exec.Command(serverBin, "-host", "localhost")
	cmdServer.Dir = serverDir // Run in temp dir
	// cmdServer.Stdout = os.Stdout // Uncomment for debug
	cmdServer.Stderr = os.Stderr
	if err := cmdServer.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer func() {
		if cmdServer.Process != nil {
			cmdServer.Process.Kill()
		}
	}()

	// Wait for server to start
	time.Sleep(5 * time.Second)

	// 3. Setup Clients
	tempDir, err := os.MkdirTemp("", "phantom_test_clients")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	aliceDir := filepath.Join(tempDir, "alice")
	bobDir := filepath.Join(tempDir, "bob")
	os.MkdirAll(aliceDir, 0700)
	os.MkdirAll(bobDir, 0700)

	pin := "1234"

	// Initialize Alice
	aliceHandler := &TestHandler{Name: "Alice"}
	aliceCore, err := phantomcore.NewCore("Alice", pin, aliceDir, aliceHandler)
	if err != nil {
		t.Fatalf("Failed to init Alice: %v", err)
	}
	go func() {
		if err := aliceCore.Start(serverAddr, phantomcore.Auto); err != nil {
			t.Logf("Alice Start error (might be expected on stop): %v", err)
		}
	}()

	// Initialize Bob
	bobHandler := &TestHandler{Name: "Bob"}
	bobCore, err := phantomcore.NewCore("Bob", pin, bobDir, bobHandler)
	if err != nil {
		t.Fatalf("Failed to init Bob: %v", err)
	}
	go func() {
		if err := bobCore.Start(serverAddr, phantomcore.Auto); err != nil {
			t.Logf("Bob Start error (might be expected on stop): %v", err)
		}
	}()

	// Wait for connections
	time.Sleep(1 * time.Second)

	// 4. Alice creates invite
	inviteCode, err := aliceCore.CreateInvite("Alice Display Name")
	if err != nil {
		t.Fatalf("Alice failed to create invite: %v", err)
	}
	t.Logf("Invite code generated")

	// 5. Bob accepts invite
	err = bobCore.ProcessInvite(inviteCode)
	if err != nil {
		t.Fatalf("Bob failed to process invite: %v", err)
	}
	t.Logf("Bob accepted invite")

	// Wait for contact sync / registration
	time.Sleep(1 * time.Second)

	// Get Alice's hash from Bob's contacts
	contacts, err := bobCore.GetContacts()
	if err != nil {
		t.Fatalf("Bob failed to get contacts: %v", err)
	}
	if len(contacts) == 0 {
		t.Fatal("Bob has no contacts")
	}
	aliceHash := contacts[0].Hash
	t.Logf("Bob found Alice: %s", aliceHash)

	// 6. Bob sends message to Alice
	msgContent := "Hello Alice, this is Bob!"
	err = bobCore.SendMessage(aliceHash, msgContent)
	if err != nil {
		t.Fatalf("Bob failed to send message: %v", err)
	}
	t.Logf("Bob sent message")

	// 7. Verify Alice received it
	// We can check Alice's message store or wait for the handler callback.
	// For simplicity, let's poll GetMessages.

	// Alice needs to know Bob's hash to query messages.
	// Since Bob initiated the contact via invite, Alice might not have Bob in contacts yet
	// UNTIL she receives the first message (if the protocol supports implicit contact creation)
	// OR if the invite process is two-way.
	// In the current logic, ProcessInvite adds contact for Bob.
	// But Alice doesn't know Bob until Bob sends a message with his identity?
	// Actually, the invite is one-way (Bob adds Alice).
	// When Bob sends a message, he includes his identity.
	// Alice should receive it and verify.

	// Let's wait a bit for delivery
	time.Sleep(2 * time.Second)

	// Alice should have received the message.
	// We can check the handler's received messages.
	if len(aliceHandler.ReceivedMessages) == 0 {
		t.Fatal("Alice did not receive any messages")
	}

	lastMsg := aliceHandler.ReceivedMessages[0]
	if lastMsg.Content != msgContent {
		t.Errorf("Message content mismatch. Got: %s, Want: %s", lastMsg.Content, msgContent)
	}
	t.Logf("Alice received message: %s", lastMsg.Content)
}

// TestHandler implements CoreEventHandler for testing
type TestHandler struct {
	Name             string
	ReceivedMessages []phantomcore.StoredMessage
}

func (h *TestHandler) OnMessageReceived(msg phantomcore.StoredMessage) {
	fmt.Printf("[%s] Received: %s\n", h.Name, msg.Content)
	h.ReceivedMessages = append(h.ReceivedMessages, msg)
}

func (h *TestHandler) OnContactListUpdated(contacts []phantomcore.ContactInfo) {}
func (h *TestHandler) OnSessionEstablished(peerHash string) {
	fmt.Printf("[%s] Session established with %s\n", h.Name, peerHash)
}
func (h *TestHandler) OnLog(level phantomcore.LogLevel, message string) {
	fmt.Printf("[%s LOG] %s\n", h.Name, message)
}
func (h *TestHandler) OnConnectionStateChanged(state string, err error) {}
func (h *TestHandler) OnShutdown(message string)                        {}
func (h *TestHandler) OnP2PStateChanged(isActive bool, peers []string)  {}
