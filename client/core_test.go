package phantomcore

import (
	"testing"
	"time"
)

func TestCore_Lifecycle(t *testing.T) {
	tempDir := t.TempDir()

	// Create Core
	handler := &MockCoreEventHandler{}
	core, err := NewCore("testuser", "1234", tempDir, handler)
	if err != nil {
		t.Fatalf("NewCore failed: %v", err)
	}

	// Start
	// Start is blocking? No, it starts goroutines.
	// But it might block if it tries to connect to P2P/Server.
	// We should mock the transport or ensure it doesn't block forever.
	// Core.Start() calls logic.init() and p2p.Start().

	// We use P2P transport to avoid connecting to a real server
	errChan := make(chan error)
	go func() {
		errChan <- core.Start("localhost:9000", P2P)
	}()

	select {
	case err := <-errChan:
		if err != nil {
			t.Fatalf("Start failed: %v", err)
		}
	case <-time.After(1 * time.Second):
		// Assuming it started successfully if it didn't return error immediately
	}

	// Stop
	core.Stop()
}

func TestCore_SendMessage_NoSession(t *testing.T) {
	tempDir := t.TempDir()

	handler := &MockCoreEventHandler{}
	core, err := NewCore("testuser", "1234", tempDir, handler)
	if err != nil {
		t.Fatalf("NewCore failed: %v", err)
	}

	// Create a dummy contact
	// We need to access KeyStore directly to save a contact?
	// Core exposes GetContacts but not SaveContact directly (it's internal logic).
	// But we can access core.ks (it's private).
	// We can use CreateInvite to generate an invite, but that doesn't add a contact.
	// ProcessInvite adds a contact.

	// Let's use ProcessInvite to add a contact.
	// We need a valid Invite.
	// Reuse logic from logic_test.go?
	// Or just try SendMessage to a non-existent contact -> should fail.

	err = core.SendMessage("non_existent_hash", "Hello")
	if err == nil {
		t.Fatal("Expected error sending to non-existent contact")
	}
}
