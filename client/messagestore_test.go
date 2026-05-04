package phantomcore

import (
	"path/filepath"
	"testing"
	"time"
)

func TestMessageStore_Lifecycle(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_messages.db")
	ms, err := NewMessageStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create MessageStore: %v", err)
	}

	pin := "123456"

	// 1. Initialize
	err = ms.Initialize(pin)
	if err != nil {
		t.Fatalf("Failed to initialize MessageStore: %v", err)
	}

	// 2. Unlock (Success)
	err = ms.Unlock(pin)
	if err != nil {
		t.Fatalf("Failed to unlock MessageStore: %v", err)
	}

	// 3. Unlock (Wrong PIN)
	// Note: Unlock currently just derives the key. It doesn't explicitly validate the PIN
	// unless there's a check mechanism (like a known encrypted value).
	// Looking at the code, it loads salt and derives key.
	// If we try to load messages with wrong key, it should fail decryption.

	// Let's create a new instance to simulate restart
	ms2, err := NewMessageStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create MessageStore 2: %v", err)
	}
	err = ms2.Unlock("wrong_pin")
	if err != nil {
		// It might not error here if it just derives key.
		// But let's proceed to try saving/loading.
	}

	// 4. Save Message
	msg := StoredMessage{
		SessionHash: "session_1",
		IsOutgoing:  true,
		Timestamp:   time.Now().Unix(),
		Content:     "Hello, World!",
	}
	err = ms.SaveMessage(msg.SessionHash, msg.IsOutgoing, msg.Timestamp, msg.Content)
	if err != nil {
		t.Fatalf("Failed to save message: %v", err)
	}

	// 5. Load History
	history, err := ms.LoadHistory("session_1", 10)
	if err != nil {
		t.Fatalf("Failed to load history: %v", err)
	}
	if len(history) != 1 {
		t.Errorf("Expected 1 message, got %d", len(history))
	}
	if history[0].Content != "Hello, World!" {
		t.Errorf("Expected content 'Hello, World!', got '%s'", history[0].Content)
	}

	// 6. Test Decryption Failure with Wrong PIN
	// ms2 has wrong pin derived key (if Unlock didn't fail)
	history2, err := ms2.LoadHistory("session_1", 10)
	if err == nil && len(history2) > 0 {
		// If it managed to decrypt with wrong pin, that's bad (or collision, unlikely)
		// Or maybe Unlock didn't actually set the key if it failed?
		// But we expect it to fail decryption.
		t.Error("Expected error or empty history when loading with wrong PIN")
	}
}
