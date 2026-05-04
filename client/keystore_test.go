package phantomcore

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode5"
)

func TestKeyStore_Lifecycle(t *testing.T) {
	// 1. Setup
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_keystore.db")
	ks, err := NewKeyStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create KeyStore: %v", err)
	}

	pin := "123456"
	// Initialize first (sets PIN)
	err = ks.Initialize(pin)
	if err != nil {
		t.Fatalf("Failed to initialize KeyStore: %v", err)
	}

	// 2. Create Account
	err = ks.CreateAccount()
	if err != nil {
		t.Fatalf("Failed to create account: %v", err)
	}

	// 3. Verify Account Exists
	exists, err := ks.AccountExists()
	if err != nil {
		t.Fatalf("Failed to check account existence: %v", err)
	}
	if !exists {
		t.Fatal("Account should exist after creation")
	}

	// 4. Load Account (via WithUserAccount)
	err = ks.WithUserAccount(func(ua *UserAccount) error {
		if ua == nil {
			return errors.New("UserAccount is nil")
		}
		if ua.IdentityPublicKyber == nil {
			return errors.New("IdentityPublicKyber is nil")
		}
		if ua.IdentityPrivateKyber == nil {
			return errors.New("IdentityPrivateKyber is nil")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Failed to load account: %v", err)
	}

	// 5. Load Account (Wrong PIN)
	// To test wrong PIN, we need a new KeyStore instance because the existing one has encKey cached.
	ks2, _ := NewKeyStore(dbPath)
	// Unlock with wrong PIN
	err = ks2.Unlock("wrong_pin")
	if err == nil {
		t.Fatal("Expected error when unlocking with wrong PIN, got nil")
	}

	// 6. Save Account (Update)
	// We can't call saveAccount directly. We can use ReplenishOPKs to trigger a save.
	// Or we can just trust CreateAccount covers saving.
}

func TestKeyStore_Contacts(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_contacts.db")
	ks, err := NewKeyStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create KeyStore: %v", err)
	}

	ks.Initialize("1234")

	// Create dummy public key for contact
	pubKey, _, _ := mode5.GenerateKey(nil)

	contact := &Contact{
		IdentityKeyHash:      "test_hash_123",
		DisplayName:          "Alice",
		OutboundRoutingToken: []byte("alice_token"),
		IdentityPublicDili:   pubKey,
	}

	// 1. Save Contact
	err = ks.SaveContact(contact)
	if err != nil {
		t.Fatalf("Failed to save contact: %v", err)
	}

	// 2. Load Contact
	idBytes, _ := pubKey.MarshalBinary()
	realHash := fmt.Sprintf("%x", idBytes)

	loadedContact, err := ks.LoadContact(realHash)
	if err != nil {
		t.Fatalf("Failed to load contact with hash %s: %v", realHash, err)
	}
	if loadedContact == nil {
		t.Fatal("Loaded contact is nil")
	}
	if loadedContact.DisplayName != "Alice" {
		t.Errorf("Expected DisplayName 'Alice', got '%s'", loadedContact.DisplayName)
	}
	if !bytes.Equal(loadedContact.OutboundRoutingToken, []byte("alice_token")) {
		t.Error("OutboundRoutingToken mismatch")
	}

	// 3. List Contacts
	contacts, err := ks.ListContacts()
	if err != nil {
		t.Fatalf("Failed to list contacts: %v", err)
	}
	if len(contacts) != 1 {
		t.Errorf("Expected 1 contact, got %d", len(contacts))
	}
	// The hash in the list should match realHash
	if contacts[0].IdentityKeyHash != realHash {
		t.Errorf("Expected contact hash '%s', got '%s'", realHash, contacts[0].IdentityKeyHash)
	}

	// 4. Update Contact
	contact.DisplayName = "Alice Updated"
	err = ks.SaveContact(contact)
	if err != nil {
		t.Fatalf("Failed to update contact: %v", err)
	}
	loadedContact, _ = ks.LoadContact(realHash)
	if loadedContact.DisplayName != "Alice Updated" {
		t.Errorf("Expected updated name 'Alice Updated', got '%s'", loadedContact.DisplayName)
	}
}

func TestKeyStore_ReplenishOPKs(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_opks.db")
	ks, err := NewKeyStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create KeyStore: %v", err)
	}

	pin := "1234"
	ks.Initialize(pin)
	err = ks.CreateAccount()
	if err != nil {
		t.Fatalf("Failed to create account: %v", err)
	}

	var initialCount int
	ks.WithUserAccount(func(ua *UserAccount) error {
		initialCount = len(ua.OneTimePreKeys)
		// Force replenish by clearing keys (simulating usage)
		ua.OneTimePreKeys = nil
		return nil
	})

	// Replenish
	// We need to pass the account to ReplenishOPKs.
	// But ReplenishOPKs takes *UserAccount.
	// We need to get it first.
	// Since LoadAccount is private, we can't easily get the object to pass to ReplenishOPKs
	// unless we are inside WithUserAccount?
	// But ReplenishOPKs is a method on KeyStore.

	// Wait, ReplenishOPKs(account *UserAccount) returns (*UserAccount, error).
	// It modifies the passed account and saves it.
	// So we can do:
	err = ks.WithUserAccount(func(ua *UserAccount) error {
		ua.OneTimePreKeys = nil // Clear
		updatedUA, err := ks.ReplenishOPKs(ua)
		if err != nil {
			return err
		}
		if len(updatedUA.OneTimePreKeys) < initialCount {
			return errors.New("OPKs not replenished")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("ReplenishOPKs failed: %v", err)
	}
}

func TestKeyStore_WithUserAccount(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_with_ua.db")
	ks, err := NewKeyStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create KeyStore: %v", err)
	}

	pin := "1234"
	ks.Initialize(pin)
	err = ks.CreateAccount()
	if err != nil {
		t.Fatalf("Failed to create account: %v", err)
	}

	// Test WithUserAccount
	err = ks.WithUserAccount(func(ua *UserAccount) error {
		if ua == nil {
			return errors.New("UserAccount is nil")
		}
		if ua.IdentityPublicKyber == nil {
			return errors.New("IdentityPublicKyber is nil")
		}
		return nil
	})
	if err != nil {
		t.Errorf("WithUserAccount failed: %v", err)
	}
}
func TestKeyStore_Close(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_close.db")
	ks, err := NewKeyStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create KeyStore: %v", err)
	}
	if err := ks.Close(); err != nil {
		t.Fatalf("Failed to close KeyStore: %v", err)
	}
	// Verify double close doesn't panic or error (optional, depending on implementation)
	if err := ks.Close(); err != nil {
		t.Logf("Double close returned error: %v", err)
	}
}

func TestKeyStore_Persistence(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_persistence.db")

	// 1. Create and Save
	ks1, err := NewKeyStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	ks1.Initialize("1234")
	ks1.CreateAccount()

	// Modify account
	var originalID []byte
	ks1.WithUserAccount(func(ua *UserAccount) error {
		originalID, _ = ua.IdentityPublicKyber.MarshalBinary()
		// Change something if possible, or just rely on creation
		return nil
	})
	ks1.Close()

	// 2. Load from new instance
	ks2, err := NewKeyStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}

	// Try to load without unlock -> should fail or return error
	// But LoadAccount is private. We use WithUserAccount which unlocks if needed?
	// No, WithUserAccount expects ks.encKey to be set, which happens during Initialize/Unlock.

	err = ks2.Unlock("1234")
	if err != nil {
		t.Fatalf("Failed to unlock: %v", err)
	}

	err = ks2.WithUserAccount(func(ua *UserAccount) error {
		id, _ := ua.IdentityPublicKyber.MarshalBinary()
		if !bytes.Equal(id, originalID) {
			return errors.New("Identity Key mismatch after reload")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Persistence check failed: %v", err)
	}
	ks2.Close()
}
