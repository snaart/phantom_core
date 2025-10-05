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
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	_ "modernc.org/sqlite"
)

type MessageStore struct {
	db     *sql.DB
	path   string
	encKey []byte
	mu     sync.Mutex
}

type StoredMessage struct {
	SessionHash string
	IsOutgoing  bool
	Timestamp   int64
	Content     string
}

func NewMessageStore(path string) (*MessageStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, err
	}
	return &MessageStore{db: db, path: path}, nil
}

func (ms *MessageStore) Initialize(pin string) error {
	ms.encKey = argon2.IDKey([]byte(pin), []byte(dbEncryptionSalt), argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	ms.mu.Lock()
	defer ms.mu.Unlock()
	createTable := `
    CREATE TABLE IF NOT EXISTS messages (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       session_hash TEXT NOT NULL,
       is_outgoing BOOLEAN NOT NULL,
       timestamp INTEGER NOT NULL,
       encrypted_content BLOB NOT NULL,
       nonce BLOB NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_session_hash_timestamp ON messages (session_hash, timestamp);
    `
	if _, err := ms.db.Exec(createTable); err != nil {
		return err
	}
	return nil
}

func (ms *MessageStore) Unlock(pin string) {
	ms.encKey = argon2.IDKey([]byte(pin), []byte(dbEncryptionSalt), argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
}

func (ms *MessageStore) SaveMessage(sessionHash string, isOutgoing bool, timestamp int64, content string) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	encryptedContent, nonce, err := ms.encrypt([]byte(content))
	if err != nil {
		return fmt.Errorf("не удалось зашифровать контент сообщения: %w", err)
	}
	_, err = ms.db.Exec("INSERT INTO messages (session_hash, is_outgoing, timestamp, encrypted_content, nonce) VALUES (?, ?, ?, ?, ?)",
		sessionHash, isOutgoing, timestamp, encryptedContent, nonce)
	return err
}

func (ms *MessageStore) LoadHistory(sessionHash string, limit int) ([]StoredMessage, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	query := "SELECT is_outgoing, timestamp, encrypted_content, nonce FROM messages WHERE session_hash = ? ORDER BY timestamp DESC LIMIT ?"
	rows, err := ms.db.Query(query, sessionHash, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []StoredMessage
	for rows.Next() {
		var msg StoredMessage
		var encryptedContent, nonce []byte
		msg.SessionHash = sessionHash
		if err := rows.Scan(&msg.IsOutgoing, &msg.Timestamp, &encryptedContent, &nonce); err != nil {
			return nil, err
		}
		decryptedContent, err := ms.decrypt(encryptedContent, nonce)
		if err != nil {
			log.Printf("Не удалось расшифровать сообщение из истории: %v. Пропускаем.", err)
			continue
		}
		msg.Content = string(decryptedContent)
		history = append(history, msg)
	}
	for i, j := 0, len(history)-1; i < j; i, j = i+1, j-1 {
		history[i], history[j] = history[j], history[i]
	}
	return history, rows.Err()
}

func (ms *MessageStore) encrypt(plaintext []byte) (ciphertext, nonce []byte, err error) {
	if len(ms.encKey) == 0 {
		return nil, nil, errors.New("база данных заблокирована")
	}
	aead, err := chacha20poly1305.NewX(ms.encKey)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = aead.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

func (ms *MessageStore) decrypt(ciphertext, nonce []byte) ([]byte, error) {
	if len(ms.encKey) == 0 {
		return nil, errors.New("база данных заблокирована")
	}
	aead, err := chacha20poly1305.NewX(ms.encKey)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, nil)
}

func (ms *MessageStore) Close() error {
	if ms.encKey != nil {
		clear(ms.encKey)
		ms.encKey = nil
	}
	return ms.db.Close()
}
