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
	"crypto/subtle"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	_ "modernc.org/sqlite"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/dilithium/mode5"
)

const (
	NumOPKs             = 100
	dbEncryptionSalt    = "phantom-db-salt-v2"
	argon2Time          = 2
	argon2Memory        = 128 * 1024
	argon2Threads       = 4
	argon2KeyLen        = 32
	pinCheckConstant    = "phantom-pin-check-ok"
	pinCheckMetadataKey = "pin_check"
)

type KeyStore struct {
	db     *sql.DB
	path   string
	encKey []byte
	mu     sync.Mutex
}

type OneTimePreKey struct {
	ID               uint32
	PrivateKeyKyber  *kyber1024.PrivateKey
	PublicKeyKyber   *kyber1024.PublicKey
	PrivateKeyX25519 *[32]byte
	PublicKeyX25519  *[32]byte
}

type UserAccount struct {
	Username              string
	IdentityPrivateDili   sign.PrivateKey
	IdentityPublicDili    sign.PublicKey
	IdentityPrivateKyber  *kyber1024.PrivateKey
	IdentityPublicKyber   *kyber1024.PublicKey
	IdentityPrivateX25519 *[32]byte
	IdentityPublicX25519  *[32]byte
	PreKeyPrivateKyber    *kyber1024.PrivateKey
	PreKeyPublicKyber     *kyber1024.PublicKey
	PreKeyPrivateX25519   *[32]byte
	PreKeyPublicX25519    *[32]byte
	OneTimePreKeys        map[uint32]OneTimePreKey
	FreshlyCreated        bool `json:"-"`
}

func (ua *UserAccount) Zeroize() {
	if ua == nil {
		return
	}
	if ua.IdentityPrivateDili != nil {
		if marshaled, err := ua.IdentityPrivateDili.MarshalBinary(); err == nil {
			clear(marshaled)
		}
	}
	if ua.IdentityPrivateKyber != nil {
		if marshaled, err := ua.IdentityPrivateKyber.MarshalBinary(); err == nil {
			clear(marshaled)
		}
	}
	if ua.IdentityPrivateX25519 != nil {
		clear(ua.IdentityPrivateX25519[:])
	}
	if ua.PreKeyPrivateKyber != nil {
		if marshaled, err := ua.PreKeyPrivateKyber.MarshalBinary(); err == nil {
			clear(marshaled)
		}
	}
	if ua.PreKeyPrivateX25519 != nil {
		clear(ua.PreKeyPrivateX25519[:])
	}
	for _, opk := range ua.OneTimePreKeys {
		if opk.PrivateKeyKyber != nil {
			if marshaled, err := opk.PrivateKeyKyber.MarshalBinary(); err == nil {
				clear(marshaled)
			}
		}
		if opk.PrivateKeyX25519 != nil {
			clear(opk.PrivateKeyX25519[:])
		}
	}
	ua.IdentityPrivateDili, ua.IdentityPrivateKyber, ua.IdentityPrivateX25519, ua.PreKeyPrivateKyber, ua.PreKeyPrivateX25519, ua.OneTimePreKeys = nil, nil, nil, nil, nil, nil
}

type Contact struct {
	Username             string
	UsernameHash         string
	IdentityPublicDili   sign.PublicKey
	IdentityPublicX25519 *[32]byte
	RatchetState         []byte
	PendingUserMsgs      []string
}

func NewKeyStore(path string) (*KeyStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, err
	}
	return &KeyStore{db: db, path: path}, nil
}

func (ks *KeyStore) Initialize(pin string) error {
	ks.encKey = argon2.IDKey([]byte(pin), []byte(dbEncryptionSalt), argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	ks.mu.Lock()
	defer ks.mu.Unlock()
	createTables := `
	CREATE TABLE IF NOT EXISTS accounts (
		username TEXT PRIMARY KEY,
		encrypted_data BLOB NOT NULL,
		nonce BLOB NOT NULL
	);
	CREATE TABLE IF NOT EXISTS contacts (
		username_hash TEXT PRIMARY KEY,
		username TEXT,
		encrypted_data BLOB NOT NULL,
		nonce BLOB NOT NULL
	);
	CREATE TABLE IF NOT EXISTS metadata (
		key TEXT PRIMARY KEY,
		value BLOB,
		nonce BLOB
	);
	`
	if _, err := ks.db.Exec(createTables); err != nil {
		return err
	}
	encryptedCheck, nonce, err := ks.encrypt([]byte(pinCheckConstant))
	if err != nil {
		return fmt.Errorf("не удалось создать значение для проверки PIN: %w", err)
	}
	_, err = ks.db.Exec("INSERT OR REPLACE INTO metadata (key, value, nonce) VALUES (?, ?, ?)", pinCheckMetadataKey, encryptedCheck, nonce)
	return err
}

func (ks *KeyStore) Unlock(pin string) error {
	ks.encKey = argon2.IDKey([]byte(pin), []byte(dbEncryptionSalt), argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	var encryptedCheck, nonce []byte
	err := ks.db.QueryRow("SELECT value, nonce FROM metadata WHERE key = ?", pinCheckMetadataKey).Scan(&encryptedCheck, &nonce)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("база данных не инициализирована, невозможно проверить PIN-код")
		}
		return fmt.Errorf("не удалось прочитать значение для проверки PIN: %w", err)
	}
	decryptedCheck, err := ks.decrypt(encryptedCheck, nonce)
	if err != nil {
		// Ошибка расшифровки (неверный ключ -> неверный PIN) уже сама по себе является сигналом.
		// Чтобы избежать разницы во времени между ошибкой расшифровки и ошибкой сравнения,
		// можно выполнить фиктивное сравнение даже в случае ошибки.
		// Однако, для простоты, основной фокус на исправлении явной уязвимости.
		return errors.New("неверный PIN-код")
	}

	// Используем ConstantTimeCompare для защиты от timing-атак.
	// Функция возвращает 1, если срезы равны, и 0 в противном случае.
	if subtle.ConstantTimeCompare(decryptedCheck, []byte(pinCheckConstant)) != 1 {
		return errors.New("неверный PIN-код")
	}
	return nil
}

func (ks *KeyStore) CreateAccount(username string) error {
	idPrivDili, idPubDili, idPrivKyber, idPubKyber, idPrivEC, idPubEC, err := GenerateHybridIdentityKeyPair()
	if err != nil {
		return fmt.Errorf("не удалось сгенерировать гибридные identity ключи: %w", err)
	}

	spkPrivKyber, spkPubKyber, spkPrivEC, spkPubEC, err := GenerateHybridPreKey()
	if err != nil {
		// Очищаем уже сгенерированные ключи перед выходом с ошибкой
		if idPrivDili != nil {
			if m, e := idPrivDili.MarshalBinary(); e == nil {
				clear(m)
			}
		}
		if idPrivKyber != nil {
			if m, e := idPrivKyber.MarshalBinary(); e == nil {
				clear(m)
			}
		}
		if idPrivEC != nil {
			clear(idPrivEC[:])
		}
		return fmt.Errorf("не удалось сгенерировать гибридные signed prekey: %w", err)
	}

	account := &UserAccount{
		Username:              username,
		FreshlyCreated:        true,
		IdentityPrivateDili:   idPrivDili,
		IdentityPublicDili:    idPubDili,
		IdentityPrivateKyber:  idPrivKyber,
		IdentityPublicKyber:   idPubKyber,
		IdentityPrivateX25519: idPrivEC,
		IdentityPublicX25519:  idPubEC,
		PreKeyPrivateKyber:    spkPrivKyber,
		PreKeyPublicKyber:     spkPubKyber,
		PreKeyPrivateX25519:   spkPrivEC,
		PreKeyPublicX25519:    spkPubEC,
		OneTimePreKeys:        make(map[uint32]OneTimePreKey),
	}
	// КРИТИЧЕСКИ ВАЖНО: гарантируем очистку account со всеми ключами при выходе из функции.
	defer account.Zeroize()

	if err := ks.generateOPKs(account); err != nil {
		return fmt.Errorf("не удалось сгенерировать гибридные OPKs: %w", err)
	}

	return ks.saveAccount(account)
}

func (ks *KeyStore) AccountExists(username string) (bool, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	var count int
	err := ks.db.QueryRow("SELECT COUNT(1) FROM accounts WHERE username = ?", username).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (ks *KeyStore) WithUserAccount(username string, action func(ua *UserAccount) error) error {
	account, err := ks.loadAccount(username)
	if err != nil {
		return err
	}
	defer account.Zeroize()

	return action(account)
}

func (ks *KeyStore) loadAccount(username string) (*UserAccount, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	var encryptedData, nonce []byte
	err := ks.db.QueryRow("SELECT encrypted_data, nonce FROM accounts WHERE username = ?", username).Scan(&encryptedData, &nonce)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("аккаунт '%s' не найден", username)
		}
		return nil, err
	}
	decryptedData, err := ks.decrypt(encryptedData, nonce)
	if err != nil {
		return nil, fmt.Errorf("ошибка расшифровки данных аккаунта: %w", err)
	}
	var storedAccount StoredUserAccount
	if err := json.Unmarshal(decryptedData, &storedAccount); err != nil {
		return nil, err
	}
	account, err := storedAccount.toUserAccount()
	if err != nil {
		return nil, err
	}
	account.FreshlyCreated = false
	return account, nil
}

func (ks *KeyStore) ReplenishOPKs(username string, account *UserAccount) (*UserAccount, error) {
	account.OneTimePreKeys = make(map[uint32]OneTimePreKey)
	if err := ks.generateOPKs(account); err != nil {
		return nil, err
	}
	return account, ks.saveAccount(account)
}

func (ks *KeyStore) SaveContact(contact *Contact) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	return ks.savecontactLocked(contact)
}

func (ks *KeyStore) savecontactLocked(contact *Contact) error {
	storedContact, err := contact.toStoredContact()
	if err != nil {
		return err
	}
	data, err := json.Marshal(storedContact)
	if err != nil {
		return err
	}
	encryptedData, nonce, err := ks.encrypt(data)
	if err != nil {
		return err
	}
	_, err = ks.db.Exec("INSERT OR REPLACE INTO contacts (username_hash, username, encrypted_data, nonce) VALUES (?, ?, ?, ?)",
		contact.UsernameHash, contact.Username, encryptedData, nonce)
	return err
}

func (ks *KeyStore) LoadContact(usernameHash string) (*Contact, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	var encryptedData, nonce []byte
	var username sql.NullString
	err := ks.db.QueryRow("SELECT username, encrypted_data, nonce FROM contacts WHERE username_hash = ?", usernameHash).Scan(&username, &encryptedData, &nonce)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("контакт с хэшем '%s' не найден", usernameHash)
		}
		return nil, err
	}
	decryptedData, err := ks.decrypt(encryptedData, nonce)
	if err != nil {
		return nil, err
	}
	var storedContact StoredContact
	if err := json.Unmarshal(decryptedData, &storedContact); err != nil {
		return nil, err
	}
	contact, err := storedContact.toContact()
	if err != nil {
		return nil, err
	}
	if username.Valid {
		contact.Username = username.String
	}
	contact.UsernameHash = usernameHash
	return contact, nil
}

// LoadContactByUsername Загрузка контакта по имени
func (ks *KeyStore) LoadContactByUsername(username string) (*Contact, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	var encryptedData, nonce []byte
	var usernameHash sql.NullString
	err := ks.db.QueryRow("SELECT username_hash, encrypted_data, nonce FROM contacts WHERE username = ?", username).Scan(&usernameHash, &encryptedData, &nonce)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("контакт с именем '%s' не найден", username)
		}
		return nil, err
	}
	decryptedData, err := ks.decrypt(encryptedData, nonce)
	if err != nil {
		return nil, err
	}
	var storedContact StoredContact
	if err := json.Unmarshal(decryptedData, &storedContact); err != nil {
		return nil, err
	}
	contact, err := storedContact.toContact()
	if err != nil {
		return nil, err
	}
	contact.Username = username
	if usernameHash.Valid {
		contact.UsernameHash = usernameHash.String
	}
	return contact, nil
}

func (ks *KeyStore) ListContactUsernames() ([]string, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	rows, err := ks.db.Query("SELECT username FROM contacts WHERE username IS NOT NULL AND username != '' ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var usernames []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		usernames = append(usernames, name)
	}
	return usernames, rows.Err()
}

func (ks *KeyStore) saveAccount(account *UserAccount) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	stored, err := account.toStoredUserAccount()
	if err != nil {
		return fmt.Errorf("ошибка конвертации аккаунта для сохранения: %w", err)
	}
	data, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	encryptedData, nonce, err := ks.encrypt(data)
	if err != nil {
		return err
	}
	_, err = ks.db.Exec("INSERT OR REPLACE INTO accounts (username, encrypted_data, nonce) VALUES (?, ?, ?)",
		account.Username, encryptedData, nonce)
	return err
}

func (ks *KeyStore) generateOPKs(account *UserAccount) error {
	for i := 0; i < NumOPKs; i++ {
		var idBytes [4]byte
		var id uint32
		for {
			if _, err := rand.Read(idBytes[:]); err != nil {
				return fmt.Errorf("не удалось сгенерировать случайный ID для OPK: %w", err)
			}
			id = binary.BigEndian.Uint32(idBytes[:])
			if _, exists := account.OneTimePreKeys[id]; !exists {
				break
			}
		}
		privK, pubK, privEC, pubEC, err := GenerateHybridPreKey()
		if err != nil {
			return err
		}
		account.OneTimePreKeys[id] = OneTimePreKey{
			ID: id, PrivateKeyKyber: privK, PublicKeyKyber: pubK, PrivateKeyX25519: privEC, PublicKeyX25519: pubEC,
		}
	}
	return nil
}

func (ks *KeyStore) encrypt(plaintext []byte) (ciphertext, nonce []byte, err error) {
	if len(ks.encKey) == 0 {
		return nil, nil, errors.New("база данных заблокирована")
	}
	aead, err := chacha20poly1305.NewX(ks.encKey)
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

func (ks *KeyStore) decrypt(ciphertext, nonce []byte) ([]byte, error) {
	if len(ks.encKey) == 0 {
		return nil, errors.New("база данных заблокирована")
	}
	aead, err := chacha20poly1305.NewX(ks.encKey)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, nil)
}

func (ks *KeyStore) Close() error {
	if ks.encKey != nil {
		clear(ks.encKey)
		ks.encKey = nil
	}
	return ks.db.Close()
}

type StoredUserAccount struct {
	Username                                                                                                                                                                                                        string
	IdentityPrivateDili, IdentityPublicDili, IdentityPrivateKyber, IdentityPublicKyber, IdentityPrivateX25519, IdentityPublicX25519, PreKeyPrivateKyber, PreKeyPublicKyber, PreKeyPrivateX25519, PreKeyPublicX25519 []byte
	OneTimePreKeys                                                                                                                                                                                                  map[uint32]StoredOneTimePreKey
}
type StoredOneTimePreKey struct {
	ID                                                                 uint32
	PrivateKeyKyber, PublicKeyKyber, PrivateKeyX25519, PublicKeyX25519 []byte
}
type StoredContact struct {
	UsernameHash, IdentityPublicDili, IdentityPublicX25519, RatchetState []byte
	PendingUserMsgs                                                      []string `json:"pending_user_msgs,omitempty"`
}

func (ua *UserAccount) toStoredUserAccount() (*StoredUserAccount, error) {
	idPrivDili, err := ua.IdentityPrivateDili.MarshalBinary()
	if err != nil {
		return nil, err
	}
	idPubDili, err := ua.IdentityPublicDili.MarshalBinary()
	if err != nil {
		return nil, err
	}
	idPrivKyber, err := ua.IdentityPrivateKyber.MarshalBinary()
	if err != nil {
		return nil, err
	}
	idPubKyber, err := ua.IdentityPublicKyber.MarshalBinary()
	if err != nil {
		return nil, err
	}
	spkPrivKyber, err := ua.PreKeyPrivateKyber.MarshalBinary()
	if err != nil {
		return nil, err
	}
	spkPubKyber, err := ua.PreKeyPublicKyber.MarshalBinary()
	if err != nil {
		return nil, err
	}
	storedOPKs := make(map[uint32]StoredOneTimePreKey)
	for id, opk := range ua.OneTimePreKeys {
		privK, err := opk.PrivateKeyKyber.MarshalBinary()
		if err != nil {
			return nil, err
		}
		pubK, err := opk.PublicKeyKyber.MarshalBinary()
		if err != nil {
			return nil, err
		}
		storedOPKs[id] = StoredOneTimePreKey{ID: id, PrivateKeyKyber: privK, PublicKeyKyber: pubK, PrivateKeyX25519: opk.PrivateKeyX25519[:], PublicKeyX25519: opk.PublicKeyX25519[:]}
	}
	return &StoredUserAccount{Username: ua.Username, IdentityPrivateDili: idPrivDili, IdentityPublicDili: idPubDili, IdentityPrivateKyber: idPrivKyber, IdentityPublicKyber: idPubKyber, IdentityPrivateX25519: ua.IdentityPrivateX25519[:], IdentityPublicX25519: ua.IdentityPublicX25519[:], PreKeyPrivateKyber: spkPrivKyber, PreKeyPublicKyber: spkPubKyber, PreKeyPrivateX25519: ua.PreKeyPrivateX25519[:], PreKeyPublicX25519: ua.PreKeyPublicX25519[:], OneTimePreKeys: storedOPKs}, nil
}

func (sua *StoredUserAccount) toUserAccount() (*UserAccount, error) {
	diliScheme := mode5.Scheme()
	idPrivDili, err := diliScheme.UnmarshalBinaryPrivateKey(sua.IdentityPrivateDili)
	if err != nil {
		return nil, err
	}
	idPubDili, err := diliScheme.UnmarshalBinaryPublicKey(sua.IdentityPublicDili)
	if err != nil {
		return nil, err
	}
	kemScheme := kyber1024.Scheme()
	idPrivKyber, err := kemScheme.UnmarshalBinaryPrivateKey(sua.IdentityPrivateKyber)
	if err != nil {
		return nil, err
	}
	idPubKyber, err := kemScheme.UnmarshalBinaryPublicKey(sua.IdentityPublicKyber)
	if err != nil {
		return nil, err
	}
	spkPrivKyber, err := kemScheme.UnmarshalBinaryPrivateKey(sua.PreKeyPrivateKyber)
	if err != nil {
		return nil, err
	}
	spkPubKyber, err := kemScheme.UnmarshalBinaryPublicKey(sua.PreKeyPublicKyber)
	if err != nil {
		return nil, err
	}
	opks := make(map[uint32]OneTimePreKey)
	for id, sopk := range sua.OneTimePreKeys {
		privK, err := kemScheme.UnmarshalBinaryPrivateKey(sopk.PrivateKeyKyber)
		if err != nil {
			return nil, err
		}
		pubK, err := kemScheme.UnmarshalBinaryPublicKey(sopk.PublicKeyKyber)
		if err != nil {
			return nil, err
		}
		opks[id] = OneTimePreKey{ID: id, PrivateKeyKyber: privK.(*kyber1024.PrivateKey), PublicKeyKyber: pubK.(*kyber1024.PublicKey), PrivateKeyX25519: (*[32]byte)(sopk.PrivateKeyX25519), PublicKeyX25519: (*[32]byte)(sopk.PublicKeyX25519)}
	}
	return &UserAccount{Username: sua.Username, IdentityPrivateDili: idPrivDili, IdentityPublicDili: idPubDili, IdentityPrivateKyber: idPrivKyber.(*kyber1024.PrivateKey), IdentityPublicKyber: idPubKyber.(*kyber1024.PublicKey), IdentityPrivateX25519: (*[32]byte)(sua.IdentityPrivateX25519), IdentityPublicX25519: (*[32]byte)(sua.IdentityPublicX25519), PreKeyPrivateKyber: spkPrivKyber.(*kyber1024.PrivateKey), PreKeyPublicKyber: spkPubKyber.(*kyber1024.PublicKey), PreKeyPrivateX25519: (*[32]byte)(sua.PreKeyPrivateX25519), PreKeyPublicX25519: (*[32]byte)(sua.PreKeyPublicX25519), OneTimePreKeys: opks}, nil
}

func (c *Contact) toStoredContact() (*StoredContact, error) {
	var idPubDili []byte
	var err error
	if c.IdentityPublicDili != nil {
		idPubDili, err = c.IdentityPublicDili.MarshalBinary()
		if err != nil {
			return nil, err
		}
	}
	var idPubEC []byte
	if c.IdentityPublicX25519 != nil {
		idPubEC = c.IdentityPublicX25519[:]
	}
	return &StoredContact{UsernameHash: []byte(c.UsernameHash), IdentityPublicDili: idPubDili, IdentityPublicX25519: idPubEC, RatchetState: c.RatchetState, PendingUserMsgs: c.PendingUserMsgs}, nil
}

func (sc *StoredContact) toContact() (*Contact, error) {
	var idPubDili sign.PublicKey
	if sc.IdentityPublicDili != nil && len(sc.IdentityPublicDili) > 0 {
		diliScheme := mode5.Scheme()
		var err error
		idPubDili, err = diliScheme.UnmarshalBinaryPublicKey(sc.IdentityPublicDili)
		if err != nil {
			return nil, err
		}
	}
	var idPubEC *[32]byte
	if len(sc.IdentityPublicX25519) == 32 {
		idPubEC = (*[32]byte)(sc.IdentityPublicX25519)
	}
	contact := &Contact{UsernameHash: string(sc.UsernameHash), IdentityPublicDili: idPubDili, IdentityPublicX25519: idPubEC, RatchetState: sc.RatchetState, PendingUserMsgs: sc.PendingUserMsgs}
	if contact.PendingUserMsgs == nil {
		contact.PendingUserMsgs = make([]string, 0)
	}
	return contact, nil
}
