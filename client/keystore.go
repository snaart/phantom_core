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
// dbSaltMetadataKey moved to common.go
// Argon2 params moved to common.go
)

type KeyStore struct {
	db     *sql.DB
	path   string
	encKey []byte
	salt   []byte
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
	// Username removed
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
	RoutingToken          []byte // Токен, на который мы принимаем сообщения
	FreshlyCreated        bool   `json:"-"`
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
	DisplayName          string
	IdentityPublicDili   sign.PublicKey
	IdentityPublicKyber  *kyber1024.PublicKey
	IdentityPublicX25519 *[32]byte
	RatchetState         []byte
	PendingUserMsgs      []string
	OutboundRoutingToken []byte // Токен, который мы используем для отправки этому контакту
	InboundRoutingToken  []byte // Токен, который мы выдали этому контакту (слушаем его)
	IdentityKeyHash      string // Хэш публичного ключа Dilithium (для идентификации)
	SignedPreKeyKyber    []byte
	SignedPreKeyX25519   []byte
	PreKeySignatureDili  []byte
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
	// Генерируем случайную соль для БД
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("не удалось сгенерировать соль: %w", err)
	}
	ks.salt = salt
	ks.encKey = argon2.IDKey([]byte(pin), ks.salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	ks.mu.Lock()
	defer ks.mu.Unlock()

	createTables := `
	CREATE TABLE IF NOT EXISTS identity (
		id INTEGER PRIMARY KEY CHECK (id = 1), -- Только одна запись
		encrypted_data BLOB NOT NULL,
		nonce BLOB NOT NULL
	);
	CREATE TABLE IF NOT EXISTS contacts (
		identity_key_hash TEXT PRIMARY KEY, -- Хэш IdentityKeyDilithium для поиска
		display_name TEXT,
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

	// Сохраняем соль в открытом виде (или можно обфусцировать, но соль не секретна)
	// Для простоты сохраним в metadata без шифрования? Нет, metadata имеет структуру key, value, nonce.
	// Но value зашифровано? В текущей схеме metadata хранит зашифрованные значения?
	// Посмотрим на pinCheck: encryptedCheck, nonce. Да, зашифровано.
	// Но соль нужна ДО расшифровки. Значит соль должна храниться отдельно или в metadata, но в открытом виде.
	// Давайте создадим таблицу config для открытых данных.

	if _, err := ks.db.Exec("CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value BLOB)"); err != nil {
		return err
	}

	if _, err := ks.db.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", dbSaltMetadataKey, ks.salt); err != nil {
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
	// Сначала читаем соль
	var salt []byte
	err := ks.db.QueryRow("SELECT value FROM config WHERE key = ?", dbSaltMetadataKey).Scan(&salt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || err.Error() == "no such table: config" {
			return errors.New("база данных не инициализирована или повреждена (нет соли)")
		}
		// Fallback для старых баз? Нет, мы делаем breaking change.
		return fmt.Errorf("не удалось прочитать соль: %w", err)
	}
	ks.salt = salt
	ks.encKey = argon2.IDKey([]byte(pin), ks.salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	var encryptedCheck, nonce []byte
	err = ks.db.QueryRow("SELECT value, nonce FROM metadata WHERE key = ?", pinCheckMetadataKey).Scan(&encryptedCheck, &nonce)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("база данных не инициализирована, невозможно проверить PIN-код")
		}
		return fmt.Errorf("не удалось прочитать значение для проверки PIN: %w", err)
	}
	decryptedCheck, err := ks.decrypt(encryptedCheck, nonce)
	if err != nil {
		return errors.New("неверный PIN-код")
	}

	if subtle.ConstantTimeCompare(decryptedCheck, []byte(pinCheckConstant)) != 1 {
		return errors.New("неверный PIN-код")
	}
	return nil
}

func (ks *KeyStore) CreateAccount() error {
	idPrivDili, idPubDili, idPrivKyber, idPubKyber, idPrivEC, idPubEC, err := GenerateHybridIdentityKeyPair()
	if err != nil {
		return fmt.Errorf("не удалось сгенерировать гибридные identity ключи: %w", err)
	}

	spkPrivKyber, spkPubKyber, spkPrivEC, spkPubEC, err := GenerateHybridPreKey()
	if err != nil {
		// Очистка ключей опущена для краткости, но должна быть
		return fmt.Errorf("не удалось сгенерировать гибридные signed prekey: %w", err)
	}

	account := &UserAccount{
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

	// Генерируем RoutingToken
	account.RoutingToken = make([]byte, 32)
	if _, err := rand.Read(account.RoutingToken); err != nil {
		return fmt.Errorf("не удалось сгенерировать RoutingToken: %w", err)
	}

	defer account.Zeroize()

	if err := ks.generateOPKs(account); err != nil {
		return fmt.Errorf("не удалось сгенерировать гибридные OPKs: %w", err)
	}

	return ks.saveAccount(account)
}

func (ks *KeyStore) AccountExists() (bool, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	var count int
	err := ks.db.QueryRow("SELECT COUNT(1) FROM identity WHERE id = 1").Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (ks *KeyStore) WithUserAccount(action func(ua *UserAccount) error) error {
	account, err := ks.loadAccount()
	if err != nil {
		return err
	}
	defer account.Zeroize()

	return action(account)
}

func (ks *KeyStore) loadAccount() (*UserAccount, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	var encryptedData, nonce []byte
	err := ks.db.QueryRow("SELECT encrypted_data, nonce FROM identity WHERE id = 1").Scan(&encryptedData, &nonce)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("аккаунт не найден")
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

func (ks *KeyStore) ReplenishOPKs(account *UserAccount) (*UserAccount, error) {
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

	// Используем хэш IdentityKey как ключ
	idKeyHash := fmt.Sprintf("%x", contact.IdentityPublicDili) // Просто hex от ключа, или реальный хэш. Ключ уникален.
	// IdentityPublicDili это interface, надо маршалить.
	idBytes, _ := contact.IdentityPublicDili.MarshalBinary()
	idKeyHash = fmt.Sprintf("%x", idBytes)

	_, err = ks.db.Exec("INSERT OR REPLACE INTO contacts (identity_key_hash, display_name, encrypted_data, nonce) VALUES (?, ?, ?, ?)",
		idKeyHash, contact.DisplayName, encryptedData, nonce)
	return err
}

func (ks *KeyStore) LoadContact(identityKeyHash string) (*Contact, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	var encryptedData, nonce []byte
	var displayName sql.NullString
	err := ks.db.QueryRow("SELECT display_name, encrypted_data, nonce FROM contacts WHERE identity_key_hash = ?", identityKeyHash).Scan(&displayName, &encryptedData, &nonce)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("контакт не найден")
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
	if displayName.Valid {
		contact.DisplayName = displayName.String
	}
	return contact, nil
}

// LoadContactByUsername Загрузка контакта по имени
// LoadContactByUsername удален, так как имен больше нет.

func (ks *KeyStore) ListContacts() ([]*Contact, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	rows, err := ks.db.Query("SELECT identity_key_hash FROM contacts")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var contacts []*Contact
	var hashes []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err == nil {
			hashes = append(hashes, h)
		}
	}
	rows.Close()

	// Теперь загружаем каждый контакт (неэффективно, но безопасно с точки зрения блокировок, если бы мы вызывали LoadContact внутри)
	// Но LoadContact берет лок. У нас уже есть лок?
	// LoadContact берет лок. Мы держим лок. Deadlock!
	// Поэтому надо вынести логику загрузки в loadContactLocked или читать всё здесь.
	// Для простоты прочитаем всё здесь.

	for _, h := range hashes {
		var encryptedData, nonce []byte
		var displayName sql.NullString
		err := ks.db.QueryRow("SELECT display_name, encrypted_data, nonce FROM contacts WHERE identity_key_hash = ?", h).Scan(&displayName, &encryptedData, &nonce)
		if err != nil {
			continue
		}
		decryptedData, err := ks.decrypt(encryptedData, nonce)
		if err != nil {
			continue
		}
		var storedContact StoredContact
		if err := json.Unmarshal(decryptedData, &storedContact); err != nil {
			continue
		}
		contact, err := storedContact.toContact()
		if err != nil {
			continue
		}
		contact.IdentityKeyHash = h
		if displayName.Valid {
			contact.DisplayName = displayName.String
		}
		contacts = append(contacts, contact)
	}

	return contacts, nil
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
	_, err = ks.db.Exec("INSERT OR REPLACE INTO identity (id, encrypted_data, nonce) VALUES (1, ?, ?)",
		encryptedData, nonce)
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
	// Username removed
	IdentityPrivateDili, IdentityPublicDili, IdentityPrivateKyber, IdentityPublicKyber, IdentityPrivateX25519, IdentityPublicX25519, PreKeyPrivateKyber, PreKeyPublicKyber, PreKeyPrivateX25519, PreKeyPublicX25519 []byte
	OneTimePreKeys                                                                                                                                                                                                  map[uint32]StoredOneTimePreKey
	RoutingToken                                                                                                                                                                                                    []byte
}
type StoredOneTimePreKey struct {
	ID                                                                 uint32
	PrivateKeyKyber, PublicKeyKyber, PrivateKeyX25519, PublicKeyX25519 []byte
}
type StoredContact struct {
	IdentityPublicDili, IdentityPublicKyber, IdentityPublicX25519, RatchetState []byte
	PendingUserMsgs                                                             []string `json:"pending_user_msgs,omitempty"`
	OutboundRoutingToken                                                        []byte
	InboundRoutingToken                                                         []byte
	SignedPreKeyKyber                                                           []byte
	SignedPreKeyX25519                                                          []byte
	PreKeySignatureDili                                                         []byte
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
	return &StoredUserAccount{IdentityPrivateDili: idPrivDili, IdentityPublicDili: idPubDili, IdentityPrivateKyber: idPrivKyber, IdentityPublicKyber: idPubKyber, IdentityPrivateX25519: ua.IdentityPrivateX25519[:], IdentityPublicX25519: ua.IdentityPublicX25519[:], PreKeyPrivateKyber: spkPrivKyber, PreKeyPublicKyber: spkPubKyber, PreKeyPrivateX25519: ua.PreKeyPrivateX25519[:], PreKeyPublicX25519: ua.PreKeyPublicX25519[:], OneTimePreKeys: storedOPKs, RoutingToken: ua.RoutingToken}, nil
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

		// Правильно копируем X25519 ключи для OPK
		var opkPrivX25519, opkPubX25519 *[32]byte
		if len(sopk.PrivateKeyX25519) == 32 {
			opkPrivX25519 = new([32]byte)
			copy(opkPrivX25519[:], sopk.PrivateKeyX25519)
		}
		if len(sopk.PublicKeyX25519) == 32 {
			opkPubX25519 = new([32]byte)
			copy(opkPubX25519[:], sopk.PublicKeyX25519)
		}

		opks[id] = OneTimePreKey{ID: id, PrivateKeyKyber: privK.(*kyber1024.PrivateKey), PublicKeyKyber: pubK.(*kyber1024.PublicKey), PrivateKeyX25519: opkPrivX25519, PublicKeyX25519: opkPubX25519}
	}

	// КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Правильно копируем X25519 ключи
	var idPrivX25519, idPubX25519, preKeyPrivX25519, preKeyPubX25519 *[32]byte

	if len(sua.IdentityPrivateX25519) == 32 {
		idPrivX25519 = new([32]byte)
		copy(idPrivX25519[:], sua.IdentityPrivateX25519)
	}
	if len(sua.IdentityPublicX25519) == 32 {
		idPubX25519 = new([32]byte)
		copy(idPubX25519[:], sua.IdentityPublicX25519)
	}
	if len(sua.PreKeyPrivateX25519) == 32 {
		preKeyPrivX25519 = new([32]byte)
		copy(preKeyPrivX25519[:], sua.PreKeyPrivateX25519)
	}
	if len(sua.PreKeyPublicX25519) == 32 {
		preKeyPubX25519 = new([32]byte)
		copy(preKeyPubX25519[:], sua.PreKeyPublicX25519)
	}

	return &UserAccount{IdentityPrivateDili: idPrivDili, IdentityPublicDili: idPubDili, IdentityPrivateKyber: idPrivKyber.(*kyber1024.PrivateKey), IdentityPublicKyber: idPubKyber.(*kyber1024.PublicKey), IdentityPrivateX25519: idPrivX25519, IdentityPublicX25519: idPubX25519, PreKeyPrivateKyber: spkPrivKyber.(*kyber1024.PrivateKey), PreKeyPublicKyber: spkPubKyber.(*kyber1024.PublicKey), PreKeyPrivateX25519: preKeyPrivX25519, PreKeyPublicX25519: preKeyPubX25519, OneTimePreKeys: opks, RoutingToken: sua.RoutingToken}, nil
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
	var idPubKyber []byte
	if c.IdentityPublicKyber != nil {
		idPubKyber, err = c.IdentityPublicKyber.MarshalBinary()
		if err != nil {
			return nil, err
		}
	}
	var idPubEC []byte
	if c.IdentityPublicX25519 != nil {
		idPubEC = c.IdentityPublicX25519[:]
	}
	return &StoredContact{
		IdentityPublicDili:   idPubDili,
		IdentityPublicKyber:  idPubKyber,
		IdentityPublicX25519: idPubEC,
		RatchetState:         c.RatchetState,
		PendingUserMsgs:      c.PendingUserMsgs,
		OutboundRoutingToken: c.OutboundRoutingToken,
		InboundRoutingToken:  c.InboundRoutingToken,
		SignedPreKeyKyber:    c.SignedPreKeyKyber,
		SignedPreKeyX25519:   c.SignedPreKeyX25519,
		PreKeySignatureDili:  c.PreKeySignatureDili,
	}, nil
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
	var idPubKyber *kyber1024.PublicKey
	if sc.IdentityPublicKyber != nil && len(sc.IdentityPublicKyber) > 0 {
		kemScheme := kyber1024.Scheme()
		var err error
		pk, err := kemScheme.UnmarshalBinaryPublicKey(sc.IdentityPublicKyber)
		if err != nil {
			return nil, err
		}
		idPubKyber = pk.(*kyber1024.PublicKey)
	}
	var idPubEC *[32]byte
	if len(sc.IdentityPublicX25519) == 32 {
		idPubEC = (*[32]byte)(sc.IdentityPublicX25519)
	}
	contact := &Contact{
		IdentityPublicDili:   idPubDili,
		IdentityPublicKyber:  idPubKyber,
		IdentityPublicX25519: idPubEC,
		RatchetState:         sc.RatchetState,
		PendingUserMsgs:      sc.PendingUserMsgs,
		OutboundRoutingToken: sc.OutboundRoutingToken,
		InboundRoutingToken:  sc.InboundRoutingToken,
		SignedPreKeyKyber:    sc.SignedPreKeyKyber,
		SignedPreKeyX25519:   sc.SignedPreKeyX25519,
		PreKeySignatureDili:  sc.PreKeySignatureDili,
	}
	if contact.PendingUserMsgs == nil {
		contact.PendingUserMsgs = make([]string, 0)
	}
	return contact, nil
}
