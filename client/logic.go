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
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	proto2 "phantom/proto"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/dilithium/mode5"
	"github.com/gen2brain/beeep"
)

const (
	MaxMessageSize      = 32 * 1024
	workerPoolSize      = 10
	InitiateChatMessage = "__PHANTOM_INITIATE_CHAT__"
	serverPublicKeyB64  = "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"
)

var (
	serverPublicKey sign.PublicKey
)

type peerSession struct {
	initMutex          sync.Mutex
	pendingKeyResp     *proto2.KeyResponse
	pendingInboundPkts []*proto2.Packet
	isEstablished      bool
	keyRequestInFlight bool
}

type logicClient struct {
	ks             *KeyStore
	ms             *MessageStore
	username       string
	stream         proto2.Phantom_TransmitClient
	myUsernameHash string
	mu             sync.RWMutex
	peerSessions   map[string]*peerSession
	handler        CoreEventHandler
	contactsMu     sync.RWMutex
	usernameToHash map[string]string
	hashToUsername map[string]string
	packetQueue    chan *proto2.Packet
	wg             sync.WaitGroup
	p2pTransport   *P2PTransport // Ссылка на P2P транспорт
}

func init() {
	var err error
	if serverPublicKeyB64 == "" {
		log.Fatalf("Не установлен публичный ключ сервера")
		return
	}
	keyBytes, err := base64.StdEncoding.DecodeString(serverPublicKeyB64)
	if err != nil {
		log.Fatalf("КРИТИЧЕСКАЯ ОШИБКА: Неверный формат публичного ключа сервера: %v", err)
	}
	scheme := mode5.Scheme()
	serverPublicKey, err = scheme.UnmarshalBinaryPublicKey(keyBytes)
	if err != nil {
		log.Fatalf("КРИТИЧЕСКАЯ ОШИБКА: Не удалось распаковать Dilithium5 ключ сервера: %v", err)
	}
}

func newLogicClient(username string, ks *KeyStore, ms *MessageStore, handler CoreEventHandler) (*logicClient, error) {
	client := &logicClient{
		ks:             ks,
		ms:             ms,
		username:       username,
		peerSessions:   make(map[string]*peerSession),
		handler:        handler,
		usernameToHash: make(map[string]string),
		hashToUsername: make(map[string]string),
		packetQueue:    make(chan *proto2.Packet, 100),
	}
	return client, nil
}

// Реализация интерфейса P2PMessageHandler

func (c *logicClient) GetUsernameHash() string {
	return c.myUsernameHash
}

// GetContactHashes возвращает список хэшей всех контактов для P2P анонсирования
func (c *logicClient) GetContactHashes() []string {
	c.contactsMu.RLock()
	defer c.contactsMu.RUnlock()

	var hashes []string
	for _, hash := range c.usernameToHash {
		hashes = append(hashes, hash)
	}
	return hashes
}

func (c *logicClient) HandleP2PMessage(packet *proto2.Packet) error {
	c.handler.OnLog(LogLevelInfo, fmt.Sprintf("📨 Получен P2P пакет от %s...", truncateHash(packet.SourceClientIdHash)))

	switch pld := packet.Payload.(type) {
	case *proto2.Packet_EncryptedMessage:
		c.handleEncryptedMessage(packet)
	case *proto2.Packet_KeyRequest:
		c.handleP2PKeyRequest(packet)
	case *proto2.Packet_KeyResponse:
		c.handleKeyResponse(pld.KeyResponse)
	default:
		c.handler.OnLog(LogLevelWarning, "Получен неизвестный тип P2P пакета")
	}
	return nil
}

// handleP2PKeyRequest обрабатывает P2P запрос ключей
func (c *logicClient) handleP2PKeyRequest(packet *proto2.Packet) {
	c.handler.OnLog(LogLevelInfo, fmt.Sprintf("🔑 Получен P2P запрос ключей от %s", truncateHash(packet.SourceClientIdHash)))

	session := c.getOrCreateSession(packet.SourceClientIdHash)
	session.initMutex.Lock()
	// Проверяем, не отправили ли мы сами запрос на установку сессии этому пиру.
	// `keyRequestInFlight` будет true, если мы уже вызвали `sendMessageViaP2P` без сессии.
	if session.keyRequestInFlight {
		// Правило разрешения конфликта: выигрывает тот, у кого хэш "меньше".
		if c.myUsernameHash < packet.SourceClientIdHash {
			// Наш хэш меньше. Мы "выигрываем" гонку. Мы будем Алисой.
			// Поэтому мы игнорируем ИХ KeyRequest и ждем KeyResponse на НАШ запрос.
			c.handler.OnLog(LogLevelInfo, fmt.Sprintf("🏁 Обнаружена встречная инициализация. Мы победили (%s < %s). Игнорируем их запрос.", truncateHash(c.myUsernameHash), truncateHash(packet.SourceClientIdHash)))
			session.initMutex.Unlock()
			return
		}
		// Наш хэш больше. Мы "проиграли". Мы будем Бобом.
		// Мы должны отменить нашу собственную инициализацию и просто ответить на их запрос.
		c.handler.OnLog(LogLevelInfo, fmt.Sprintf("🏁 Обнаружена встречная инициализация. Мы уступаем (%s > %s). Отвечаем на их запрос.", truncateHash(c.myUsernameHash), truncateHash(packet.SourceClientIdHash)))
		session.keyRequestInFlight = false // Сбрасываем флаг, так как мы больше не инициатор
	}
	session.initMutex.Unlock()

	err := c.ks.WithUserAccount(c.username, func(ua *UserAccount) error {
		opksKyber := make(map[uint32][]byte)
		opksX25519 := make(map[uint32][]byte)

		// Берем только один OPK для P2P обмена
		var chosenOPKID uint32
		for id, key := range ua.OneTimePreKeys {
			chosenOPKID = id
			pubBytesK, err := key.PublicKeyKyber.MarshalBinary()
			if err != nil {
				return err
			}
			opksKyber[id] = pubBytesK
			opksX25519[id] = key.PublicKeyX25519[:]
			break // Берем только один
		}

		idPubDiliBytes, _ := ua.IdentityPublicDili.MarshalBinary()
		idPubKyberBytes, _ := ua.IdentityPublicKyber.MarshalBinary()
		spkPubKyberBytes, _ := ua.PreKeyPublicKyber.MarshalBinary()

		dataToSign := append(spkPubKyberBytes, ua.PreKeyPublicX25519[:]...)
		sig := mode5.Scheme().Sign(ua.IdentityPrivateDili, dataToSign, nil)

		prekeyBundle := &proto2.HybridPreKeyBundle{
			IdentityKeyDilithium:     idPubDiliBytes,
			IdentityKeyKyber:         idPubKyberBytes,
			IdentityKeyX25519:        ua.IdentityPublicX25519[:],
			SignedPrekeyKyber:        spkPubKyberBytes,
			SignedPrekeyX25519:       ua.PreKeyPublicX25519[:],
			PrekeySignatureDilithium: sig,
			OneTimePrekeysKyber:      opksKyber,
			OneTimePrekeysX25519:     opksX25519,
		}
		bundleData, err := proto.Marshal(prekeyBundle)
		if err != nil {
			return err
		}

		keyResp := &proto2.KeyResponse{
			HybridPrekeyBundle:  bundleData,
			ClientIdHash:        c.myUsernameHash,
			OneTimePrekeyKyber:  opksKyber[chosenOPKID],
			OneTimePrekeyX25519: opksX25519[chosenOPKID],
			OneTimePrekeyId:     chosenOPKID,
		}

		responsePacket := &proto2.Packet{
			SourceClientIdHash:      c.myUsernameHash,
			DestinationClientIdHash: packet.SourceClientIdHash,
			Payload:                 &proto2.Packet_KeyResponse{KeyResponse: keyResp},
		}

		if err := c.signPacket(responsePacket, ua.IdentityPrivateDili); err != nil {
			return err
		}

		if c.p2pTransport != nil {
			c.handler.OnLog(LogLevelInfo, fmt.Sprintf("🔑 Отправка KeyResponse пиру %s...", truncateHash(packet.SourceClientIdHash)))
			go c.p2pTransport.SendPacket(packet.SourceClientIdHash, responsePacket)
		}

		return nil
	})

	if err != nil {
		c.handler.OnLog(LogLevelError, fmt.Sprintf("Ошибка обработки P2P запроса ключей: %v", err))
	}
}

// sendMessageViaP2P отправляет сообщение через P2P транспорт
func (c *logicClient) sendMessageViaP2P(peerHash, text string, p2pTransport *P2PTransport) error {
	c.p2pTransport = p2pTransport
	contact, err := c.ks.LoadContact(peerHash)
	if err != nil {
		return fmt.Errorf("не могу найти контакт для отправки сообщения: %w", err)
	}

	if len(contact.RatchetState) == 0 {
		c.handler.OnLog(LogLevelInfo, "✅ [HANDSHAKE] Шаг 1: Сессия не установлена. Отправка запроса ключей (KeyRequest)...")

		// Устанавливаем флаг, что мы инициируем сессию.
		// Это поможет разрешить "гонку", если собеседник сделает то же самое.
		session := c.getOrCreateSession(peerHash)
		session.initMutex.Lock()
		session.keyRequestInFlight = true
		session.initMutex.Unlock()

		keyReqPacket := &proto2.Packet{
			SourceClientIdHash:      c.myUsernameHash,
			DestinationClientIdHash: peerHash,
			Payload:                 &proto2.Packet_KeyRequest{KeyRequest: &proto2.KeyRequest{RequestedClientIdHash: peerHash}},
		}

		if err := c.ks.WithUserAccount(c.username, func(ua *UserAccount) error {
			return c.signPacket(keyReqPacket, ua.IdentityPrivateDili)
		}); err != nil {
			return err
		}

		if err := p2pTransport.SendPacket(peerHash, keyReqPacket); err != nil {
			return fmt.Errorf("не удалось запросить ключи через P2P: %w", err)
		}

		c.handler.OnLog(LogLevelInfo, fmt.Sprintf("Сообщение для %s поставлено в очередь.", contact.Username))
		contact.PendingUserMsgs = append(contact.PendingUserMsgs, text)

		if err := c.ms.SaveMessage(peerHash, true, time.Now().Unix(), text); err != nil {
			c.handler.OnLog(LogLevelError, fmt.Sprintf("Ошибка сохранения сообщения в очередь в БД: %v", err))
		}

		return c.ks.SaveContact(contact)
	}

	var ratchet DoubleRatchet
	if err := json.Unmarshal(contact.RatchetState, &ratchet); err != nil {
		return fmt.Errorf("не удалось восстановить сессию для отправки: %w", err)
	}
	defer ratchet.Zeroize()

	headerData, ciphertext, err := ratchet.RatchetEncrypt([]byte(text), nil)
	if err != nil {
		return fmt.Errorf("ошибка шифрования: %w", err)
	}

	if err := c.persistRatchetState(peerHash, &ratchet); err != nil {
		return err
	}

	packet := &proto2.Packet{
		SourceClientIdHash:      c.myUsernameHash,
		DestinationClientIdHash: peerHash,
		Payload: &proto2.Packet_EncryptedMessage{EncryptedMessage: &proto2.EncryptedMessage{
			RatchetHeader: headerData,
			Ciphertext:    ciphertext,
			Timestamp:     time.Now().Unix(),
		}},
	}

	// Асимметричная подпись удалена для обеспечения отказуемости (Deniability).
	// Аутентификация сообщения обеспечивается симметричным тегом AES-GCM.

	if err := p2pTransport.SendPacket(peerHash, packet); err != nil {
		return fmt.Errorf("не удалось отправить сообщение через P2P: %w", err)
	}

	if err := c.ms.SaveMessage(peerHash, true, time.Now().Unix(), text); err != nil {
		c.handler.OnLog(LogLevelError, fmt.Sprintf("Ошибка сохранения отправленного сообщения в БД: %v", err))
	}
	c.handler.OnLog(LogLevelInfo, fmt.Sprintf("✅ Сообщение успешно отправлено через P2P пиру %s", truncateHash(peerHash)))
	return nil
}

// startProcessing начинает обработку пакетов после установки соединения.
func (c *logicClient) startProcessing(stream proto2.Phantom_TransmitClient, tlsConfig *tls.Config, readyChan chan<- error) {
	// Сначала получаем собственный хэш. Это критически важно для дальнейшей работы.
	myFinalHash, _, err := getHashesFromServerSecurely(c.username, "dummy", tlsConfig, c.handler)
	if err != nil {
		c.handler.OnLog(LogLevelError, fmt.Sprintf("Критическая ошибка: не удалось получить собственный хэш: %v", err))
		readyChan <- err
		return
	}
	c.myUsernameHash = myFinalHash
	c.handler.OnLog(LogLevelInfo, fmt.Sprintf("Вход выполнен. Ваш хэш (%s): %s...", c.username, truncateHash(c.myUsernameHash)))

	// Синхронизируем контакты, теперь когда у нас есть TLS конфиг.
	c.initialContactSync(tlsConfig)

	// Сохраняем стрим и регистрируемся на сервере
	c.stream = stream
	if err := c.register(); err != nil {
		c.handler.OnConnectionStateChanged("Critical Error", err)
		readyChan <- err
		return
	}

	c.handler.OnLog(LogLevelInfo, fmt.Sprintf("Запуск %d обработчиков пакетов...", workerPoolSize))
	c.wg.Add(workerPoolSize)
	for i := 0; i < workerPoolSize; i++ {
		go c.packetWorker()
	}

	readyChan <- nil // Сигнализируем, что клиент готов к работе

	go c.handleIncoming()
}

func (c *logicClient) handleIncoming() {
	defer close(c.packetQueue)

	for {
		packet, err := c.stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) || status.Code(err) == codes.Canceled {
				c.handler.OnConnectionStateChanged("Connection Closed", nil)
			} else {
				c.handler.OnConnectionStateChanged("Connection Lost", err)
				c.handler.OnLog(LogLevelWarning, fmt.Sprintf("Соединение потеряно: %v", err))
			}
			return
		}

		c.packetQueue <- packet
	}
}

func (c *logicClient) packetWorker() {
	defer c.wg.Done()

	for packet := range c.packetQueue {
		switch pld := packet.Payload.(type) {
		case *proto2.Packet_KeyResponse:
			c.handleKeyResponse(pld.KeyResponse)
		case *proto2.Packet_EncryptedMessage:
			c.handleEncryptedMessage(packet)
		case *proto2.Packet_SystemNotification:
			if c.handleSystemNotification(pld.SystemNotification) {
				c.handler.OnShutdown("Критическая ошибка регистрации, завершение работы.")
			}
		}
	}
}

func (c *logicClient) getHashForUsername(username string) string {
	c.contactsMu.RLock()
	defer c.contactsMu.RUnlock()
	return c.usernameToHash[username]
}

func (c *logicClient) getUsernameForHash(hash string) string {
	c.contactsMu.RLock()
	defer c.contactsMu.RUnlock()
	return c.hashToUsername[hash]
}

func (c *logicClient) initialContactSync(tlsConfig *tls.Config) {
	c.handler.OnLog(LogLevelInfo, "Синхронизация контактов с сервером...")
	contacts, err := c.ks.ListContactUsernames()
	if err != nil {
		c.handler.OnLog(LogLevelError, fmt.Sprintf("Не удалось загрузить контакты из БД для синхронизации: %v", err))
		return
	}

	newUsernameToHash := make(map[string]string)
	newHashToUsername := make(map[string]string)
	var contactInfos []ContactInfo

	for _, name := range contacts {
		_, hash, err := getHashesFromServerSecurely("dummy", name, tlsConfig, c.handler)
		if err == nil {
			newUsernameToHash[name] = hash
			newHashToUsername[hash] = name
			contactInfos = append(contactInfos, ContactInfo{Name: name, Hash: hash})

			// Убеждаемся, что контакт сохранен в локальной БД
			_, err := c.ks.LoadContact(hash)
			if err != nil {
				// Контакт не найден в БД, создаем его
				contact := &Contact{
					Username:     name,
					UsernameHash: hash,
				}
				if err := c.ks.SaveContact(contact); err != nil {
					c.handler.OnLog(LogLevelWarning, fmt.Sprintf("Не удалось сохранить контакт %s в БД: %v", name, err))
				}
			}
		} else {
			c.handler.OnLog(LogLevelWarning, fmt.Sprintf("Не удалось получить хеш для контакта '%s' при синхронизации.", name))
		}
	}

	c.contactsMu.Lock()
	c.usernameToHash = newUsernameToHash
	c.hashToUsername = newHashToUsername
	c.contactsMu.Unlock()

	c.handler.OnContactListUpdated(contactInfos)
	c.handler.OnLog(LogLevelInfo, fmt.Sprintf("Синхронизация контактов завершена. Загружено %d контактов.", len(c.usernameToHash)))
}

func (c *logicClient) handleKeyResponse(resp *proto2.KeyResponse) {
	peerHash := resp.ClientIdHash
	c.handler.OnLog(LogLevelInfo, fmt.Sprintf("✅ [HANDSHAKE] Шаг 2: Получен KeyResponse от %s.", truncateHash(peerHash)))

	session := c.getOrCreateSession(peerHash)
	session.initMutex.Lock()
	defer session.initMutex.Unlock()

	contact, err := c.ks.LoadContact(peerHash)
	if err == nil && len(contact.RatchetState) > 0 {
		c.handler.OnLog(LogLevelInfo, fmt.Sprintf("Сессия с %s уже установлена, игнорируем KeyResponse.", truncateHash(peerHash)))
		return
	}

	session.pendingKeyResp = resp

	c.handler.OnLog(LogLevelInfo, "✅ [HANDSHAKE] Шаг 3: Инициирую установку сессии как Алиса...")
	if c.establishSessionAsAlice(session, peerHash) {
		c.handler.OnLog(LogLevelInfo, "✅ [HANDSHAKE] Шаг 4: Сессия как Алиса успешно установлена.")
		c.handler.OnSessionEstablished(peerHash)

		freshContact, err := c.ks.LoadContact(peerHash)
		if err == nil && freshContact != nil {
			go c.processUserMessages(freshContact)
		}
	} else {
		c.handler.OnLog(LogLevelError, fmt.Sprintf("❌ [HANDSHAKE] Не удалось установить сессию с %s после получения ключей.", truncateHash(peerHash)))
	}
}

func (c *logicClient) establishSessionAsAlice(session *peerSession, peerHash string) bool {
	contact, err := c.ks.LoadContact(peerHash)
	if err == nil && len(contact.RatchetState) > 0 {
		return true
	}

	c.handler.OnLog(LogLevelInfo, "Вы выступаете в роли ИНИЦИАТОРА. Создание гибридной сессии...")
	ratchet, initialCts, err := c.initAlice(session)
	if err != nil {
		c.handler.OnLog(LogLevelError, fmt.Sprintf("Ошибка инициализации (Alice): %v", err))
		return false
	}
	defer ratchet.Zeroize()

	c.handler.OnLog(LogLevelInfo, "Сессия установлена. Отправка пакета инициации...")
	initiationPayload := fmt.Sprintf("%s:%s", InitiateChatMessage, c.username)

	err = c.sendEncryptedPacket(peerHash, initiationPayload, ratchet, initialCts)
	if err != nil {
		c.handler.OnLog(LogLevelError, fmt.Sprintf("Критическая ошибка: не удалось отправить пакет инициации: %v", err))
		return false
	}

	session.initMutex.Lock()
	session.isEstablished = true
	session.initMutex.Unlock()

	return true
}

func (c *logicClient) sendEncryptedPacket(peerHash, text string, ratchet *DoubleRatchet, initialCts *InitialCiphertexts) error {
	finalHeaderData, ciphertext, err := ratchet.RatchetEncrypt([]byte(text), initialCts)
	if err != nil {
		return fmt.Errorf("ошибка шифрования: %w", err)
	}

	if err := c.persistRatchetState(peerHash, ratchet); err != nil {
		return err
	}

	packet := &proto2.Packet{
		SourceClientIdHash:      c.myUsernameHash,
		DestinationClientIdHash: peerHash,
		Payload: &proto2.Packet_EncryptedMessage{EncryptedMessage: &proto2.EncryptedMessage{
			RatchetHeader: finalHeaderData,
			Ciphertext:    ciphertext,
			Timestamp:     time.Now().Unix(),
		}},
	}

	// Подписываем только пакет инициации сессии для подтверждения авторства ключей.
	// Обычные сообщения не подписываются для обеспечения отказуемости (deniability).
	if initialCts != nil {
		err = c.ks.WithUserAccount(c.username, func(ua *UserAccount) error {
			return c.signPacket(packet, ua.IdentityPrivateDili)
		})
		if err != nil {
			return err
		}
	}

	// Пытаемся отправить через P2P если доступно
	if c.p2pTransport != nil && c.p2pTransport.IsP2PAvailable(peerHash) {
		if err := c.p2pTransport.SendPacket(peerHash, packet); err == nil {
			c.handler.OnLog(LogLevelInfo, "✉️ Пакет отправлен через P2P")
			return nil
		}
	}

	// Отправляем через сервер
	go func() {
		if c.stream == nil {
			c.handler.OnLog(LogLevelError, "Ошибка отправки: gRPC поток не инициализирован.")
			return
		}
		if err := c.stream.Send(packet); err != nil {
			c.handler.OnLog(LogLevelError, fmt.Sprintf("Ошибка отправки пакета на сервер: %v", err))
		}
	}()
	return nil
}

func (c *logicClient) handleEncryptedMessage(packet *proto2.Packet) {
	peerHash := packet.SourceClientIdHash
	session := c.getOrCreateSession(peerHash)

	session.initMutex.Lock()

	contact, _ := c.ks.LoadContact(peerHash)
	if contact != nil && len(contact.RatchetState) > 0 {
		session.initMutex.Unlock()
		c.decryptAndHandle(packet)
		return
	}

	session.pendingInboundPkts = append(session.pendingInboundPkts, packet)

	if session.keyRequestInFlight {
		session.initMutex.Unlock()
		return
	}

	session.keyRequestInFlight = true
	session.initMutex.Unlock()

	c.handler.OnLog(LogLevelInfo, fmt.Sprintf("Получен зашифрованный пакет от %s, но ключи еще не получены. Запрос ключей...", truncateHash(peerHash)))
	c.requestKeys(peerHash)
}

func (c *logicClient) processInboundPackets(packetsToProcess []*proto2.Packet) {
	if len(packetsToProcess) == 0 {
		return
	}
	peerHash := packetsToProcess[0].SourceClientIdHash

	established := c.tryEstablishSessionAsBob(peerHash, packetsToProcess[0])
	if established {
		c.handler.OnSessionEstablished(peerHash)
	}

	for _, packet := range packetsToProcess {
		c.decryptAndHandle(packet)
	}
}

func (c *logicClient) tryEstablishSessionAsBob(peerHash string, packet *proto2.Packet) bool {
	contact, err := c.ks.LoadContact(peerHash)
	if err == nil && len(contact.RatchetState) > 0 {
		return true
	}

	session := c.getOrCreateSession(peerHash)

	if session.pendingKeyResp == nil {
		return false
	}

	msg := packet.GetEncryptedMessage()
	var headerWithInitialCts struct {
		RatchetHeader
		InitialCiphertexts *InitialCiphertexts `json:"initial_cts,omitempty"`
	}
	if err := json.Unmarshal(msg.RatchetHeader, &headerWithInitialCts); err != nil {
		return false
	}
	if headerWithInitialCts.InitialCiphertexts == nil {
		return false
	}

	var ratchet *DoubleRatchet
	err = c.ks.WithUserAccount(c.username, func(ua *UserAccount) error {
		var initErr error
		ratchet, initErr = c.initBob(session, ua, headerWithInitialCts.RatchetHeader, headerWithInitialCts.InitialCiphertexts)
		return initErr
	})

	if err != nil {
		c.handler.OnLog(LogLevelError, fmt.Sprintf("Ошибка инициализации сессии из пакета: %v", err))
		return false
	}
	defer ratchet.Zeroize()

	if err := c.persistRatchetState(peerHash, ratchet); err != nil {
		c.handler.OnLog(LogLevelError, fmt.Sprintf("Критическая ошибка сохранения сессии Боба: %v", err))
		return false
	}

	session.initMutex.Lock()
	session.isEstablished = true
	session.initMutex.Unlock()

	if newContact, err := c.ks.LoadContact(peerHash); err == nil && newContact != nil {
		go c.processUserMessages(newContact)
	}
	return true
}

func (c *logicClient) decryptAndHandle(packet *proto2.Packet) {
	peerHash := packet.SourceClientIdHash
	contact, err := c.ks.LoadContact(peerHash)

	// **КЛЮЧЕВОЕ ИСПРАВЛЕНИЕ**
	if err != nil || len(contact.RatchetState) == 0 {
		c.handler.OnLog(LogLevelInfo, fmt.Sprintf("Получен шифрованный пакет от %s, но сессии нет. Попытка установить как Боб...", truncateHash(peerHash)))

		if c.tryEstablishSessionAsBob(peerHash, packet) {
			c.handler.OnLog(LogLevelInfo, "✅ Сессия успешно установлена как Боб. Повторная обработка пакета...")
			c.decryptAndHandle(packet) // Рекурсивный вызов для расшифровки тем же пакетом
		} else {
			c.handler.OnLog(LogLevelWarning, fmt.Sprintf("Не удалось установить сессию как Боб. Пакет от %s отброшен.", truncateHash(peerHash)))
		}
		return
	}

	var ratchet DoubleRatchet
	if err := json.Unmarshal(contact.RatchetState, &ratchet); err != nil {
		c.handler.OnLog(LogLevelError, fmt.Sprintf("Не удалось восстановить сессию для расшифровки: %v", err))
		return
	}
	defer ratchet.Zeroize()

	plaintextBytes, err := ratchet.RatchetDecrypt(packet.GetEncryptedMessage().RatchetHeader, packet.GetEncryptedMessage().Ciphertext)
	if err != nil {
		c.handler.OnLog(LogLevelError, fmt.Sprintf("Ошибка расшифровки: %v", err))
		return
	}
	c.handler.OnLog(LogLevelInfo, fmt.Sprintf("✅ Сообщение от %s успешно расшифровано.", truncateHash(peerHash)))

	if err := c.persistRatchetState(peerHash, &ratchet); err != nil {
		c.handler.OnLog(LogLevelCritical, fmt.Sprintf("Не удалось сохранить состояние сессии после расшифровки: %v", err))
	}

	plaintext := string(plaintextBytes)
	timestamp := packet.GetEncryptedMessage().Timestamp

	if strings.HasPrefix(plaintext, InitiateChatMessage) {
		parts := strings.SplitN(plaintext, ":", 2)
		if len(parts) == 2 {
			revealedUsername := parts[1]
			c.handler.OnLog(LogLevelInfo, fmt.Sprintf("Собеседник %s (%s...) инициировал чат.", revealedUsername, truncateHash(packet.SourceClientIdHash)))

			go beeep.Notify("Новый чат", fmt.Sprintf("Пользователь '%s' хочет начать с вами диалог.", revealedUsername), "")

			if contact.Username == "" || strings.HasPrefix(contact.Username, "Незнакомец") {
				contact.Username = revealedUsername
				if err := c.ks.SaveContact(contact); err != nil {
					c.handler.OnLog(LogLevelError, fmt.Sprintf("Не удалось сохранить имя собеседника: %v", err))
				} else {
					c.contactsMu.Lock()
					c.usernameToHash[revealedUsername] = peerHash
					c.hashToUsername[peerHash] = revealedUsername
					c.contactsMu.Unlock()

					c.handler.OnLog(LogLevelInfo, "Обнаружен новый контакт. Немедленное обновление списка контактов в UI...")

					c.contactsMu.RLock()
					var allContacts []ContactInfo
					for name, hash := range c.usernameToHash {
						allContacts = append(allContacts, ContactInfo{Name: name, Hash: hash, IsOnline: true})
					}
					c.contactsMu.RUnlock()

					c.handler.OnContactListUpdated(allContacts)
				}
			}
		}
		return
	}

	var senderName string
	if contact != nil && contact.Username != "" {
		senderName = contact.Username
	} else {
		senderName = c.getUsernameForHash(peerHash)
		if senderName == "" {
			senderName = truncateHash(peerHash)
		}
	}

	if err := c.ms.SaveMessage(peerHash, false, timestamp, plaintext); err != nil {
		c.handler.OnLog(LogLevelError, fmt.Sprintf("Ошибка сохранения входящего сообщения в БД: %v", err))
	}

	msg := StoredMessage{
		SessionHash: peerHash, IsOutgoing: false, Timestamp: timestamp, Content: plaintext,
	}

	go beeep.Notify(fmt.Sprintf("New message from %s", senderName), plaintext, "")
	c.handler.OnMessageReceived(msg)
}

func (c *logicClient) processUserMessages(contact *Contact) {
	if len(contact.PendingUserMsgs) == 0 {
		return
	}
	messagesToSend := contact.PendingUserMsgs
	contact.PendingUserMsgs = []string{}

	if err := c.ks.SaveContact(contact); err != nil {
		c.handler.OnLog(LogLevelError, fmt.Sprintf("Не удалось очистить очередь в БД перед отправкой: %v", err))
	}

	c.handler.OnLog(LogLevelInfo, fmt.Sprintf("✅ [HANDSHAKE] Шаг 5: Сессия установлена. Отправка %d отложенных сообщений для %s...", len(messagesToSend), contact.Username))

	for _, text := range messagesToSend {
		if err := c.sendMessageViaP2P(contact.UsernameHash, text, c.p2pTransport); err != nil {
			c.handler.OnLog(LogLevelError, fmt.Sprintf("Ошибка отправки сообщения '%s': %v.", text, err))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (c *logicClient) startNewChat(peerUsername string, tlsConfig *tls.Config) error {
	_, peerHash, err := getHashesFromServerSecurely(c.username, peerUsername, tlsConfig, c.handler)
	if err != nil {
		return fmt.Errorf("could not get hash for %s: %w", peerUsername, err)
	}

	c.contactsMu.Lock()
	c.usernameToHash[peerUsername] = peerHash
	c.hashToUsername[peerHash] = peerUsername
	c.contactsMu.Unlock()

	contact, _ := c.ks.LoadContact(peerHash)
	if contact == nil {
		contact = &Contact{Username: peerUsername, UsernameHash: peerHash}
		if err := c.ks.SaveContact(contact); err != nil {
			return fmt.Errorf("could not save new contact: %w", err)
		}
		go c.initialContactSync(tlsConfig)
	}

	c.handler.OnLog(LogLevelInfo, fmt.Sprintf("Starting new chat with %s (%s...)", peerUsername, truncateHash(peerHash)))
	return c.requestKeys(peerHash)
}

func (c *logicClient) sendMessage(peerHash, text string) error {
	contact, err := c.ks.LoadContact(peerHash)
	if err != nil {
		return fmt.Errorf("не могу найти контакт для отправки сообщения: %w", err)
	}

	if len(contact.RatchetState) > 0 {
		var ratchet DoubleRatchet
		if err := json.Unmarshal(contact.RatchetState, &ratchet); err != nil {
			return fmt.Errorf("не удалось восстановить сессию для отправки: %w", err)
		}
		defer ratchet.Zeroize()

		err := c.sendEncryptedPacket(peerHash, text, &ratchet, nil)
		if err == nil {
			c.ms.SaveMessage(peerHash, true, time.Now().Unix(), text)
		}
		return err
	}

	c.handler.OnLog(LogLevelInfo, "Сессия не установлена. Сообщение сохранено и будет отправлено автоматически.")
	contact.PendingUserMsgs = append(contact.PendingUserMsgs, text)

	// Сохраняем контакт с сообщением в очереди
	if err := c.ks.SaveContact(contact); err != nil {
		return fmt.Errorf("не удалось сохранить сообщение в очередь: %w", err)
	}

	// После сохранения сообщения в очередь, немедленно инициируем хендшейк,
	// отправляя запрос на ключи через сервер.
	return c.requestKeys(peerHash)
}

func (c *logicClient) initAlice(session *peerSession) (*DoubleRatchet, *InitialCiphertexts, error) {
	resp := session.pendingKeyResp
	var prekeyBundle proto2.HybridPreKeyBundle
	if err := proto.Unmarshal(resp.HybridPrekeyBundle, &prekeyBundle); err != nil {
		return nil, nil, fmt.Errorf("ошибка разбора HybridPreKeyBundle: %w", err)
	}
	diliScheme, kemScheme := mode5.Scheme(), kyber1024.Scheme()
	theirIKeyDili, err := diliScheme.UnmarshalBinaryPublicKey(prekeyBundle.IdentityKeyDilithium)
	if err != nil {
		return nil, nil, err
	}
	theirIKeyKyber, err := kemScheme.UnmarshalBinaryPublicKey(prekeyBundle.IdentityKeyKyber)
	if err != nil {
		return nil, nil, err
	}
	theirSPKeyKyber, err := kemScheme.UnmarshalBinaryPublicKey(prekeyBundle.SignedPrekeyKyber)
	if err != nil {
		return nil, nil, err
	}

	if len(prekeyBundle.IdentityKeyX25519) != 32 || len(prekeyBundle.SignedPrekeyX25519) != 32 {
		return nil, nil, errors.New("неверная длина классических ключей в бандле")
	}
	theirIKeyX25519, theirSPKeyX25519 := (*[32]byte)(prekeyBundle.IdentityKeyX25519), (*[32]byte)(prekeyBundle.SignedPrekeyX25519)
	dataToVerify := append(prekeyBundle.SignedPrekeyKyber, prekeyBundle.SignedPrekeyX25519...)
	if !mode5.Verify(theirIKeyDili.(*mode5.PublicKey), dataToVerify, prekeyBundle.PrekeySignatureDilithium) {
		return nil, nil, errors.New("гибрид: неверная подпись prekey собеседника (Dilithium5)")
	}
	if err := c.verifyIdentityKeys(theirIKeyDili, theirIKeyX25519, resp.ClientIdHash); err != nil {
		return nil, nil, err
	}
	var theirOPKeyKyber *kyber1024.PublicKey
	var theirOPKeyX25519 *[32]byte
	if len(resp.OneTimePrekeyKyber) > 0 {
		opk, err := kemScheme.UnmarshalBinaryPublicKey(resp.OneTimePrekeyKyber)
		if err != nil {
			return nil, nil, err
		}
		theirOPKeyKyber = opk.(*kyber1024.PublicKey)
		if len(resp.OneTimePrekeyX25519) != 32 {
			return nil, nil, errors.New("получен OPK Kyber, но OPK X25519 имеет неверную длину")
		}
		theirOPKeyX25519 = (*[32]byte)(resp.OneTimePrekeyX25519)
	} else {
		c.handler.OnLog(LogLevelWarning, "ВНИМАНИЕ: Собеседник не предоставил одноразовые ключи (OPK).")
	}
	ratchet, initialCts, err := RatchetInitAlice(theirIKeyKyber.(*kyber1024.PublicKey), theirIKeyX25519, theirSPKeyKyber.(*kyber1024.PublicKey), theirSPKeyX25519, theirOPKeyKyber, theirOPKeyX25519, resp.OneTimePrekeyId)
	if err != nil {
		return nil, nil, err
	}

	return ratchet, initialCts, nil
}

func (c *logicClient) initBob(session *peerSession, ua *UserAccount, header RatchetHeader, initialCts *InitialCiphertexts) (*DoubleRatchet, error) {
	resp := session.pendingKeyResp
	var prekeyBundle proto2.HybridPreKeyBundle
	if err := proto.Unmarshal(resp.HybridPrekeyBundle, &prekeyBundle); err != nil {
		return nil, fmt.Errorf("ошибка разбора HybridPreKeyBundle для Bob: %w", err)
	}
	diliScheme, kemScheme := mode5.Scheme(), kyber1024.Scheme()
	theirIKeyDili, err := diliScheme.UnmarshalBinaryPublicKey(prekeyBundle.IdentityKeyDilithium)
	if err != nil {
		return nil, err
	}

	if len(prekeyBundle.IdentityKeyX25519) != 32 {
		return nil, errors.New("неверная длина X25519 IK в бандле Боба")
	}
	theirIKeyX25519 := (*[32]byte)(prekeyBundle.IdentityKeyX25519)
	if err := c.verifyIdentityKeys(theirIKeyDili, theirIKeyX25519, resp.ClientIdHash); err != nil {
		return nil, err
	}
	pk, err := kemScheme.UnmarshalBinaryPublicKey(header.KyberPublicKey)
	if err != nil {
		return nil, err
	}
	theirEphemeralKyberPub := pk.(*kyber1024.PublicKey)
	if len(initialCts.EphemeralECPublicKey) != 32 {
		return nil, errors.New("неверная длина эфемерного ключа Алисы")
	}
	theirEphemeralECPub := (*[32]byte)(initialCts.EphemeralECPublicKey)
	opkID := initialCts.OPKID
	ourUsedOneTimeKey, ok := ua.OneTimePreKeys[opkID]
	var ourOpkPrivKyber *kyber1024.PrivateKey
	var ourOpkPrivX25519 *[32]byte
	if ok {
		c.handler.OnLog(LogLevelInfo, fmt.Sprintf("Инициатор использовал наш гибридный OPK #%d.", opkID))
		ourOpkPrivKyber, ourOpkPrivX25519 = ourUsedOneTimeKey.PrivateKeyKyber, ourUsedOneTimeKey.PrivateKeyX25519
	} else if len(initialCts.OPKCiphertext) > 0 {
		return nil, fmt.Errorf("критическая ошибка: инициатор использовал OPK с ID %d, который не найден у нас", opkID)
	}
	ratchet, err := RatchetInitBob(ua.IdentityPrivateKyber, ua.IdentityPrivateX25519, ua.PreKeyPrivateKyber, ua.PreKeyPrivateX25519, ourOpkPrivKyber, ourOpkPrivX25519, theirEphemeralKyberPub, theirEphemeralECPub, initialCts)
	if err != nil {
		return nil, err
	}

	if ok {
		delete(ua.OneTimePreKeys, opkID)
		if err := c.ks.saveAccount(ua); err != nil {
			c.handler.OnLog(LogLevelWarning, fmt.Sprintf("Не удалось сохранить аккаунт после удаления OPK: %v", err))
		}
	}
	return ratchet, nil
}

func (c *logicClient) getOrCreateSession(peerHash string) *peerSession {
	c.mu.RLock()
	session, exists := c.peerSessions[peerHash]
	c.mu.RUnlock()
	if exists {
		return session
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	session, exists = c.peerSessions[peerHash]
	if exists {
		return session
	}

	c.handler.OnLog(LogLevelInfo, fmt.Sprintf("Создана новая пустая сессия для %s...", truncateHash(peerHash)))
	session = &peerSession{}
	c.peerSessions[peerHash] = session

	return session
}

func (c *logicClient) verifyIdentityKeys(newKeyDili sign.PublicKey, newKeyX25519 *[32]byte, peerHash string) error {
	contact, err := c.ks.LoadContact(peerHash)
	if err == nil && contact != nil && contact.IdentityPublicDili != nil && contact.IdentityPublicX25519 != nil {
		diliChanged := !contact.IdentityPublicDili.Equal(newKeyDili)
		ecChanged := !bytes.Equal(contact.IdentityPublicX25519[:], newKeyX25519[:])
		if diliChanged || ecChanged {
			c.handler.OnLog(LogLevelWarning, "ВНИМАНИЕ: Ключ идентификации собеседника изменился! Возможна атака.")
			return errors.New("смена ключа идентификации")
		}
	}
	if contact == nil {
		contact = &Contact{UsernameHash: peerHash}
	}
	contact.IdentityPublicDili, contact.IdentityPublicX25519 = newKeyDili, newKeyX25519
	if err := c.ks.SaveContact(contact); err != nil {
		c.handler.OnLog(LogLevelError, fmt.Sprintf("Ошибка сохранения IdentityKey: %v", err))
	}
	return nil
}

func (c *logicClient) register() error {
	c.handler.OnLog(LogLevelInfo, "Регистрация на сервере с гибридными ключами...")

	return c.ks.WithUserAccount(c.username, func(ua *UserAccount) error {
		opksKyber := make(map[uint32][]byte)
		opksX25519 := make(map[uint32][]byte)
		for id, key := range ua.OneTimePreKeys {
			pubBytesK, err := key.PublicKeyKyber.MarshalBinary()
			if err != nil {
				return err
			}
			opksKyber[id], opksX25519[id] = pubBytesK, key.PublicKeyX25519[:]
		}

		idPubDiliBytes, err := ua.IdentityPublicDili.MarshalBinary()
		if err != nil {
			return err
		}
		idPubKyberBytes, err := ua.IdentityPublicKyber.MarshalBinary()
		if err != nil {
			return err
		}
		spkPubKyberBytes, err := ua.PreKeyPublicKyber.MarshalBinary()
		if err != nil {
			return err
		}

		idPubX25519Bytes := ua.IdentityPublicX25519[:]
		spkPubX25519Bytes := ua.PreKeyPublicX25519[:]
		dataToSign := append(spkPubKyberBytes, spkPubX25519Bytes...)

		sig := mode5.Scheme().Sign(ua.IdentityPrivateDili, dataToSign, nil)

		prekeyBundle := &proto2.HybridPreKeyBundle{
			IdentityKeyDilithium: idPubDiliBytes, IdentityKeyKyber: idPubKyberBytes, IdentityKeyX25519: idPubX25519Bytes,
			SignedPrekeyKyber: spkPubKyberBytes, SignedPrekeyX25519: spkPubX25519Bytes,
			PrekeySignatureDilithium: sig, OneTimePrekeysKyber: opksKyber, OneTimePrekeysX25519: opksX25519,
		}
		bundleData, err := proto.Marshal(prekeyBundle)
		if err != nil {
			return err
		}

		// Подготавливаем регистрационный запрос
		regRequest := &proto2.RegistrationRequest{
			HybridPrekeyBundle: bundleData,
		}

		// Добавляем P2P информацию если P2P транспорт активен
		if c.p2pTransport != nil {
			peerID := c.getP2PPeerID()
			addresses := c.getP2PAddresses()
			if peerID != "" && len(addresses) > 0 {
				regRequest.P2PInfo = &proto2.P2PInfo{
					PeerId:       peerID,
					Addresses:    addresses,
					PreferP2P:    true,
					RelayWilling: false, // По умолчанию не relay
				}
				c.handler.OnLog(LogLevelInfo, "📡 Регистрация с P2P поддержкой")
			}
		}

		packet := &proto2.Packet{
			SourceClientIdHash: c.myUsernameHash,
			Payload:            &proto2.Packet_RegistrationRequest{RegistrationRequest: regRequest},
		}

		if err := c.signPacket(packet, ua.IdentityPrivateDili); err != nil {
			return err
		}

		c.handler.OnLog(LogLevelInfo, fmt.Sprintf("✅ Гибридный регистрационный пакет с %d OPK отправлен.", len(opksKyber)))
		return c.stream.Send(packet)
	})
}

func (c *logicClient) requestKeys(userHash string) error {
	c.handler.OnLog(LogLevelInfo, fmt.Sprintf("Запрос ключей для %s...", truncateHash(userHash)))
	packet := &proto2.Packet{
		SourceClientIdHash: c.myUsernameHash,
		Payload:            &proto2.Packet_KeyRequest{KeyRequest: &proto2.KeyRequest{RequestedClientIdHash: userHash}},
	}

	err := c.ks.WithUserAccount(c.username, func(ua *UserAccount) error {
		return c.signPacket(packet, ua.IdentityPrivateDili)
	})
	if err != nil {
		return err
	}

	return c.stream.Send(packet)
}

func (c *logicClient) persistRatchetState(userHash string, ratchet *DoubleRatchet) error {
	contact, err := c.ks.LoadContact(userHash)
	if err != nil {
		contact = &Contact{UsernameHash: userHash}
	}
	ratchetData, err := json.Marshal(ratchet)
	if err != nil {
		c.handler.OnLog(LogLevelCritical, fmt.Sprintf("Не удалось сериализовать состояние рэтчета: %v", err))
		return err
	}
	contact.RatchetState = ratchetData
	if err := c.ks.SaveContact(contact); err != nil {
		c.handler.OnLog(LogLevelCritical, fmt.Sprintf("Не удалось сохранить состояние сессии в БД: %v", err))
		return err
	}
	return nil
}

func (c *logicClient) signPacket(packet *proto2.Packet, privKey sign.PrivateKey) error {
	packetCopy := proto.Clone(packet).(*proto2.Packet)
	packetCopy.Signature = nil
	data, err := proto.Marshal(packetCopy)
	if err != nil {
		return fmt.Errorf("ошибка сериализации пакета для подписи: %w", err)
	}
	packet.Signature = mode5.Scheme().Sign(privKey, data, nil)
	return nil
}

func (c *logicClient) handleSystemNotification(notif *proto2.SystemNotification) bool {
	switch notif.Type {
	case proto2.SystemNotification_OPK_LOW:
		c.handler.OnLog(LogLevelWarning, "ВНИМАНИЕ: На сервере заканчиваются ваши одноразовые ключи (OPK).")
		go c.replenishOPKsAndReregister()
	case proto2.SystemNotification_REGISTRATION_FAILED_USERNAME_TAKEN:
		c.handler.OnLog(LogLevelCritical, fmt.Sprintf("ОШИБКА РЕГИСТРАЦИИ: %s", notif.Message))
		return true
	case proto2.SystemNotification_P2P_AVAILABLE:
		// Обработка уведомления о доступности P2P
		if notif.P2PInfo != nil && c.p2pTransport != nil {
			c.handler.OnLog(LogLevelInfo, fmt.Sprintf("🌐 Получено уведомление: пир доступен через P2P"))
			c.updateP2PPeerInfo(notif.P2PInfo)
		}
	case proto2.SystemNotification_P2P_PEER_INFO:
		// Обработка P2P информации о пире
		if notif.P2PInfo != nil && c.p2pTransport != nil {
			c.handler.OnLog(LogLevelInfo, fmt.Sprintf("📡 Получена P2P информация о пире"))
			c.updateP2PPeerInfo(notif.P2PInfo)
		}
	}
	return false
}

// updateP2PPeerInfo обновляет информацию о P2P пире
func (c *logicClient) updateP2PPeerInfo(info *proto2.P2PInfo) {
	if c.p2pTransport == nil || info == nil {
		return
	}

	// Пытаемся подключиться к пиру используя полученную информацию
	go func() {
		for _, addr := range info.Addresses {
			c.handler.OnLog(LogLevelInfo, fmt.Sprintf("🔗 Попытка подключения к P2P адресу: %s", addr))
			// P2P транспорт сам обработает подключение
		}
	}()
}

// getP2PPeerID возвращает PeerID для P2P транспорта
func (c *logicClient) getP2PPeerID() string {
	if c.p2pTransport == nil || c.p2pTransport.host == nil {
		return ""
	}
	return c.p2pTransport.host.ID().String()
}

// getP2PAddresses возвращает multiaddr адреса для P2P транспорта
func (c *logicClient) getP2PAddresses() []string {
	if c.p2pTransport == nil || c.p2pTransport.host == nil {
		return nil
	}

	addrs := c.p2pTransport.host.Addrs()
	result := make([]string, 0, len(addrs))

	hostID := c.p2pTransport.host.ID().String()
	for _, addr := range addrs {
		// Добавляем PeerID к адресу
		fullAddr := fmt.Sprintf("%s/p2p/%s", addr.String(), hostID)
		result = append(result, fullAddr)
	}

	return result
}

// sendP2PUpdate отправляет обновление P2P информации на сервер
func (c *logicClient) sendP2PUpdate() error {
	if c.stream == nil || c.p2pTransport == nil {
		return nil
	}

	addresses := c.getP2PAddresses()
	if len(addresses) == 0 {
		return nil
	}

	update := &proto2.P2PUpdate{
		Addresses:    addresses,
		RelayWilling: false,
	}

	packet := &proto2.Packet{
		SourceClientIdHash: c.myUsernameHash,
		Payload:            &proto2.Packet_P2PUpdate{P2PUpdate: update},
	}

	err := c.ks.WithUserAccount(c.username, func(ua *UserAccount) error {
		return c.signPacket(packet, ua.IdentityPrivateDili)
	})
	if err != nil {
		return err
	}

	return c.stream.Send(packet)
}

func (c *logicClient) replenishOPKsAndReregister() {
	err := c.ks.WithUserAccount(c.username, func(ua *UserAccount) error {
		c.handler.OnLog(LogLevelInfo, "Пополнение OPK...")
		newAccount, err := c.ks.ReplenishOPKs(c.username, ua)
		if err != nil {
			return fmt.Errorf("ошибка пополнения OPK в локальной БД: %v", err)
		}
		c.handler.OnLog(LogLevelInfo, fmt.Sprintf("✅ Локальные OPK пополнены. Текущее количество: %d.", len(newAccount.OneTimePreKeys)))
		return nil
	})

	if err != nil {
		c.handler.OnLog(LogLevelError, err.Error())
		return
	}

	if err := c.register(); err != nil {
		c.handler.OnLog(LogLevelError, fmt.Sprintf("Ошибка повторной регистрации с новыми OPK: %v", err))
	}
}

func (c *logicClient) generateSafetyNumber(peerHash string) (string, error) {
	var safetyNumber string
	err := c.ks.WithUserAccount(c.username, func(ua *UserAccount) error {
		contact, err := c.ks.LoadContact(peerHash)
		if err != nil || contact.IdentityPublicDili == nil || contact.IdentityPublicX25519 == nil {
			return errors.New("невозможно сгенерировать номер безопасности: информация о собеседнике отсутствует. Убедитесь, что сессия успешно установлена")
		}
		myIDKeyDili, _ := ua.IdentityPublicDili.MarshalBinary()
		myIDKeyEC := ua.IdentityPublicX25519[:]
		theirIDKeyDili, _ := contact.IdentityPublicDili.MarshalBinary()
		theirIDKeyEC := contact.IdentityPublicX25519[:]
		myCombinedID := append(myIDKeyDili, myIDKeyEC...)
		theirCombinedID := append(theirIDKeyDili, theirIDKeyEC...)
		var combined []byte
		if bytes.Compare(myCombinedID, theirCombinedID) < 0 {
			combined = append(myCombinedID, theirCombinedID...)
		} else {
			combined = append(theirCombinedID, myCombinedID...)
		}
		hash := sha512.Sum512_256(combined)
		var safetyNumbers [6]uint64
		for i := 0; i < 6; i++ {
			chunk := hash[i*5 : (i+1)*5]
			paddedChunk := make([]byte, 8)
			copy(paddedChunk[3:], chunk)
			val := binary.BigEndian.Uint64(paddedChunk)
			safetyNumbers[i] = val % 100000
		}
		safetyNumber = fmt.Sprintf("%05d %05d %05d\n   %05d %05d %05d",
			safetyNumbers[0], safetyNumbers[1], safetyNumbers[2],
			safetyNumbers[3], safetyNumbers[4], safetyNumbers[5])
		return nil
	})
	return safetyNumber, err
}

func (c *logicClient) shutdown() {
	c.handler.OnLog(LogLevelInfo, "ℹ️ Ожидание завершения обработчиков пакетов...")
	c.wg.Wait()
	c.handler.OnLog(LogLevelInfo, "✅ Обработчики пакетов остановлены.")
}

func truncateHash(hash string) string {
	if len(hash) > 8 {
		return hash[:8]
	}
	return hash
}

// forceConnection принудительно устанавливает соединение через реальный вызов.
func forceConnection(conn *grpc.ClientConn, timeout time.Duration, handler CoreEventHandler) error {
	handler.OnLog(LogLevelInfo, fmt.Sprintf("🔍 Проверка соединения (таймаут: %v)", timeout))
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	authClient := proto2.NewAuthClient(conn)
	state := conn.GetState()
	handler.OnLog(LogLevelInfo, fmt.Sprintf("📊 Текущее состояние: %v", state))

	_, err := authClient.GetPublicSalt(ctx, &proto2.PublicSaltRequest{})
	if err != nil {
		finalState := conn.GetState()
		handler.OnLog(LogLevelError, fmt.Sprintf("❌ Проверка не удалась. Состояние: %v → %v, ошибка: %v", state, finalState, err))
		return err
	}
	finalState := conn.GetState()
	handler.OnLog(LogLevelInfo, fmt.Sprintf("✅ Проверка успешна. Состояние: %v → %v", state, finalState))
	return nil
}

func getHashesFromServerSecurely(myUsername, destUsername string, tlsConfig *tls.Config, handler CoreEventHandler) (string, string, error) {
	maxAttempts := 3
	baseTimeout := 10 * time.Second

	creds := credentials.NewTLS(tlsConfig)

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		timeout := time.Duration(attempt) * baseTimeout
		var conn *grpc.ClientConn
		var err error

		conn, err = grpc.NewClient(
			serverAddress,
			grpc.WithTransportCredentials(creds),
			grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(1024*1024)),
		)
		if err != nil {
			if attempt == maxAttempts {
				return "", "", fmt.Errorf("не удалось подключиться для получения хэшей после %d попыток: %v", maxAttempts, err)
			}
			handler.OnLog(LogLevelWarning, fmt.Sprintf("Попытка %d/%d подключения не удалась: %v", attempt, maxAttempts, err))
			time.Sleep(time.Second * time.Duration(attempt))
			continue
		}

		if err := forceConnection(conn, timeout, handler); err != nil {
			conn.Close()
			if attempt == maxAttempts {
				return "", "", fmt.Errorf("тест соединения не прошел после %d попыток: %v", maxAttempts, err)
			}
			handler.OnLog(LogLevelWarning, fmt.Sprintf("Тест соединения %d/%d не удался: %v", attempt, maxAttempts, err))
			time.Sleep(time.Second * time.Duration(attempt))
			continue
		}

		authClient := proto2.NewAuthClient(conn)
		ctx, cancel := context.WithTimeout(context.Background(), timeout)

		publicSalt := []byte("your-fixed-salt-that-will-be-the-same-every-time")
		myLocalHash := hmac.New(sha256.New, publicSalt)
		myLocalHash.Write([]byte(myUsername))
		destLocalHash := hmac.New(sha256.New, publicSalt)
		destLocalHash.Write([]byte(destUsername))

		myFinalHashResp, err := authClient.GetFinalHash(ctx, &proto2.FinalHashRequest{LocalHash: myLocalHash.Sum(nil)})
		if err != nil {
			cancel()
			conn.Close()
			if attempt == maxAttempts {
				return "", "", fmt.Errorf("ошибка получения финального хэша для %s после %d попыток: %w", myUsername, maxAttempts, err)
			}
			handler.OnLog(LogLevelWarning, fmt.Sprintf("Ошибка получения хэша для %s, попытка %d/%d: %v", myUsername, attempt, maxAttempts, err))
			time.Sleep(time.Second * time.Duration(attempt))
			continue
		}

		destFinalHashResp, err := authClient.GetFinalHash(ctx, &proto2.FinalHashRequest{LocalHash: destLocalHash.Sum(nil)})
		if err != nil {
			cancel()
			conn.Close()
			if attempt == maxAttempts {
				return "", "", fmt.Errorf("ошибка получения финального хэша для %s после %d попыток: %w", destUsername, maxAttempts, err)
			}
			handler.OnLog(LogLevelWarning, fmt.Sprintf("Ошибка получения хэша для %s, попытка %d/%d: %v", destUsername, attempt, maxAttempts, err))
			time.Sleep(time.Second * time.Duration(attempt))
			continue
		}

		cancel()
		conn.Close()
		return myFinalHashResp.FinalHash, destFinalHashResp.FinalHash, nil
	}

	return "", "", fmt.Errorf("все попытки подключения исчерпаны")
}
