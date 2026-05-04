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
	"crypto/rand"
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

	"google.golang.org/grpc/codes"
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
	pendingInboundPkts []*proto2.Packet
	isEstablished      bool
	// keyRequestInFlight bool // Removed
}

type logicClient struct {
	ks           *KeyStore
	ms           *MessageStore
	stream       proto2.Phantom_TransmitClient
	mu           sync.RWMutex
	peerSessions map[string]*peerSession // Key: IdentityKeyHash
	handler      CoreEventHandler
	contactsMu   sync.RWMutex
	packetQueue  chan *proto2.Packet
	wg           sync.WaitGroup
	p2pTransport *P2PTransport
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

func newLogicClient(ks *KeyStore, ms *MessageStore, handler CoreEventHandler) (*logicClient, error) {
	client := &logicClient{
		ks:           ks,
		ms:           ms,
		peerSessions: make(map[string]*peerSession),
		handler:      handler,
		packetQueue:  make(chan *proto2.Packet, 100),
	}
	return client, nil
}

// Реализация интерфейса P2PMessageHandler

func (c *logicClient) GetUsernameHash() string {
	// Возвращаем пустую строку или ID, если нужно.
	// Для P2P нам нужен PeerID или IdentityKeyHash.
	// Пока оставим пустым или реализуем позже.
	return ""
}

// GetContactHashes возвращает список хэшей всех контактов для P2P анонсирования
func (c *logicClient) GetContactHashes() []string {
	// TODO: Реализовать возврат IdentityKeyHashes
	return []string{}
}

func (c *logicClient) HandleP2PMessage(packet *proto2.Packet) error {
	c.handler.OnLog(LogLevelInfo, fmt.Sprintf("📩 Получено P2P сообщение (RoutingToken: %x)...", packet.RoutingToken))

	switch pld := packet.Payload.(type) {
	case *proto2.Packet_EncryptedMessage:
		c.handleEncryptedMessage(packet)
	case *proto2.Packet_P2PUpdate:
		c.handler.OnLog(LogLevelInfo, "🔄 Получен P2P Update (Not implemented)")
	default:
		c.handler.OnLog(LogLevelWarning, fmt.Sprintf("⚠️ Получен неизвестный тип P2P пакета: %T", pld))
	}
	return nil
}

// handleP2PKeyRequest removed (legacy)

// sendMessageViaP2P отправляет сообщение через P2P транспорт
func (c *logicClient) sendMessageViaP2P(peerHash, text string, p2pTransport *P2PTransport) error {
	c.p2pTransport = p2pTransport
	contact, err := c.ks.LoadContact(peerHash)
	if err != nil {
		return fmt.Errorf("не могу найти контакт для отправки сообщения: %w", err)
	}

	if len(contact.RatchetState) == 0 {
		// Сессия не установлена. Пытаемся инициализировать из Invite (Contact keys).
		c.handler.OnLog(LogLevelInfo, "✅ [HANDSHAKE] Шаг 1: Сессия не установлена. Инициализация Alice из Invite...")

		var ratchet *DoubleRatchet
		var initialCts *InitialCiphertexts

		err = c.ks.WithUserAccount(func(ua *UserAccount) error {
			var e error
			ratchet, initialCts, e = c.initAliceFromInvite(ua, contact)
			return e
		})

		if err != nil {
			c.handler.OnLog(LogLevelError, fmt.Sprintf("Не удалось инициализировать сессию: %v. Сообщение поставлено в очередь.", err))
			contact.PendingUserMsgs = append(contact.PendingUserMsgs, text)
			if err := c.ms.SaveMessage(peerHash, true, time.Now().Unix(), text); err != nil {
				c.handler.OnLog(LogLevelError, fmt.Sprintf("Ошибка сохранения сообщения в очередь в БД: %v", err))
			}
			return c.ks.SaveContact(contact)
		}
		defer ratchet.Zeroize()

		return c.sendEncryptedPacket(peerHash, text, ratchet, initialCts)
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
		// RoutingToken: ...
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
	c.handler.OnLog(LogLevelInfo, fmt.Sprintf("✅ Сообщение успешно отправлено через P2P пиру %s", peerHash))
	return nil
}

// startProcessing начинает обработку пакетов после установки соединения.
func (c *logicClient) startProcessing(stream proto2.Phantom_TransmitClient, tlsConfig *tls.Config, readyChan chan<- error) {
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
		case *proto2.Packet_EncryptedMessage:
			c.handleEncryptedMessage(packet)
		case *proto2.Packet_SystemNotification:
			if c.handleSystemNotification(pld.SystemNotification) {
				c.handler.OnShutdown("Критическая ошибка регистрации, завершение работы.")
			}
		}
	}
}

// initialContactSync удален, так как нет глобального реестра

// handleKeyResponse removed (legacy)

// establishSessionAsAlice removed (legacy)

func (c *logicClient) sendEncryptedPacket(peerHash, text string, ratchet *DoubleRatchet, initialCts *InitialCiphertexts) error {
	finalHeaderData, ciphertext, err := ratchet.RatchetEncrypt([]byte(text), initialCts)
	if err != nil {
		return fmt.Errorf("ошибка шифрования: %w", err)
	}

	if err := c.persistRatchetState(peerHash, ratchet); err != nil {
		return err
	}

	contact, err := c.ks.LoadContact(peerHash)
	if err != nil {
		return fmt.Errorf("contact not found: %w", err)
	}

	packet := &proto2.Packet{
		RoutingToken: contact.OutboundRoutingToken, // Используем токен из контакта!
		Payload: &proto2.Packet_EncryptedMessage{EncryptedMessage: &proto2.EncryptedMessage{
			RatchetHeader: finalHeaderData,
			Ciphertext:    ciphertext,
			Timestamp:     time.Now().Unix(),
		}},
	}

	// Подписываем только пакет инициации сессии для подтверждения авторства ключей.
	// Обычные сообщения не подписываются для обеспечения отказуемости (deniability).
	if initialCts != nil {
		err = c.ks.WithUserAccount(func(ua *UserAccount) error {
			idKeyBytes, err := ua.IdentityPublicDili.MarshalBinary()
			if err != nil {
				return err
			}
			packet.SenderIdentityKey = idKeyBytes
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
	// peerHash больше нет в пакете.
	// Мы должны определить peerHash (IdentityKeyHash) по RoutingToken, на который пришел пакет.
	// Но Packet.RoutingToken - это то, КУДА отправлено.
	// Если мы получили пакет, значит он пришел на один из наших ListenTokens.
	// Нам нужно знать, КАКОЙ это был токен.
	// Проблема: gRPC stream.Recv() возвращает Packet, и там поле RoutingToken заполнено отправителем.
	// Сервер не меняет его.
	// Значит, мы можем прочитать packet.RoutingToken и найти контакт.

	routingToken := packet.RoutingToken

	// Ищем контакт по InboundRoutingToken
	var peerHash string
	var contact *Contact

	contacts, err := c.ks.ListContacts()
	if err == nil {
		for _, ct := range contacts {
			if bytes.Equal(ct.InboundRoutingToken, routingToken) {
				contact = ct
				// peerHash = ct.IdentityKeyHash? У нас нет поля Hash в Contact struct, но есть IdentityPublicDili
				// Мы можем вычислить хэш.
				idBytes, _ := ct.IdentityPublicDili.MarshalBinary()
				peerHash = fmt.Sprintf("%x", idBytes)
				break
			}
		}
	}

	// Если не нашли по токену, возможно это "Main Invite Token" (если мы его реализовали в UserAccount)
	if contact == nil {
		var myRoutingToken []byte
		c.ks.WithUserAccount(func(ua *UserAccount) error {
			myRoutingToken = ua.RoutingToken
			return nil
		})

		if bytes.Equal(routingToken, myRoutingToken) {
			// Это сообщение на наш основной токен (Handshake)
			// Мы еще не знаем кто это.
			// Мы должны попытаться расшифровать или извлечь SenderIdentityKey.
			// Если это Handshake, там должен быть SenderIdentityKey.
			if len(packet.SenderIdentityKey) > 0 {
				// Это новый контакт!
				// Создаем временную структуру или обрабатываем как "Неизвестный"
				// Но для decryptAndHandle нам нужен peerHash.
				peerHash = fmt.Sprintf("%x", packet.SenderIdentityKey)
				// Проверяем, может он уже есть (просто токен сменился или мы потеряли связь)
				// Если нет, создаем.
				// Но мы должны быть осторожны с DoS.

				// Проверим подпись пакета СЕЙЧАС.
				diliScheme := mode5.Scheme()
				pubKey, err := diliScheme.UnmarshalBinaryPublicKey(packet.SenderIdentityKey)
				if err == nil {
					// Формируем msg для проверки
					// signPacket подписывает (RoutingToken + Payload)
					var payloadBytes []byte
					if pkt, ok := packet.Payload.(*proto2.Packet_EncryptedMessage); ok {
						payloadBytes, _ = proto.Marshal(pkt.EncryptedMessage)
					}
					msg := append(packet.RoutingToken, payloadBytes...)

					if diliScheme.Verify(pubKey, msg, packet.Signature, nil) {
						// Подпись верна!
						// Создаем контакт.
						newContact := &Contact{
							DisplayName:        "Unknown", // Или извлечь из payload если там есть? Нет.
							IdentityPublicDili: pubKey,
							// IdentityPublicX25519 пока нет, он внутри шифрованного сообщения (в RatchetHeader)
							// OutboundRoutingToken пока нет! Мы не можем ответить, пока не расшифруем сообщение и не найдем там "Reply-To" токен.
							// Но для расшифровки нам нужен только IdentityKey (для проверки подписи внутри Ratchet? Нет, Ratchet симметричный + DH).
							// Для первого сообщения (Alice -> Bob), Bob (мы) использует свои ключи (PreKeys).
							// Alice использовала наши PreKeys.
							// Нам нужно инициализировать сессию как Bob.
						}
						// Сохраняем
						// Но нам нужен OutboundRoutingToken для ответа.
						// Предположим, что он придет внутри сообщения?
						// Или мы пока не можем ответить.

						// Сохраняем контакт.
						// c.usernameToHash // Removed
						if err := c.ks.SaveContact(newContact); err == nil {
							peerHash = fmt.Sprintf("%x", packet.SenderIdentityKey)
							contact = newContact
						}
					}
				}
			}
		}
	}

	if contact == nil {
		var myRoutingToken []byte
		c.ks.WithUserAccount(func(ua *UserAccount) error {
			myRoutingToken = ua.RoutingToken
			return nil
		})

		if bytes.Equal(routingToken, myRoutingToken) {
			// ... (existing logic)
		} else {
			c.handler.OnLog(LogLevelWarning, fmt.Sprintf("Получен пакет на неизвестный токен: %x. Мой токен: %x", routingToken, myRoutingToken))
			// Debug: list contacts
			contacts, _ := c.ks.ListContacts()
			for _, ct := range contacts {
				c.handler.OnLog(LogLevelWarning, fmt.Sprintf("Контакт %s: Inbound=%x", ct.DisplayName, ct.InboundRoutingToken))
			}
			return
		}
	}

	session := c.getOrCreateSession(peerHash)

	session.initMutex.Lock()

	contact, _ = c.ks.LoadContact(peerHash)
	session.initMutex.Unlock()
	c.decryptAndHandle(packet)
}

func (c *logicClient) processInboundPackets(packetsToProcess []*proto2.Packet) {
	if len(packetsToProcess) == 0 {
		return
	}
	// peerHash := packetsToProcess[0].SourceClientIdHash // Removed

	// The session establishment as Bob is now handled within decryptAndHandle
	// when RatchetState is empty.
	// This function might need to be re-evaluated or removed if its sole purpose
	// was to manage the old KeyRequest/KeyResponse flow.
	// For now, we'll just iterate and decrypt.
	for _, packet := range packetsToProcess {
		c.decryptAndHandle(packet)
	}
}

// tryEstablishSessionAsBob больше не нужен в таком виде, так как мы обрабатываем это в handleEncryptedMessage
// Но оставим пока как заглушку или вспомогательный метод

func (c *logicClient) decryptAndHandle(packet *proto2.Packet) {
	// peerHash нужно передавать или извлекать.
	// Но сигнатура метода принимает только packet.
	// Мы уже определили peerHash в handleEncryptedMessage, но здесь мы его теряем.
	// Надо изменить сигнатуру decryptAndHandle или извлекать снова.
	// Извлечем снова (неэффективно, но проще для рефакторинга).

	routingToken := packet.RoutingToken
	var peerHash string

	contacts, _ := c.ks.ListContacts()
	for _, ct := range contacts {
		if bytes.Equal(ct.InboundRoutingToken, routingToken) {
			idBytes, _ := ct.IdentityPublicDili.MarshalBinary()
			peerHash = fmt.Sprintf("%x", idBytes)
			break
		}
	}

	// Если не нашли, проверяем Main Token и SenderIdentityKey
	if peerHash == "" && len(packet.SenderIdentityKey) > 0 {
		peerHash = fmt.Sprintf("%x", packet.SenderIdentityKey)
	}

	if peerHash == "" {
		return
	}

	contact, err := c.ks.LoadContact(peerHash)

	// **КЛЮЧЕВОЕ ИСПРАВЛЕНИЕ**
	if err != nil || len(contact.RatchetState) == 0 {
		c.handler.OnLog(LogLevelInfo, fmt.Sprintf("Получен шифрованный пакет от %s, но сессии нет. Попытка установить как Боб...", truncateHash(peerHash)))

		if c.tryEstablishSessionAsBob(peerHash, packet) {
			c.handler.OnLog(LogLevelInfo, "✅ Сессия успешно установлена как Боб. Повторная обработка пакета...")
			c.handleEncryptedMessage(packet) // Рекурсивный вызов для расшифровки тем же пакетом
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
	if contact == nil {
		c.handler.OnLog(LogLevelWarning, fmt.Sprintf("Получено сообщение от неизвестного контакта (Hash: %s). Игнорирование.", peerHash))
		return
	}
	c.handler.OnLog(LogLevelInfo, fmt.Sprintf("✅ Сообщение от %s успешно расшифровано.", peerHash))

	if err := c.persistRatchetState(peerHash, &ratchet); err != nil {
		c.handler.OnLog(LogLevelCritical, fmt.Sprintf("Не удалось сохранить состояние сессии после расшифровки: %v", err))
	}

	plaintext := string(plaintextBytes)
	timestamp := packet.GetEncryptedMessage().Timestamp

	if strings.HasPrefix(plaintext, InitiateChatMessage) {
		parts := strings.SplitN(plaintext, ":", 2)
		if len(parts) == 2 {
			revealedUsername := parts[1]
			c.handler.OnLog(LogLevelInfo, fmt.Sprintf("Собеседник %s (%s...) инициировал чат.", revealedUsername, peerHash))

			go beeep.Notify("Новый чат", fmt.Sprintf("Пользователь '%s' хочет начать с вами диалог.", revealedUsername), "")

			if contact.DisplayName == "" || strings.HasPrefix(contact.DisplayName, "Unknown") {
				// contact.Username = username // Removed
				contact.DisplayName = revealedUsername
				if err := c.ks.SaveContact(contact); err != nil {
					c.handler.OnLog(LogLevelError, fmt.Sprintf("Не удалось сохранить имя собеседника: %v", err))
				} else {
					c.contactsMu.Lock()
					// c.usernameToHash[revealedUsername] = peerHash // Removed
					// c.hashToUsername[peerHash] = revealedUsername // Removed
					c.contactsMu.Unlock()

					c.handler.OnLog(LogLevelInfo, "Обнаружен новый контакт. Немедленное обновление списка контактов в UI...")

					c.contactsMu.RLock()
					var allContacts []ContactInfo
					for _, ct := range contacts {
						allContacts = append(allContacts, ContactInfo{Name: ct.DisplayName, Hash: ct.IdentityKeyHash, IsOnline: true})
					}
					c.contactsMu.RUnlock()

					c.handler.OnContactListUpdated(allContacts)
				}
			}
		}
		return
	}

	var senderName string
	if contact != nil && contact.DisplayName != "" {
		senderName = contact.DisplayName
	} else {
		if senderName == "" {
			senderName = peerHash
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

	c.handler.OnLog(LogLevelInfo, fmt.Sprintf("✅ [HANDSHAKE] Шаг 5: Сессия установлена. Отправка %d отложенных сообщений для %s...", len(messagesToSend), contact.DisplayName))

	for _, text := range messagesToSend {
		userHash := contact.IdentityKeyHash
		if err := c.sendMessageViaP2P(userHash, text, c.p2pTransport); err != nil {
			c.handler.OnLog(LogLevelError, fmt.Sprintf("Ошибка отправки сообщения '%s': %v.", text, err))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (c *logicClient) ProcessInvite(invite *proto2.Invite) error {
	// Импорт инвайта
	// 1. Проверяем подпись пре-ключа (Dilithium)
	// 2. Сохраняем контакт

	diliScheme := mode5.Scheme()
	pk, err := diliScheme.UnmarshalBinaryPublicKey(invite.IdentityKeyDilithium)
	if err != nil {
		return fmt.Errorf("invalid identity key (Dilithium): %w", err)
	}

	kemScheme := kyber1024.Scheme()
	pkKyber, err := kemScheme.UnmarshalBinaryPublicKey(invite.IdentityKeyKyber)
	if err != nil {
		return fmt.Errorf("invalid identity key (Kyber): %w", err)
	}

	// Verify signature over IdentityKeys + SignedPreKeys
	// Use a fresh slice to avoid modifying the underlying arrays of the invite fields
	dataToVerify := make([]byte, 0, len(invite.IdentityKeyKyber)+len(invite.IdentityKeyX25519)+len(invite.SignedPrekeyKyber)+len(invite.SignedPrekeyX25519))
	dataToVerify = append(dataToVerify, invite.IdentityKeyKyber...)
	dataToVerify = append(dataToVerify, invite.IdentityKeyX25519...)
	dataToVerify = append(dataToVerify, invite.SignedPrekeyKyber...)
	dataToVerify = append(dataToVerify, invite.SignedPrekeyX25519...)

	if !diliScheme.Verify(pk, dataToVerify, invite.PrekeySignatureDilithium, nil) {
		return errors.New("invalid prekey signature in invite")
	}

	// DEBUG: Проверяем что ключи разные в invite
	fmt.Printf("[ProcessInvite DEBUG] IdentityKeyKyber (first 16): %x\n", invite.IdentityKeyKyber[:16])
	fmt.Printf("[ProcessInvite DEBUG] SignedPrekeyKyber (first 16): %x\n", invite.SignedPrekeyKyber[:16])
	fmt.Printf("[ProcessInvite DEBUG] Keys are same: %v\n", bytes.Equal(invite.IdentityKeyKyber, invite.SignedPrekeyKyber))

	// idKeyHash // Removed

	contact := &Contact{
		DisplayName:          invite.DisplayName,
		IdentityPublicDili:   pk,
		IdentityPublicKyber:  pkKyber.(*kyber1024.PublicKey),
		OutboundRoutingToken: invite.RoutingToken,
		SignedPreKeyKyber:    invite.SignedPrekeyKyber,
		SignedPreKeyX25519:   invite.SignedPrekeyX25519,
		PreKeySignatureDili:  invite.PrekeySignatureDilithium,
	}
	if len(invite.IdentityKeyX25519) == 32 {
		var k [32]byte
		copy(k[:], invite.IdentityKeyX25519)
		contact.IdentityPublicX25519 = &k
	}

	// Генерируем InboundRoutingToken для этого контакта
	inToken := make([]byte, 32)
	rand.Read(inToken)
	contact.InboundRoutingToken = inToken

	// c.usernameToHash // Removed

	if err := c.ks.SaveContact(contact); err != nil {
		return err
	}

	// Нужно зарегистрировать новый токен на сервере!
	// Это требует отправки RegistrationRequest с новым токеном.
	// Пока просто перерегистрируемся (неэффективно, но работает)
	go c.register()

	return nil
}

func (c *logicClient) sendMessage(peerHash, text string) error {
	contact, err := c.ks.LoadContact(peerHash)
	if err != nil {
		return fmt.Errorf("contact not found: %w", err)
	}

	if len(contact.OutboundRoutingToken) == 0 {
		return fmt.Errorf("no outbound routing token for contact")
	}

	// Если сессии нет, мы должны начать handshake.
	// В новой схеме Invite уже содержит ключи.
	// Мы можем сразу шифровать!
	// Но нам нужно создать сессию Double Ratchet.

	if len(contact.RatchetState) == 0 {
		// Инициализация сессии как Alice (мы отправляем первое сообщение)
		session := c.getOrCreateSession(peerHash)
		session.initMutex.Lock()
		defer session.initMutex.Unlock()

		// Загружаем ключи из контакта (они пришли из Invite)
		// Нам нужен PreKeyBundle.
		// В Invite у нас есть: SignedPreKeyKyber, SignedPreKeyX25519.
		// OneTimePreKey нет (в QR коде обычно один набор).
		// Мы используем SignedPreKey как "последний шанс" или единственный ключ.

		// Создаем Ratchet
		var ratchet *DoubleRatchet
		var initialCts *InitialCiphertexts

		err = c.ks.WithUserAccount(func(ua *UserAccount) error {
			var e error
			ratchet, initialCts, e = c.initAliceFromInvite(ua, contact)
			return e
		})
		if err != nil {
			return err
		}
		defer ratchet.Zeroize()

		// Шифруем и отправляем
		return c.sendEncryptedPacket(peerHash, text, ratchet, initialCts)
	}

	// Сессия есть, просто шифруем
	var ratchet DoubleRatchet
	if err := json.Unmarshal(contact.RatchetState, &ratchet); err != nil {
		return err
	}
	defer ratchet.Zeroize()

	return c.sendEncryptedPacket(peerHash, text, &ratchet, nil)
}

func (c *logicClient) initAliceFromInvite(ua *UserAccount, contact *Contact) (*DoubleRatchet, *InitialCiphertexts, error) {
	kemScheme := kyber1024.Scheme()

	if contact.IdentityPublicDili == nil {
		return nil, nil, errors.New("contact has no identity key")
	}
	theirIKeyDili := contact.IdentityPublicDili

	if contact.IdentityPublicX25519 == nil {
		return nil, nil, errors.New("contact has no X25519 identity key")
	}
	theirIKeyX25519 := contact.IdentityPublicX25519

	// Используем SignedPreKeys из контакта
	if len(contact.SignedPreKeyKyber) == 0 || len(contact.SignedPreKeyX25519) == 0 {
		return nil, nil, errors.New("contact has no SignedPreKeys")
	}

	theirSPKeyKyber, err := kemScheme.UnmarshalBinaryPublicKey(contact.SignedPreKeyKyber)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid Kyber SignedPreKey: %w", err)
	}

	if len(contact.SignedPreKeyX25519) != 32 {
		return nil, nil, errors.New("invalid X25519 SignedPreKey length")
	}
	theirSPKeyX25519 := (*[32]byte)(contact.SignedPreKeyX25519)

	// Проверяем подпись
	dataToVerify := append(contact.SignedPreKeyKyber, contact.SignedPreKeyX25519...)
	if !mode5.Verify(theirIKeyDili.(*mode5.PublicKey), dataToVerify, contact.PreKeySignatureDili) {
		return nil, nil, errors.New("invalid PreKey signature")
	}

	// One-Time PreKeys отсутствуют в Invite. Передаем nil.
	// Это означает, что мы используем только SignedPreKey.
	// Это менее безопасно (нет PFS для первого сообщения, если SignedPreKey скомпрометирован),
	// но допустимо для упрощенной схемы Invite.

	var opkKyber *kyber1024.PublicKey = nil
	var opkX25519 *[32]byte = nil

	ratchet, initialCts, err := RatchetInitAlice(contact.IdentityPublicKyber, theirIKeyX25519, theirSPKeyKyber.(*kyber1024.PublicKey), theirSPKeyX25519, opkKyber, opkX25519, 0)
	if err != nil {
		return nil, nil, err
	}

	return ratchet, initialCts, nil
}

func (c *logicClient) initBob(session *peerSession, ua *UserAccount, header RatchetHeader, initialCts *InitialCiphertexts) (*DoubleRatchet, error) {
	kemScheme := kyber1024.Scheme()

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
	}

	// Если OPK не найден, но он был использован (OPKID != 0), RatchetInitBob может вернуть ошибку или мы должны обработать это.
	// Но RatchetInitBob принимает указатели, так что если они nil, он будет использовать только SignedPreKey (если протокол позволяет).
	// В нашей реализации RatchetInitBob требует OPK если он был использован?
	// Проверим реализацию RatchetInitBob позже, но пока передаем то что есть.

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

	c.handler.OnLog(LogLevelInfo, fmt.Sprintf("Создана новая пустая сессия для %s...", peerHash))
	session = &peerSession{}
	c.peerSessions[peerHash] = session

	return session
}

func (c *logicClient) register() error {
	c.handler.OnLog(LogLevelInfo, "📝 Регистрация на сервере...")

	var listenTokens [][]byte
	contacts, err := c.ks.ListContacts()
	if err != nil {
		return fmt.Errorf("ошибка получения контактов: %w", err)
	}

	for _, contact := range contacts {
		if len(contact.InboundRoutingToken) > 0 {
			listenTokens = append(listenTokens, contact.InboundRoutingToken)
		}
	}

	err = c.ks.WithUserAccount(func(ua *UserAccount) error {
		if len(ua.RoutingToken) > 0 {
			listenTokens = append(listenTokens, ua.RoutingToken)
		}
		return nil
	})
	if err != nil {
		return err
	}

	req := &proto2.RegistrationRequest{
		ListenTokens: listenTokens,
		P2PInfo:      c.getP2PInfo(),
	}

	err = c.ks.WithUserAccount(func(ua *UserAccount) error {
		idKeyBytes, err := ua.IdentityPublicDili.MarshalBinary()
		if err != nil {
			return err
		}
		packet := &proto2.Packet{
			SenderIdentityKey: idKeyBytes,
			Payload:           &proto2.Packet_RegistrationRequest{RegistrationRequest: req},
		}
		if err := c.signPacket(packet, ua.IdentityPrivateDili); err != nil {
			return err
		}

		if c.stream == nil {
			return fmt.Errorf("stream is nil")
		}
		return c.stream.Send(packet)
	})
	return err
}

// requestKeys removed (legacy)

func (c *logicClient) persistRatchetState(userHash string, ratchet *DoubleRatchet) error {
	contact, err := c.ks.LoadContact(userHash)
	if err != nil || contact == nil {
		c.handler.OnLog(LogLevelInfo, fmt.Sprintf("Контакт %s не найден, создание нового...", userHash))

		// The original instruction provided `packet.SenderIdentityKey` here,
		// but `packet` is not available in `persistRatchetState`.
		// Assuming the intent was to create a contact if not found,
		// but without the SenderIdentityKey from a packet, we can't populate it fully.
		// For now, we'll create a basic contact.
		// If SenderIdentityKey is truly needed here, the function signature or call site needs adjustment.
		contact = &Contact{
			IdentityKeyHash: userHash,
			DisplayName:     "Unknown Sender", // Default name
		}
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
	case proto2.SystemNotification_DELIVERY_FAILURE:
		c.handler.OnLog(LogLevelError, fmt.Sprintf("❌ Ошибка доставки: %s", notif.Message))
		// TODO: Mark message as failed in DB?
	case proto2.SystemNotification_P2P_AVAILABLE:
		c.handler.OnLog(LogLevelInfo, "🔒 P2P доступен для контакта.")
		// Можно инициировать P2P соединение, если нужно
	case proto2.SystemNotification_P2P_PEER_INFO:
		if notif.P2PInfo != nil {
			c.updateP2PPeerInfo(notif.P2PInfo)
		}
	default:
		c.handler.OnLog(LogLevelWarning, fmt.Sprintf("⚠️ Получено системное уведомление неизвестного типа: %v", notif.Type))
	}
	return true
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

// getP2PInfo возвращает P2PInfo для регистрации
func (c *logicClient) getP2PInfo() *proto2.P2PInfo {
	if c.p2pTransport == nil {
		return nil
	}

	peerID := c.getP2PPeerID()
	addresses := c.getP2PAddresses()

	if peerID == "" || len(addresses) == 0 {
		return nil
	}

	return &proto2.P2PInfo{
		PeerId:       peerID,
		Addresses:    addresses,
		PreferP2P:    true,
		RelayWilling: false, // По умолчанию не relay
	}
}

// sendP2PUpdate отправляет обновление P2P информации на сервер
func (c *logicClient) sendP2PUpdate() error {
	if c.stream == nil || c.p2pTransport == nil {
		return nil
	}

	p2pInfo := c.getP2PInfo()
	if p2pInfo == nil {
		return nil
	}

	update := &proto2.P2PUpdate{
		Addresses:    p2pInfo.Addresses,
		RelayWilling: p2pInfo.RelayWilling,
	}

	packet := &proto2.Packet{
		Payload: &proto2.Packet_P2PUpdate{P2PUpdate: update},
	}

	err := c.ks.WithUserAccount(func(ua *UserAccount) error {
		return c.signPacket(packet, ua.IdentityPrivateDili)
	})
	if err != nil {
		return err
	}

	return c.stream.Send(packet)
}

func (c *logicClient) replenishOPKsAndReregister() {
	err := c.ks.WithUserAccount(func(ua *UserAccount) error {
		c.handler.OnLog(LogLevelInfo, "Пополнение OPK...")
		newAccount, err := c.ks.ReplenishOPKs(ua)
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
	err := c.ks.WithUserAccount(func(ua *UserAccount) error {
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

// getHashesFromServerSecurely removed (legacy)

func (c *logicClient) CreateInvite(displayName string) (string, error) {
	var invite *proto2.Invite
	err := c.ks.WithUserAccount(func(ua *UserAccount) error {
		if ua.PreKeyPublicKyber == nil || ua.PreKeyPublicX25519 == nil {
			return errors.New("prekeys not initialized")
		}

		// Pack Kyber keys
		var kyberIDBytes [kyber1024.PublicKeySize]byte
		ua.IdentityPublicKyber.Pack(kyberIDBytes[:])

		var kyberPreKeyBytes [kyber1024.PublicKeySize]byte
		ua.PreKeyPublicKyber.Pack(kyberPreKeyBytes[:])

		// Pack Dilithium Key
		var diliIDBytes [mode5.PublicKeySize]byte
		// ua.IdentityPublicDili is sign.PublicKey interface, assert to *mode5.PublicKey
		diliPub, ok := ua.IdentityPublicDili.(*mode5.PublicKey)
		if !ok {
			return errors.New("invalid dilithium public key type")
		}
		diliPub.Pack(&diliIDBytes)

		// Sign PreKeys (Kyber || X25519)
		dataToSign := append(kyberPreKeyBytes[:], ua.PreKeyPublicX25519[:]...)
		signature := mode5.Scheme().Sign(ua.IdentityPrivateDili, dataToSign, nil)

		invite = &proto2.Invite{
			IdentityKeyDilithium:     diliIDBytes[:],
			IdentityKeyKyber:         kyberIDBytes[:],
			IdentityKeyX25519:        ua.IdentityPublicX25519[:],
			SignedPrekeyKyber:        kyberPreKeyBytes[:],
			SignedPrekeyX25519:       ua.PreKeyPublicX25519[:],
			PrekeySignatureDilithium: signature,
			RoutingToken:             ua.RoutingToken,
			DisplayName:              displayName,
		}
		return nil
	})
	if err != nil {
		return "", err
	}

	data, err := proto.Marshal(invite)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(data), nil
}

// tryEstablishSessionAsBob пытается установить сессию как Боб (получатель первого сообщения)
// tryEstablishSessionAsBob пытается установить сессию как Боб (получатель первого сообщения)
func (c *logicClient) tryEstablishSessionAsBob(peerHash string, packet *proto2.Packet) bool {
	// Проверяем наличие контакта и создаем его, если нет
	contact, err := c.ks.LoadContact(peerHash)
	if err != nil || contact == nil {
		c.handler.OnLog(LogLevelInfo, fmt.Sprintf("Контакт %s не найден, создание нового...", peerHash))

		if len(packet.SenderIdentityKey) == 0 {
			c.handler.OnLog(LogLevelError, "SenderIdentityKey отсутствует в пакете, невозможно создать контакт.")
			return false
		}

		pubKey, err := mode5.Scheme().UnmarshalBinaryPublicKey(packet.SenderIdentityKey)
		if err != nil {
			c.handler.OnLog(LogLevelError, fmt.Sprintf("Ошибка декодирования SenderIdentityKey: %v", err))
			return false
		}

		contact = &Contact{
			IdentityKeyHash:    peerHash,
			IdentityPublicDili: pubKey,
			DisplayName:        "Unknown Sender",
		}

		// Сохраняем контакт СРАЗУ, чтобы у него были ключи
		if err := c.ks.SaveContact(contact); err != nil {
			c.handler.OnLog(LogLevelError, fmt.Sprintf("Ошибка сохранения нового контакта: %v", err))
			return false
		}
	}

	session := c.getOrCreateSession(peerHash)

	msg := packet.GetEncryptedMessage()
	if msg == nil {
		c.handler.OnLog(LogLevelError, "tryEstablishSessionAsBob: msg is nil")
		return false
	}

	var headerWithInitialCts struct {
		RatchetHeader
		InitialCiphertexts *InitialCiphertexts `json:"initial_cts,omitempty"`
	}
	if err := json.Unmarshal(msg.RatchetHeader, &headerWithInitialCts); err != nil {
		c.handler.OnLog(LogLevelError, fmt.Sprintf("tryEstablishSessionAsBob: json unmarshal error: %v", err))
		return false
	}
	if headerWithInitialCts.InitialCiphertexts == nil {
		c.handler.OnLog(LogLevelWarning, "tryEstablishSessionAsBob: InitialCiphertexts is nil")
		return false
	}

	var ratchet *DoubleRatchet
	err = c.ks.WithUserAccount(func(ua *UserAccount) error {
		if ua == nil {
			return fmt.Errorf("UserAccount is nil")
		}
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
