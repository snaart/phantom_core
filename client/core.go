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
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	pb "phantom/proto"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
	"google.golang.org/grpc"
)

// LogLevel определяет уровень логирования для колбэка OnLog.
type LogLevel int

const (
	LogLevelInfo LogLevel = iota
	LogLevelWarning
	LogLevelError
	LogLevelCritical
)

// TransportProtocol определяет транспортный протокол для подключения к серверу.
type TransportProtocol int

const (
	Auto TransportProtocol = iota
	TCP
	QUIC
	P2P
	Hybrid
)

// String возвращает строковое представление транспортного протокола
func (tp TransportProtocol) String() string {
	switch tp {
	case Auto:
		return "Auto"
	case TCP:
		return "TCP"
	case QUIC:
		return "QUIC"
	case P2P:
		return "P2P"
	case Hybrid:
		return "Hybrid"
	default:
		return "Unknown"
	}
}

// ContactInfo содержит публичную информацию о контакте для отображения в UI.
type ContactInfo struct {
	Name         string
	Hash         string
	IsOnline     bool
	SessionState string
	IsP2P        bool
	P2PLocation  string
}

// CoreEventHandler — это интерфейс для асинхронных событий от ядра.
type CoreEventHandler interface {
	OnMessageReceived(message StoredMessage)
	OnContactListUpdated(contacts []ContactInfo)
	OnSessionEstablished(peerHash string)
	OnLog(level LogLevel, message string)
	OnConnectionStateChanged(state string, err error)
	OnShutdown(message string)
	OnP2PStateChanged(isActive bool, peers []string)
}

// Core — это главная структура, инкапсулирующая всю логику Phantom.
type Core struct {
	mu              sync.Mutex
	logicClient     *logicClient
	grpcConn        *grpc.ClientConn
	transportCloser io.Closer
	ks              *KeyStore
	ms              *MessageStore
	username        string
	handler         CoreEventHandler
	isStarted       bool
	lastTransport   TransportProtocol
	tlsConfig       *tls.Config
	p2pTransport    *P2PTransport
	useP2P          bool
}

// NewCore создает и инициализирует новый экземпляр ядра.
func NewCore(username, pin, basePath string, handler CoreEventHandler) (*Core, error) {
	if handler == nil {
		return nil, fmt.Errorf("обработчик событий (handler) не может быть nil")
	}

	ks, err := NewKeyStore(filepath.Join(basePath, "keystore.db"))
	if err != nil {
		return nil, fmt.Errorf("ошибка создания KeyStore: %w", err)
	}
	ms, err := NewMessageStore(filepath.Join(basePath, "messagestore.db"))
	if err != nil {
		err := ks.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("ошибка создания MessageStore: %w", err)
	}

	if !fileExists(ks.path) {
		if err := ks.Initialize(pin); err != nil {
			return nil, fmt.Errorf("ошибка инициализации KeyStore: %w", err)
		}
		if err := ms.Initialize(pin); err != nil {
			return nil, fmt.Errorf("ошибка инициализации MessageStore: %w", err)
		}
		handler.OnLog(LogLevelInfo, "✅ Новые защищенные хранилища созданы.")

		if err := ks.CreateAccount(username); err != nil {
			return nil, fmt.Errorf("не удалось создать аккаунт: %w", err)
		}
		handler.OnLog(LogLevelInfo, "✅ Новый защищенный аккаунт создан.")

	} else {
		if err := ks.Unlock(pin); err != nil {
			return nil, fmt.Errorf("не удалось разблокировать KeyStore: %w", err)
		}
		ms.Unlock(pin)
		handler.OnLog(LogLevelInfo, "✅ Хранилища успешно разблокированы.")

		exists, err := ks.AccountExists(username)
		if err != nil {
			return nil, fmt.Errorf("ошибка при проверке существования аккаунта: %w", err)
		}
		if !exists {
			return nil, fmt.Errorf("аккаунт для пользователя '%s' не найден в хранилище", username)
		}
		handler.OnLog(LogLevelInfo, fmt.Sprintf("✅ Аккаунт для %s готов к использованию.", username))
	}

	p2pTransport, err := NewP2PTransport(handler)
	if err != nil {
		handler.OnLog(LogLevelWarning, fmt.Sprintf("⚠️ Не удалось создать P2P транспорт: %v", err))
	}

	return &Core{
		ks:           ks,
		ms:           ms,
		username:     username,
		handler:      handler,
		p2pTransport: p2pTransport,
	}, nil
}

// Start запускает ядро: подключается к серверу и начинает слушать события.
func (c *Core) Start(transport TransportProtocol) error {
	c.mu.Lock()
	if c.isStarted {
		c.mu.Unlock()
		return fmt.Errorf("ядро уже запущено")
	}
	c.mu.Unlock()

	c.handler.OnLog(LogLevelInfo, fmt.Sprintf("Инициализация подключения с транспортом: %s", transport.String()))

	c.useP2P = transport == P2P || transport == Hybrid || transport == Auto

	if transport == P2P {
		return c.startP2POnly()
	}

	tlsConfig, err := loadTLSCredentials(c.handler)
	if err != nil {
		return fmt.Errorf("не удалось загрузить TLS-конфигурацию: %w", err)
	}

	logic, err := newLogicClient(c.username, c.ks, c.ms, c.handler)
	if err != nil {
		return fmt.Errorf("не удалось создать логический клиент: %w", err)
	}

	var grpcConn *grpc.ClientConn
	var transportCloser io.Closer
	var usedTransport string

	if transport == Hybrid {
		grpcConn, transportCloser, usedTransport, err = tryConnect(Auto, tlsConfig, c.handler)
	} else {
		grpcConn, transportCloser, usedTransport, err = tryConnect(transport, tlsConfig, c.handler)
	}
	if err != nil {
		return fmt.Errorf("не удалось установить соединение: %w", err)
	}
	c.handler.OnLog(LogLevelInfo, fmt.Sprintf("✅ Транспортное соединение установлено через %s", usedTransport))

	phantomClient := pb.NewPhantomClient(grpcConn)
	stream, err := phantomClient.Transmit(context.Background())
	if err != nil {
		err := grpcConn.Close()
		if err != nil {
			return err
		}
		if transportCloser != nil {
			err := transportCloser.Close()
			if err != nil {
				return err
			}
		}
		return fmt.Errorf("не удалось создать gRPC-стрим: %w", err)
	}

	c.mu.Lock()
	c.grpcConn = grpcConn
	c.transportCloser = transportCloser
	c.logicClient = logic
	c.tlsConfig = tlsConfig
	c.mu.Unlock()

	readyChan := make(chan error, 1)
	go c.logicClient.startProcessing(stream, tlsConfig, readyChan)

	if err := <-readyChan; err != nil {
		err := c.Stop()
		if err != nil {
			return err
		}
		return fmt.Errorf("не удалось запустить логику ядра: %w", err)
	}

	if c.useP2P && c.p2pTransport != nil {
		go c.startP2PTransport()
	}

	c.mu.Lock()
	c.isStarted = true
	c.lastTransport = transport
	c.mu.Unlock()

	transportInfo := usedTransport
	if c.useP2P {
		transportInfo += " + P2P"
	}
	c.handler.OnLog(LogLevelInfo, fmt.Sprintf("✅ Ядро успешно запущено. Используемый транспорт: %s", transportInfo))

	return nil
}

// startP2POnly запускает только P2P транспорт без сервера
func (c *Core) startP2POnly() error {
	c.handler.OnLog(LogLevelInfo, "🌐 Запуск в режиме чистого P2P (без сервера)...")
	myHash := c.calculateLocalHash(c.username)

	logic, err := newLogicClient(c.username, c.ks, c.ms, c.handler)
	if err != nil {
		return fmt.Errorf("не удалось создать логический клиент: %w", err)
	}
	logic.myUsernameHash = myHash

	c.mu.Lock()
	c.logicClient = logic
	c.mu.Unlock()

	if c.p2pTransport == nil {
		return fmt.Errorf("P2P транспорт не инициализирован")
	}
	if err := c.p2pTransport.Start(myHash); err != nil {
		return fmt.Errorf("не удалось запустить P2P транспорт: %w", err)
	}

	c.p2pTransport.SetMessageHandler(logic)
	c.p2pTransport.SetCore(c)

	c.loadLocalContactsForP2P()

	go c.monitorP2PStatus()

	c.mu.Lock()
	c.isStarted = true
	c.lastTransport = P2P
	c.mu.Unlock()

	c.handler.OnLog(LogLevelInfo, "✅ Ядро запущено в режиме чистого P2P")
	c.handler.OnP2PStateChanged(true, []string{})

	return nil
}

// startP2PTransport запускает P2P транспорт
func (c *Core) startP2PTransport() {
	if c.p2pTransport == nil || c.logicClient == nil {
		return
	}
	c.handler.OnLog(LogLevelInfo, "🌐 Запуск P2P транспорта...")
	myHash := c.logicClient.myUsernameHash
	if myHash == "" {
		c.handler.OnLog(LogLevelError, "Не удалось получить хэш пользователя для P2P")
		return
	}

	if err := c.p2pTransport.Start(myHash); err != nil {
		c.handler.OnLog(LogLevelError, fmt.Sprintf("Не удалось запустить P2P: %v", err))
		return
	}

	c.p2pTransport.SetMessageHandler(c.logicClient)
	c.p2pTransport.SetCore(c)
	c.handler.OnP2PStateChanged(true, c.p2pTransport.GetP2PPeers())

	go c.monitorP2PStatus()
}

// monitorP2PStatus периодически ищет оффлайн-контакты.
func (c *Core) monitorP2PStatus() {
	// Даем время на первоначальное объявление в сети
	time.Sleep(5 * time.Second)

	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		c.mu.Lock()
		if !c.isStarted || c.p2pTransport == nil {
			c.mu.Unlock()
			return
		}
		p2pTransport := c.p2pTransport
		c.mu.Unlock()

		contacts, err := c.GetContacts()
		if err != nil {
			c.handler.OnLog(LogLevelWarning, "Не удалось получить контакты для периодического поиска.")
			<-ticker.C
			continue
		}

		// Для каждого оффлайн-контакта запускаем поиск
		for _, contact := range contacts {
			if !p2pTransport.IsP2PAvailable(contact.Hash) {
				c.handler.OnLog(LogLevelInfo, fmt.Sprintf("🔄 Периодический поиск оффлайн-контакта %s (%s...)", contact.Name, truncateHash(contact.Hash)))
				p2pTransport.ForceFindPeer(contact.Hash)
			}
		}

		// Обновляем UI с текущим статусом P2P
		peers := p2pTransport.GetP2PPeers()
		c.handler.OnP2PStateChanged(true, peers)
		c.updateContactsP2PStatus()

		<-ticker.C
	}
}

// updateContactsP2PStatus обновляет P2P статус контактов
func (c *Core) updateContactsP2PStatus() {
	contacts, err := c.GetContacts()
	if err != nil {
		return
	}
	if c.p2pTransport == nil {
		return
	}

	c.p2pTransport.peersMu.RLock()
	defer c.p2pTransport.peersMu.RUnlock()

	for i := range contacts {
		hash := contacts[i].Hash
		if c.p2pTransport.IsP2PAvailable(hash) {
			contacts[i].IsP2P = true
			if peerInfo, exists := c.p2pTransport.peers[hash]; exists {
				if peerInfo.IsLocal {
					contacts[i].P2PLocation = "local"
				} else {
					contacts[i].P2PLocation = "global"
				}
			}
		} else {
			contacts[i].IsP2P = false
			contacts[i].P2PLocation = ""
		}
	}

	c.handler.OnContactListUpdated(contacts)
}

// Stop останавливает ядро
func (c *Core) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.isStarted {
		return nil
	}
	c.handler.OnLog(LogLevelInfo, "Остановка ядра...")
	if c.p2pTransport != nil {
		err := c.p2pTransport.Stop()
		if err != nil {
			return err
		}
		c.handler.OnP2PStateChanged(false, []string{})
	}
	if c.logicClient != nil {
		c.logicClient.shutdown()
	}
	if c.grpcConn != nil {
		err := c.grpcConn.Close()
		if err != nil {
			return err
		}
	}
	if c.transportCloser != nil {
		err := c.transportCloser.Close()
		if err != nil {
			return err
		}
	}
	if c.ks != nil {
		err := c.ks.Close()
		if err != nil {
			return err
		}
	}
	if c.ms != nil {
		err := c.ms.Close()
		if err != nil {
			return err
		}
	}
	c.isStarted = false
	c.logicClient = nil
	c.grpcConn = nil
	c.transportCloser = nil
	c.tlsConfig = nil
	c.handler.OnLog(LogLevelInfo, "Ядро остановлено.")
	c.handler.OnShutdown("Ядро остановлено")

	return nil
}

// Restart перезапускает ядро
func (c *Core) Restart(transport TransportProtocol) error {
	c.handler.OnLog(LogLevelInfo, fmt.Sprintf("Перезапуск ядра с транспортом: %s", transport.String()))
	err := c.Stop()
	if err != nil {
		return err
	}
	time.Sleep(1 * time.Second)
	return c.Start(transport)
}

// GetLastTransport возвращает последний использованный транспорт
func (c *Core) GetLastTransport() TransportProtocol {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastTransport
}

// GetCurrentTransport возвращает фактически используемый транспорт
func (c *Core) GetCurrentTransport() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.isStarted {
		return "Не подключено"
	}
	var transports []string
	if c.grpcConn != nil {
		if c.lastTransport == QUIC {
			transports = append(transports, "QUIC")
		} else if c.lastTransport == TCP {
			transports = append(transports, "TCP")
		} else {
			transports = append(transports, "Server")
		}
	}
	if c.p2pTransport != nil && c.useP2P {
		peers := c.p2pTransport.GetP2PPeers()
		transports = append(transports, fmt.Sprintf("P2P(%d)", len(peers)))
	}
	if len(transports) == 0 {
		return "Неизвестно"
	}
	return strings.Join(transports, " + ")
}

// IsConnected проверяет, активно ли соединение
func (c *Core) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	serverConnected := c.isStarted && c.logicClient != nil && c.grpcConn != nil
	p2pConnected := c.p2pTransport != nil && c.useP2P && len(c.p2pTransport.GetP2PPeers()) > 0
	return serverConnected || p2pConnected
}

// GetContacts возвращает текущий список контактов.
func (c *Core) GetContacts() ([]ContactInfo, error) {
	usernames, err := c.ks.ListContactUsernames()
	if err != nil {
		return nil, fmt.Errorf("не удалось загрузить контакты из БД: %w", err)
	}

	// Используем map для хранения уникальных контактов по их хэшу
	uniqueContacts := make(map[string]ContactInfo)

	for _, name := range usernames {
		var hash string
		if c.logicClient != nil && c.lastTransport != P2P {
			hash = c.logicClient.getHashForUsername(name)
		}
		if hash == "" {
			hash = c.calculateLocalHash(name)
		}

		contact := ContactInfo{Name: name, Hash: hash}
		if c.p2pTransport != nil && c.p2pTransport.IsP2PAvailable(hash) {
			contact.IsP2P = true
			contact.IsOnline = true
			c.p2pTransport.peersMu.RLock()
			if peerInfo, exists := c.p2pTransport.peers[hash]; exists {
				contact.P2PLocation = "global"
				if peerInfo.IsLocal {
					contact.P2PLocation = "local"
				}
			}
			c.p2pTransport.peersMu.RUnlock()
		}
		uniqueContacts[hash] = contact // Добавляем или перезаписываем контакт в map
	}

	var contacts []ContactInfo
	for _, contact := range uniqueContacts {
		contacts = append(contacts, contact)
	}

	return contacts, nil
}

// GetHistory загружает историю сообщений.
func (c *Core) GetHistory(peerHash string, limit int) ([]StoredMessage, error) {
	return c.ms.LoadHistory(peerHash, limit)
}

// SendMessage отправляет сообщение.
func (c *Core) SendMessage(peerHash, text string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.isStarted || c.logicClient == nil {
		return fmt.Errorf("ядро не запущено")
	}

	if c.useP2P && c.p2pTransport != nil && c.p2pTransport.IsP2PAvailable(peerHash) {
		c.handler.OnLog(LogLevelInfo, fmt.Sprintf("📡 Отправка сообщения через P2P пиру %s...", truncateHash(peerHash)))
		err := c.logicClient.sendMessageViaP2P(peerHash, text, c.p2pTransport)
		if err == nil {
			return nil
		}
		c.handler.OnLog(LogLevelWarning, fmt.Sprintf("⚠️ P2P отправка не удалась: %v. Пробуем через сервер...", err))
	}

	if c.grpcConn != nil {
		return c.logicClient.sendMessage(peerHash, text)
	}
	return fmt.Errorf("нет доступных каналов для отправки сообщения")
}

// StartNewChat инициирует новый чат.
func (c *Core) StartNewChat(peerUsername string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.isStarted {
		return fmt.Errorf("ядро не запущено")
	}

	if c.lastTransport == P2P {
		peerHash := c.calculateLocalHash(peerUsername)
		// Проверяем, не существует ли контакт уже
		contacts, _ := c.GetContacts()
		for _, contact := range contacts {
			if contact.Name == peerUsername {
				c.handler.OnLog(LogLevelInfo, fmt.Sprintf("Контакт %s уже существует.", peerUsername))
				return nil
			}
		}

		contact := &Contact{Username: peerUsername, UsernameHash: peerHash}
		if err := c.ks.SaveContact(contact); err != nil {
			return fmt.Errorf("не удалось сохранить контакт: %w", err)
		}
		c.handler.OnLog(LogLevelInfo, fmt.Sprintf("✅ Контакт %s добавлен локально (P2P)", peerUsername))
		c.loadLocalContacts()

		return nil
	}

	if c.logicClient == nil {
		return fmt.Errorf("логический клиент не инициализирован для работы с сервером")
	}
	return c.logicClient.startNewChat(peerUsername, c.tlsConfig)
}

// GenerateSafetyNumber генерирует номер безопасности.
func (c *Core) GenerateSafetyNumber(peerHash string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.isStarted || c.logicClient == nil {
		return "", fmt.Errorf("ядро не запущено")
	}
	return c.logicClient.generateSafetyNumber(peerHash)
}

// ForceContactSync принудительно синхронизирует контакты.
func (c *Core) ForceContactSync() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.isStarted && c.logicClient != nil && c.grpcConn != nil {
		go c.logicClient.initialContactSync(c.tlsConfig)
	}
	if c.p2pTransport != nil {
		c.updateContactsP2PStatus()
	}
}

// TryReconnect пытается переподключиться.
func (c *Core) TryReconnect() error {
	c.mu.Lock()
	isStarted := c.isStarted
	lastTransport := c.lastTransport
	c.mu.Unlock()
	if !isStarted {
		return fmt.Errorf("ядро не было запущено, используйте Start() вместо TryReconnect()")
	}
	c.handler.OnLog(LogLevelInfo, "Попытка переподключения...")
	if err := c.Restart(lastTransport); err != nil {
		if lastTransport != Auto {
			c.handler.OnLog(LogLevelWarning, fmt.Sprintf("Переподключение с %s не удалось, пробуем Auto", lastTransport.String()))
			return c.Restart(Auto)
		}
		return err
	}
	return nil
}

// GetP2PStatus возвращает статус P2P.
func (c *Core) GetP2PStatus() (bool, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.p2pTransport == nil || !c.useP2P {
		return false, []string{}
	}
	peers := c.p2pTransport.GetP2PPeers()
	return len(peers) > 0, peers
}

// calculateLocalHash вычисляет хэш локально.
func (c *Core) calculateLocalHash(username string) string {
	publicSalt := []byte("your-fixed-salt-that-will-be-the-same-every-time")
	localHash := hmac.New(sha256.New, publicSalt)
	localHash.Write([]byte(username))
	return base64.URLEncoding.EncodeToString(localHash.Sum(nil))
}

// calculateP2PHashWithSharedSecret вычисляет P2P хэш с общим секретом.
func (c *Core) calculateP2PHashWithSharedSecret(contactHash, contactName string) (string, error) {
	var myPrivateKey, theirPublicKey *[32]byte
	err := c.ks.WithUserAccount(c.username, func(ua *UserAccount) error {
		if ua.IdentityPrivateX25519 == nil {
			return fmt.Errorf("приватный ключ X25519 отсутствует")
		}
		myPrivateKey = ua.IdentityPrivateX25519
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("не удалось получить приватный ключ: %w", err)
	}
	contact, err := c.ks.LoadContact(contactHash)
	if err != nil {
		return "", fmt.Errorf("не удалось загрузить контакт: %w", err)
	}
	if contact.IdentityPublicX25519 == nil {
		return "", fmt.Errorf("публичный ключ X25519 контакта отсутствует")
	}
	theirPublicKey = contact.IdentityPublicX25519
	sharedSecret, err := curve25519.X25519(myPrivateKey[:], theirPublicKey[:])
	if err != nil {
		return "", fmt.Errorf("не удалось вычислить общий секрет X25519: %w", err)
	}
	firstRoundHash := c.calculateLocalHash(contactName)
	secondRoundHMAC := hmac.New(sha256.New, sharedSecret[:])
	secondRoundHMAC.Write([]byte(firstRoundHash))
	finalHash := base64.URLEncoding.EncodeToString(secondRoundHMAC.Sum(nil))
	c.handler.OnLog(LogLevelInfo, fmt.Sprintf("🔐 Вычислен P2P хэш с общим секретом для %s: %s", truncateHash(contactHash), truncateHash(finalHash)))
	return finalHash, nil
}

// loadLocalContacts загружает контакты из локальной БД.
func (c *Core) loadLocalContacts() {
	contacts, err := c.GetContacts()
	if err != nil {
		c.handler.OnLog(LogLevelError, fmt.Sprintf("Не удалось загрузить контакты: %v", err))
		return
	}
	if c.logicClient != nil {
		c.logicClient.contactsMu.Lock()
		c.logicClient.usernameToHash = make(map[string]string)
		c.logicClient.hashToUsername = make(map[string]string)
		for _, contact := range contacts {
			if contact.Name != "" && contact.Hash != "" {
				c.logicClient.usernameToHash[contact.Name] = contact.Hash
				c.logicClient.hashToUsername[contact.Hash] = contact.Name
			}
		}
		c.logicClient.contactsMu.Unlock()
		c.handler.OnLog(LogLevelInfo, fmt.Sprintf("Состояние logicClient обновлено. Теперь отслеживается %d контактов.", len(contacts)))
	}
	c.handler.OnContactListUpdated(contacts)
}

// loadLocalContactsForP2P загружает контакты для P2P режима.
func (c *Core) loadLocalContactsForP2P() {
	contacts, err := c.GetContacts()
	if err != nil {
		c.handler.OnLog(LogLevelError, fmt.Sprintf("Не удалось загрузить контакты: %v", err))
		return
	}
	if c.logicClient != nil {
		c.logicClient.contactsMu.Lock()
		c.logicClient.usernameToHash = make(map[string]string)
		c.logicClient.hashToUsername = make(map[string]string)
		for _, contact := range contacts {
			c.logicClient.usernameToHash[contact.Name] = contact.Hash
			c.logicClient.hashToUsername[contact.Hash] = contact.Name
		}
		c.logicClient.contactsMu.Unlock()
	}
	c.handler.OnContactListUpdated(contacts)
}

// getP2PHashesForAnnouncement возвращает хэши для анонсирования.
func (c *Core) getP2PHashesForAnnouncement() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.logicClient == nil {
		return []string{}
	}
	var hashesToAnnounce []string
	c.logicClient.contactsMu.RLock()
	for _, standardHash := range c.logicClient.usernameToHash {
		hashesToAnnounce = append(hashesToAnnounce, standardHash)
	}
	c.logicClient.contactsMu.RUnlock()
	if c.logicClient.myUsernameHash != "" {
		hashesToAnnounce = append(hashesToAnnounce, c.logicClient.myUsernameHash)
	}
	uniqueHashes := make(map[string]bool)
	var result []string
	for _, hash := range hashesToAnnounce {
		if !uniqueHashes[hash] {
			uniqueHashes[hash] = true
			result = append(result, hash)
		}
	}
	c.handler.OnLog(LogLevelInfo, fmt.Sprintf("📢 Подготовлено к анонсу %d уникальных хэшей.", len(result)))
	return result
}

// fileExists проверяет, существует ли файл.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}
