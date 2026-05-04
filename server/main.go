// Copyright 2025 snaart
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	proto2 "phantom/proto"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	// --- PQC Imports ---
	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/dilithium/mode5"
	// --- PQC Imports ---
)

var (
	globalPublicSalt = []byte("a-publicly-known-salt-for-phantom-clients")
	serverSigningKey sign.PrivateKey
	serverPublicKey  sign.PublicKey
)

const (
	MaxOfflineMessages   = 500
	OPKLowWaterMark      = 10
	certFile             = "server.crt"
	keyFile              = "server.key"
	serverSigningKeyFile = "server_signing.key"
	p2pRelayKeyFile      = "relay.key"
	privateSaltEnvVar    = "PHANTOM_PRIVATE_SALT"
	P2PInfoTTL           = 5 * time.Minute // Время жизни P2P информации
)

// P2PInfo содержит информацию о P2P возможностях клиента
type P2PInfo struct {
	PeerID       string    `json:"peer_id"`   // libp2p peer ID
	Addresses    []string  `json:"addresses"` // multiaddresses
	SupportsP2P  bool      `json:"supports_p2p"`
	LastUpdated  time.Time `json:"last_updated"`
	PreferP2P    bool      `json:"prefer_p2p"`    // Клиент предпочитает P2P
	RelayWilling bool      `json:"relay_willing"` // Готов быть relay узлом
}

type clientInfo struct {
	idHash                string
	stream                proto2.Phantom_TransmitServer
	identityPublicKeyDili sign.PublicKey
	lastSeen              time.Time
	transportType         string   // "TCP", "QUIC", "P2P-Hybrid"
	p2pInfo               *P2PInfo // Новое поле для P2P информации
	isP2PCapable          bool     // Поддерживает ли клиент P2P
}

type phantomServer struct {
	proto2.UnimplementedPhantomServer
	proto2.UnimplementedAuthServer
	mu                   sync.RWMutex
	clients              map[string]*clientInfo // Map ListenToken (hex) -> clientInfo
	registrationLimiters map[string]*rate.Limiter
	privateSalt          []byte
	p2pDirectory         map[string]*P2PInfo // Директория P2P пиров
	p2pMu                sync.RWMutex
	stats                *ServerStats
}

// ServerStats собирает статистику сервера
type ServerStats struct {
	mu                sync.RWMutex
	totalMessages     uint64
	p2pRedirects      uint64
	offlineDeliveries uint64
	activeConnections int
	p2pCapableClients int
}

func newPhantomServer(privateSalt []byte) *phantomServer {
	if len(privateSalt) < 32 {
		log.Fatalf("КРИТИЧЕСКАЯ ОШИБКА: Приватная соль сервера короче 32 байт. Запуск невозможен.")
	}
	return &phantomServer{
		clients:              make(map[string]*clientInfo),
		registrationLimiters: make(map[string]*rate.Limiter),
		privateSalt:          privateSalt,
		p2pDirectory:         make(map[string]*P2PInfo),
		stats:                &ServerStats{},
	}
}

func (s *phantomServer) Transmit(stream proto2.Phantom_TransmitServer) error {
	transportType := "TCP" // По умолчанию
	p, ok := peer.FromContext(stream.Context())
	if ok && p.Addr != nil {
		// gRPC через QUIC будет иметь UDP адрес
		if _, isUDP := p.Addr.(*net.UDPAddr); isUDP {
			transportType = "QUIC"
		}
		log.Printf("🔌 Новое Transmit-соединение от %s (транспорт: %s)", p.Addr.String(), transportType)
	} else {
		log.Printf("🔌 Новое Transmit-соединение (транспорт: неизвестен)")
	}

	var currentClientHash string
	defer func() {
		if currentClientHash != "" {
			s.clientDisconnected(currentClientHash)
		}
	}()

	for {
		packet, err := stream.Recv()
		if err != nil {
			if !errors.Is(err, io.EOF) && status.Code(err) != codes.Canceled {
				log.Printf("❌ Ошибка чтения от клиента %s... (%s): %v", truncateHash(currentClientHash), transportType, err)
			}
			return err
		}

		if currentClientHash == "" {
			if len(packet.SenderIdentityKey) > 0 {
				currentClientHash = fmt.Sprintf("%x", packet.SenderIdentityKey)
				log.Printf("✅ Соединение от %s аутентифицировано как клиент %s... (%s)",
					func() string {
						if p != nil && p.Addr != nil {
							return p.Addr.String()
						}
						return "unknown"
					}(),
					truncateHash(currentClientHash), transportType)
			} else {
				// Если это не первый пакет и хэш не установлен, или SenderIdentityKey отсутствует
				log.Printf("⚠️ Пакет без SenderIdentityKey и сессия не установлена. Отброшен.")
				continue
			}
		}

		var publicKey sign.PublicKey
		s.mu.RLock()
		client, clientExists := s.clients[currentClientHash]
		s.mu.RUnlock()

		diliScheme := mode5.Scheme()

		if regReqPld, ok := packet.Payload.(*proto2.Packet_RegistrationRequest); ok {
			// В новой схеме RegistrationRequest содержит ListenTokens и P2PInfo.
			// Ключи (IdentityKey) уже есть в SenderIdentityKey пакета.

			// Мы можем проверить подпись, используя SenderIdentityKey.
			publicKey, err = diliScheme.UnmarshalBinaryPublicKey(packet.SenderIdentityKey)
			if err != nil {
				log.Printf("❌ Не удалось распаковать SenderIdentityKey от %s...: %v", truncateHash(currentClientHash), err)
				continue
			}

			// Проверяем P2P информацию в регистрационном пакете
			if regReqPld.RegistrationRequest.P2PInfo != nil {
				s.handleP2PRegistration(currentClientHash, regReqPld.RegistrationRequest.P2PInfo)
			}
		} else if clientExists {
			publicKey = client.identityPublicKeyDili
		} else {
			// Если клиента нет и это не регистрация, но у нас есть SenderIdentityKey,
			// мы можем попробовать извлечь ключ из него.
			if len(packet.SenderIdentityKey) > 0 {
				publicKey, err = diliScheme.UnmarshalBinaryPublicKey(packet.SenderIdentityKey)
				if err != nil {
					log.Printf("❌ Не удалось распаковать SenderIdentityKey: %v", err)
					continue
				}
			} else {
				log.Printf("⚠️ Пакет от неизвестного клиента %s... отброшен", truncateHash(currentClientHash))
				continue
			}
		}

		if err := verifyPacketSignature(packet, publicKey); err != nil {
			log.Printf("❌ Ошибка проверки подписи от %s...: %v. Пакет отброшен.", truncateHash(currentClientHash), err)
			continue
		}

		switch req := packet.Payload.(type) {
		case *proto2.Packet_RegistrationRequest:
			ip := "unknown"
			if p != nil && ok && p.Addr != nil {
				if host, _, err := net.SplitHostPort(p.Addr.String()); err == nil {
					ip = host
				}
			}

			if !clientExists {
				s.mu.Lock()
				limiter, exists := s.registrationLimiters[ip]
				if !exists {
					limiter = rate.NewLimiter(rate.Every(2*time.Minute), 2)
					s.registrationLimiters[ip] = limiter
				}
				s.mu.Unlock()

				if !limiter.Allow() {
					log.Printf("⚠️ ПРЕДОТВРАЩЕНА DoS-АТАКА: Слишком частые запросы на НОВУЮ регистрацию от IP %s. Пакет отброшен.", ip)
					continue
				}
			}
			s.handleRegistration(currentClientHash, req.RegistrationRequest, stream, transportType)
		// case *proto2.Packet_KeyRequest: // Removed
		// 	s.handleKeyRequest(currentClientHash, req.KeyRequest.RequestedClientIdHash)
		case *proto2.Packet_EncryptedMessage:
			// Проверяем, можно ли перенаправить через P2P
			// Для этого нам нужно знать Destination Hash. Но в анонимной маршрутизации у нас только RoutingToken.
			// Сервер может попробовать найти клиента по RoutingToken (ListenToken).

			// s.shouldRedirectToP2P logic needs update to work with RoutingToken or internal mapping.
			// For now, disable P2P redirect for encrypted messages until mapping is implemented.
			/*
				if s.shouldRedirectToP2P(packet.DestinationClientIdHash) {
					s.notifyP2PAvailable(currentClientHash, packet.DestinationClientIdHash)
					s.stats.mu.Lock()
					s.stats.p2pRedirects++
					s.stats.mu.Unlock()
				}
			*/
			s.routePacket(packet)
		case *proto2.Packet_P2PUpdate:
			// Обработка обновления P2P информации
			s.handleP2PUpdate(currentClientHash, req.P2PUpdate)
		}
	}
}

func (s *phantomServer) handleP2PRegistration(clientHash string, p2pInfo *proto2.P2PInfo) {
	s.p2pMu.Lock()
	defer s.p2pMu.Unlock()

	if p2pInfo == nil {
		return
	}

	s.p2pDirectory[clientHash] = &P2PInfo{
		PeerID:       p2pInfo.PeerId,
		Addresses:    p2pInfo.Addresses,
		SupportsP2P:  true,
		LastUpdated:  time.Now(),
		PreferP2P:    p2pInfo.PreferP2P,
		RelayWilling: p2pInfo.RelayWilling,
	}

	log.Printf("🌐 Клиент %s... зарегистрирован с P2P поддержкой (PeerID: %s...)",
		truncateHash(clientHash), truncateHash(p2pInfo.PeerId))
}

func (s *phantomServer) handleP2PUpdate(clientHash string, update *proto2.P2PUpdate) {
	s.p2pMu.Lock()
	defer s.p2pMu.Unlock()

	if info, exists := s.p2pDirectory[clientHash]; exists {
		info.Addresses = update.Addresses
		info.LastUpdated = time.Now()
		info.RelayWilling = update.RelayWilling
		log.Printf("📡 P2P адреса обновлены для %s...", truncateHash(clientHash))
	}
}

func (s *phantomServer) shouldRedirectToP2P(destHash string) bool {
	s.p2pMu.RLock()
	defer s.p2pMu.RUnlock()

	info, exists := s.p2pDirectory[destHash]
	if !exists {
		return false
	}

	// Проверяем, актуальна ли информация
	if time.Since(info.LastUpdated) > P2PInfoTTL {
		return false
	}

	return info.PreferP2P && len(info.Addresses) > 0
}

func (s *phantomServer) notifyP2PAvailable(sourceHash, destHash string) {
	s.mu.RLock()
	sourceClient, exists := s.clients[sourceHash]
	s.mu.RUnlock()

	if !exists || sourceClient.stream == nil {
		return
	}

	s.p2pMu.RUnlock()

	if !exists {
		return
	}

	// Отправляем уведомление о доступности P2P
	// Note: SourceClientIdHash and DestinationClientIdHash are removed.
	// We need to adapt this notification or remove it.
	// For now, removing to fix compilation.
	/*
		notification := &proto2.Packet{
			SourceClientIdHash:      "server",
			DestinationClientIdHash: sourceHash,
			Payload: &proto2.Packet_SystemNotification{
				SystemNotification: &proto2.SystemNotification{
					Type:    proto2.SystemNotification_P2P_AVAILABLE,
					Message: fmt.Sprintf("Peer %s available via P2P", destHash),
					P2PInfo: &proto2.P2PInfo{
						PeerId:    destP2PInfo.PeerID,
						Addresses: destP2PInfo.Addresses,
					},
				},
			},
		}
	*/

	/*
		go func() {
			if err := sourceClient.stream.Send(notification); err != nil {
				log.Printf("❌ Не удалось отправить P2P уведомление: %v", err)
			}
		}()
	*/
}

func (s *phantomServer) clientDisconnected(clientHash string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if client, ok := s.clients[clientHash]; ok {
		transportInfo := ""
		if client.transportType != "" {
			transportInfo = fmt.Sprintf(" (%s)", client.transportType)
		}
		if client.isP2PCapable {
			transportInfo += " [P2P-capable]"
		}
		client.stream = nil
		log.Printf("👋 Клиент %s... перешел в оффлайн%s.", truncateHash(clientHash), transportInfo)

		// Обновляем статистику
		s.stats.mu.Lock()
		s.stats.activeConnections--
		if client.isP2PCapable {
			s.stats.p2pCapableClients--
		}
		s.stats.mu.Unlock()
	}

	// НЕ удаляем P2P информацию сразу - она может быть полезна некоторое время
	// Очистка происходит по TTL
}

func verifyPacketSignature(packet *proto2.Packet, publicKey sign.PublicKey) error {
	// if packet.SourceClientIdHash == "server" { return nil } // Removed check
	if publicKey == nil {
		return errors.New("не предоставлен публичный ключ для проверки подписи")
	}

	packetCopy := proto.Clone(packet).(*proto2.Packet)
	packetCopy.Signature = nil
	data, err := proto.Marshal(packetCopy)
	if err != nil {
		return err
	}

	diliPubKey, ok := publicKey.(*mode5.PublicKey)
	if !ok {
		return errors.New("PQC: публичный ключ не является Dilithium5")
	}

	if !mode5.Verify(diliPubKey, data, packet.Signature) {
		return errors.New("неверная подпись пакета (Dilithium5)")
	}
	return nil
}

func (s *phantomServer) handleRegistration(clientHash string, req *proto2.RegistrationRequest, stream proto2.Phantom_TransmitServer, transportType string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// В новой схеме мы регистрируем ListenTokens.
	// clientHash здесь - это хэш SenderIdentityKey, который мы используем для идентификации соединения,
	// но маршрутизация идет по ListenTokens.

	client := &clientInfo{
		idHash:        clientHash,
		stream:        stream,
		lastSeen:      time.Now(),
		transportType: transportType,
		isP2PCapable:  false,
	}

	// Регистрируем каждый ListenToken
	for _, token := range req.ListenTokens {
		tokenHex := fmt.Sprintf("%x", token)
		s.clients[tokenHex] = client
	}

	// Проверяем P2P информацию
	if req.P2PInfo != nil {
		client.isP2PCapable = true
		client.p2pInfo = &P2PInfo{
			PeerID:       req.P2PInfo.PeerId,
			Addresses:    req.P2PInfo.Addresses,
			SupportsP2P:  true,
			LastUpdated:  time.Now(),
			PreferP2P:    req.P2PInfo.PreferP2P,
			RelayWilling: req.P2PInfo.RelayWilling,
		}

		s.stats.mu.Lock()
		s.stats.p2pCapableClients++
		s.stats.mu.Unlock()

		transportType += " [P2P-capable]"
	}

	log.Printf("🆕 Клиент %s... зарегистрировал %d токенов (%s).", truncateHash(clientHash), len(req.ListenTokens), transportType)

	// Обновляем статистику
	s.stats.mu.Lock()
	s.stats.activeConnections++
	s.stats.mu.Unlock()
}

// handleKeyRequest removed

// sendP2PInfo removed

func (s *phantomServer) routePacket(packet *proto2.Packet) {
	s.mu.RLock()
	// Используем RoutingToken для поиска получателя
	routingTokenHex := fmt.Sprintf("%x", packet.RoutingToken)
	destClient, found := s.clients[routingTokenHex]
	isOnline := found && destClient.stream != nil
	s.mu.RUnlock()

	// Обновляем статистику
	s.stats.mu.Lock()
	s.stats.totalMessages++
	s.stats.mu.Unlock()

	if isOnline {
		if err := destClient.stream.Send(packet); err != nil {
			log.Printf("❌ Ошибка перенаправления по токену %s...: %v. Клиент, возможно, оффлайн.", truncateHash(routingTokenHex), err)
			// s.saveOfflineMessage(routingTokenHex, packet) // Disabled for now
		}
	} else {
		log.Printf("💾 Получатель (токен %s...) оффлайн. Сообщение отброшено (оффлайн-очередь временно отключена).", truncateHash(routingTokenHex))
		// s.saveOfflineMessage(routingTokenHex, packet) // Disabled for now
	}
}

func (s *phantomServer) saveOfflineMessage(destHash string, packet *proto2.Packet) {
	// Offline messaging disabled during refactor
}

// sendKeyResponse removed
// sendOpkLowNotification removed

// Периодическая очистка устаревшей P2P информации
func (s *phantomServer) cleanupP2PDirectory() {
	ticker := time.NewTicker(P2PInfoTTL)
	defer ticker.Stop()

	for range ticker.C {
		s.p2pMu.Lock()
		now := time.Now()
		for hash, info := range s.p2pDirectory {
			if now.Sub(info.LastUpdated) > P2PInfoTTL*2 {
				delete(s.p2pDirectory, hash)
				log.Printf("🗑️ Удалена устаревшая P2P информация для %s...", truncateHash(hash))
			}
		}
		s.p2pMu.Unlock()
	}
}

// Статистика сервера
func (s *phantomServer) printStats() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.stats.mu.RLock()
		s.mu.RLock()
		s.p2pMu.RLock()

		log.Printf("📊 СТАТИСТИКА СЕРВЕРА:")
		log.Printf("   Активных соединений: %d", s.stats.activeConnections)
		log.Printf("   P2P-capable клиентов: %d", s.stats.p2pCapableClients)
		log.Printf("   Всего сообщений: %d", s.stats.totalMessages)
		log.Printf("   P2P перенаправлений: %d", s.stats.p2pRedirects)
		log.Printf("   Доставлено оффлайн: %d", s.stats.offlineDeliveries)
		log.Printf("   P2P пиров в директории: %d", len(s.p2pDirectory))
		// log.Printf("   Оффлайн очередей: %d", len(s.offlineMessages))

		s.p2pMu.RUnlock()
		s.mu.RUnlock()
		s.stats.mu.RUnlock()
	}
}

func truncateHash(hash string) string {
	if len(hash) > 8 {
		return hash[:8]
	}
	return hash
}

func loadOrGenerateTLSConfig(host string) (*tls.Config, error) {
	strictCipherSuites := []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
	}

	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			log.Println("✅ Найдены существующие TLS сертификат и ключ. Загрузка...")
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, fmt.Errorf("не удалось загрузить существующую пару ключ/сертификат: %w", err)
			}
			return &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS13,
				CipherSuites: strictCipherSuites,
				NextProtos:   []string{"h3", "h2"}, // Поддержка и HTTP/3 (QUIC) и HTTP/2 (TCP)
			}, nil
		}
	}

	log.Println("⚠️ TLS сертификат и ключ не найдены. Генерация новых...")
	if host == "" {
		return nil, errors.New("необходимо указать хост (IP или домен) для генерации сертификата с помощью флага -host")
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("не удалось сгенерировать приватный ключ: %w", err)
	}

	keyOut, err := os.Create(keyFile)
	if err != nil {
		return nil, fmt.Errorf("не удалось создать файл %s: %w", keyFile, err)
	}
	defer keyOut.Close()
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("не удалось маршалировать приватный ключ: %w", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}); err != nil {
		return nil, fmt.Errorf("не удалось записать ключ в %s: %w", keyFile, err)
	}
	log.Printf("✅ Приватный ключ сохранен в '%s'.", keyFile)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("не удалось сгенерировать серийный номер: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{Organization: []string{"Phantom Test Server"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(5, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
		log.Printf("📝 В сертификат будет встроен IP-адрес: %s", host)
	} else {
		template.DNSNames = append(template.DNSNames, host)
		log.Printf("📝 В сертификат будет встроено доменное имя: %s", host)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("не удалось создать сертификат: %w", err)
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		return nil, fmt.Errorf("не удалось создать файл %s: %w", certFile, err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, fmt.Errorf("не удалось записать данные в %s: %w", certFile, err)
	}
	log.Printf("✅ Самоподписанный TLS сертификат сохранен в '%s'.", certFile)

	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{derBytes}, PrivateKey: priv}},
		MinVersion:   tls.VersionTLS13,
		CipherSuites: strictCipherSuites,
		NextProtos:   []string{"h3", "h2"},
	}, nil
}

func loadOrGenerateServerSigningKey() error {
	diliScheme := mode5.Scheme()
	if _, err := os.Stat(serverSigningKeyFile); err == nil {
		log.Printf("✅ Найден существующий ключ подписи сервера '%s'. Загрузка...", serverSigningKeyFile)
		keyBytes, err := os.ReadFile(serverSigningKeyFile)
		if err != nil {
			return fmt.Errorf("не удалось прочитать файл ключа подписи: %w", err)
		}
		serverSigningKey, err = diliScheme.UnmarshalBinaryPrivateKey(keyBytes)
		if err != nil {
			return fmt.Errorf("не удалось распаковать ключ подписи Dilithium5: %w", err)
		}

		pub, ok := serverSigningKey.Public().(sign.PublicKey)
		if !ok {
			return fmt.Errorf("не удалось преобразовать загруженный публичный ключ в тип sign.PublicKey")
		}
		serverPublicKey = pub

		return nil
	}

	log.Printf("⚠️ Ключ подписи сервера '%s' не найден. Генерация нового...", serverSigningKeyFile)
	var err error
	serverPublicKey, serverSigningKey, err = diliScheme.GenerateKey()
	if err != nil {
		return fmt.Errorf("не удалось сгенерировать ключ подписи Dilithium5: %w", err)
	}

	privKeyBytes, err := serverSigningKey.MarshalBinary()
	if err != nil {
		return fmt.Errorf("не удалось сериализовать ключ подписи: %w", err)
	}

	if err := os.WriteFile(serverSigningKeyFile, privKeyBytes, 0600); err != nil {
		return fmt.Errorf("не удалось сохранить ключ подписи в файл: %w", err)
	}
	log.Printf("✅ Ключ подписи сервера сохранен в '%s'", serverSigningKeyFile)
	return nil
}

func loadOrGenerateP2PKey(path string) (crypto.PrivKey, error) {
	if _, err := os.Stat(path); err == nil {
		log.Printf("🔑 Найден существующий P2P ключ '%s'. Загрузка...", path)
		keyBytes, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("не удалось прочитать файл P2P ключа: %w", err)
		}
		privKey, err := crypto.UnmarshalEd25519PrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("не удалось распаковать P2P ключ: %w", err)
		}
		return privKey, nil
	}

	log.Printf("⚠️ P2P ключ '%s' не найден. Генерация нового...", path)
	privKey, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("не удалось сгенерировать P2P ключ: %w", err)
	}

	keyBytes, err := crypto.MarshalPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("не удалось сериализовать P2P ключ: %w", err)
	}

	if err := os.WriteFile(path, keyBytes, 0600); err != nil {
		return nil, fmt.Errorf("не удалось сохранить P2P ключ в файл: %w", err)
	}
	log.Printf("✅ P2P ключ сохранен в '%s'", path)
	return privKey, nil
}

func startP2PRelay() {
	privKey, err := loadOrGenerateP2PKey(p2pRelayKeyFile)
	if err != nil {
		log.Fatalf("❌ Не удалось инициализировать P2P ключ: %v", err)
	}

	// Отключаем лимиты, чтобы наш сервер не отклонял запросы на ретрансляцию.
	limiter := rcmgr.NewFixedLimiter(rcmgr.InfiniteLimits)
	rm, err := rcmgr.NewResourceManager(limiter)
	if err != nil {
		log.Fatalf("❌ Не удалось создать P2P resource manager: %v", err)
	}

	// Создаем узел libp2p
	h, err := libp2p.New(
		libp2p.Identity(privKey),
		libp2p.ListenAddrStrings(
			"/ip4/0.0.0.0/tcp/4001",         // Стандартный порт для libp2p
			"/ip6/::/tcp/4001",              // TCP на IPv6
			"/ip4/0.0.0.0/udp/4001/quic-v1", // QUIC на IPv4
			"/ip6/::/udp/4001/quic-v1",      // QUIC на IPv6
		),
		libp2p.ResourceManager(rm),
		libp2p.EnableRelayService(), // Включаем режим Relay-сервера
		libp2p.EnableHolePunching(),
	)
	if err != nil {
		log.Fatalf("❌ Не удалось создать libp2p хост: %v", err)
	}

	// Включаем сам сервис ретрансляции
	_, err = relay.New(h)
	if err != nil {
		log.Fatalf("❌ Не удалось инстанциировать Relay-сервис: %v", err)
	}

	log.Println("===========================================")
	log.Printf("✅ P2P Relay/Bootstrap узел запущен. Peer ID: %s", h.ID())
	log.Println("   Используйте один из публичных адресов ниже в конфигурации клиента (p2p_bootstrap.go):")
	for _, addr := range h.Addrs() {
		// Игнорируем локальные адреса при выводе
		if !strings.HasPrefix(addr.String(), "/ip4/127.0.0.1") {
			log.Printf("      -> %s/p2p/%s", addr, h.ID())
		}
	}
	log.Println("===========================================")
}

func main() {
	host := flag.String("host", "127.0.0.1", "Хост (публичный IP или домен), который будет встроен в TLS сертификат")
	enableStats := flag.Bool("stats", true, "Включить периодический вывод статистики")
	flag.Parse()

	privateSaltStr := os.Getenv(privateSaltEnvVar)
	if privateSaltStr == "" {
		log.Fatalf("❌ КРИТИЧЕСКАЯ ОШИБКА: Переменная окружения %s не установлена.", privateSaltEnvVar)
	}

	// --- ЗАПУСК P2P РЕТРАНСЛЯТОРА ---
	// Запускаем P2P-узел в отдельной горутине, чтобы он не блокировал основной сервер
	go startP2PRelay()
	// --- КОНЕЦ P2P ЧАСТИ ---

	if err := loadOrGenerateServerSigningKey(); err != nil {
		log.Fatalf("❌ Не удалось загрузить или сгенерировать ключ подписи сервера: %v", err)
	}

	pubKeyBytes, _ := serverPublicKey.MarshalBinary()
	log.Printf("🔑 Публичный ключ сервера (Dilithium5) для верификации (вставить в client.go): %s",
		base64.StdEncoding.EncodeToString(pubKeyBytes))

	tlsConfig, err := loadOrGenerateTLSConfig(*host)
	if err != nil {
		log.Fatalf("❌ Не удалось создать/загрузить TLS конфигурацию: %v", err)
	}

	// 1. Создаем gRPC-сервер
	serverImpl := newPhantomServer([]byte(privateSaltStr))
	grpcServer := grpc.NewServer()
	proto2.RegisterPhantomServer(grpcServer, serverImpl)
	proto2.RegisterAuthServer(grpcServer, serverImpl)

	// Запускаем фоновые задачи
	go serverImpl.cleanupP2PDirectory()
	if *enableStats {
		go serverImpl.printStats()
	}

	// 2. Создаем универсальный обработчик
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
			grpcServer.ServeHTTP(w, r)
		} else {
			// Простая страница статуса для браузера
			if r.URL.Path == "/status" {
				w.Header().Set("Content-Type", "application/json")
				serverImpl.mu.RLock()
				serverImpl.stats.mu.RLock()
				status := map[string]interface{}{
					"server": "Phantom Hybrid P2P Server",
					"stats": map[string]interface{}{
						"active_connections": serverImpl.stats.activeConnections,
						"p2p_clients":        serverImpl.stats.p2pCapableClients,
						"total_messages":     serverImpl.stats.totalMessages,
						"p2p_redirects":      serverImpl.stats.p2pRedirects,
						"offline_delivered":  serverImpl.stats.offlineDeliveries,
					},
				}
				serverImpl.stats.mu.RUnlock()
				serverImpl.mu.RUnlock()
				json.NewEncoder(w).Encode(status)
			} else {
				http.NotFound(w, r)
			}
		}
	})

	// === ЗАПУСК TCP (HTTP/2) СЕРВЕРА ===
	addr := "0.0.0.0:50051"
	tcpListener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("❌ Не удалось прослушать TCP порт: %v", err)
	}
	httpServer := &http.Server{
		Handler:   handler,
		TLSConfig: tlsConfig,
	}
	go func() {
		log.Println("✅ [TCP] Сервер gRPC/H2 запущен на", addr)
		tlsListener := tls.NewListener(tcpListener, tlsConfig)
		if err := httpServer.Serve(tlsListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("❌ Ошибка gRPC TCP/H2 сервера: %v", err)
		}
	}()

	// === ЗАПУСК QUIC (HTTP/3) СЕРВЕРА ===
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 50051, IP: net.ParseIP(strings.Split(addr, ":")[0])})
	if err != nil {
		log.Fatalf("❌ Не удалось прослушать UDP порт: %v", err)
	}
	quicConf := &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	}
	quicListener, err := quic.ListenEarly(udpConn, tlsConfig, quicConf)
	if err != nil {
		log.Fatalf("❌ Не удалось создать QUIC listener: %v", err)
	}
	h3Server := &http3.Server{
		Handler: handler,
		Addr:    addr,
	}
	go func() {
		log.Println("✅ [QUIC] Сервер gRPC/H3 запущен на", addr)
		if err := h3Server.ServeListener(quicListener); err != nil {
			log.Printf("❌ Ошибка gRPC QUIC/H3 сервера: %v", err)
		}
	}()

	log.Println("===========================================")
	log.Println("🚀 Phantom Hybrid P2P Server готов")
	log.Println("   📡 gRPC TCP:  0.0.0.0:50051 (H2)")
	log.Println("   🚀 gRPC QUIC: 0.0.0.0:50051 (H3)")
	log.Println("   📊 Status:    http://localhost:50051/status")
	log.Println("   🌐 P2P Relay: 0.0.0.0:4001 (TCP+QUIC)")
	log.Println("===========================================")

	select {}
}
