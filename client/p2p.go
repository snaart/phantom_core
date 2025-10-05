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
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	pb "phantom/proto"
	"strings"
	"sync"
	"time"

	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"
	"github.com/multiformats/go-multiaddr"
	"github.com/multiformats/go-multihash"
	"google.golang.org/protobuf/proto"
)

const (
	ProtocolID         = "/phantom/1.0.0"
	DiscoveryNamespace = "phantom-network"
	StreamTimeout      = 30 * time.Second
	DiscoveryInterval  = 15 * time.Second
	MaxP2PMessageSize  = 10 * 1024 * 1024 // 10MB
)

// P2PTransport управляет P2P соединениями через libp2p
type P2PTransport struct {
	host           host.Host
	dht            *dht.IpfsDHT
	ctx            context.Context
	cancel         context.CancelFunc
	handler        CoreEventHandler
	myUsernameHash string
	peers          map[string]*P2PeerInfo
	peersMu        sync.RWMutex
	messageHandler P2PMessageHandler
	discovery      *mdnsDiscovery
	isRunning      bool
	mu             sync.RWMutex
	core           interface {
		getP2PHashesForAnnouncement() []string
	}
}

// P2PeerInfo содержит информацию о P2P пире
type P2PeerInfo struct {
	PeerID       peer.ID
	UsernameHash string
	LastSeen     time.Time
	IsLocal      bool
	Addresses    []multiaddr.Multiaddr
	Stream       network.Stream
	StreamMu     sync.Mutex
}

// P2PMessageHandler интерфейс для обработки P2P сообщений
type P2PMessageHandler interface {
	HandleP2PMessage(packet *pb.Packet) error
	GetUsernameHash() string
}

// NewP2PTransport создает новый P2P транспорт
func NewP2PTransport(handler CoreEventHandler) (*P2PTransport, error) {
	ctx, cancel := context.WithCancel(context.Background())
	return &P2PTransport{
		ctx:     ctx,
		cancel:  cancel,
		handler: handler,
		peers:   make(map[string]*P2PeerInfo),
	}, nil
}

// Start запускает P2P транспорт
func (t *P2PTransport) Start(usernameHash string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.isRunning {
		return fmt.Errorf("P2P транспорт уже запущен")
	}

	t.myUsernameHash = usernameHash
	t.handler.OnLog(LogLevelInfo, "🌐 Запуск P2P транспорта...")

	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return fmt.Errorf("не удалось сгенерировать ключ хоста: %w", err)
	}

	cm, err := connmgr.NewConnManager(100, 400, connmgr.WithGracePeriod(time.Minute))
	if err != nil {
		return fmt.Errorf("не удалось создать connection manager: %w", err)
	}

	limiter := rcmgr.NewFixedLimiter(rcmgr.InfiniteLimits)
	rm, err := rcmgr.NewResourceManager(limiter)
	if err != nil {
		return fmt.Errorf("не удалось создать менеджер ресурсов: %w", err)
	}

	staticRelays := addrInfosFromAddrs(CustomBootstrapPeers)
	if len(staticRelays) == 0 {
		return fmt.Errorf("список bootstrap-узлов пуст, проверьте p2p_bootstrap.go")
	}

	opts := []libp2p.Option{
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings(
			"/ip4/0.0.0.0/tcp/0",
			"/ip6/::/tcp/0",
			"/ip4/0.0.0.0/udp/0/quic-v1",
			"/ip6/::/udp/0/quic-v1",
		),
		libp2p.ResourceManager(rm),
		libp2p.ConnectionManager(cm),
		libp2p.EnableHolePunching(),
		libp2p.EnableRelay(),
		libp2p.ForceReachabilityPrivate(),
		libp2p.EnableAutoRelayWithStaticRelays(staticRelays),
	}

	host, err := libp2p.New(opts...)
	if err != nil {
		return fmt.Errorf("не удалось создать libp2p хост: %w", err)
	}
	t.host = host

	t.handler.OnLog(LogLevelInfo, fmt.Sprintf("✅ P2P хост создан. PeerID: %s", host.ID().String()))
	for _, addr := range host.Addrs() {
		t.handler.OnLog(LogLevelInfo, fmt.Sprintf("📍 Listening on: %s/p2p/%s", addr, host.ID()))
	}

	kadDHT, err := dht.New(t.ctx, host, dht.Mode(dht.ModeAutoServer))
	if err != nil {
		host.Close()
		return fmt.Errorf("не удалось создать DHT: %w", err)
	}
	t.dht = kadDHT

	if err := kadDHT.Bootstrap(t.ctx); err != nil {
		host.Close()
		return fmt.Errorf("не удалось выполнить bootstrap DHT: %w", err)
	}

	for _, pi := range staticRelays {
		go func(pi peer.AddrInfo) {
			if err := host.Connect(t.ctx, pi); err == nil {
				t.handler.OnLog(LogLevelInfo, fmt.Sprintf("✅ Подключен к bootstrap узлу: %s", pi.ID))
			} else {
				t.handler.OnLog(LogLevelWarning, fmt.Sprintf("⚠️ Не удалось подключиться к bootstrap узлу %s: %v", pi.ID, err))
			}
		}(pi)
	}

	host.SetStreamHandler(protocol.ID(ProtocolID), t.handleStream)

	mdnsService := mdns.NewMdnsService(host, DiscoveryNamespace, t)
	if err := mdnsService.Start(); err != nil {
		t.handler.OnLog(LogLevelWarning, fmt.Sprintf("⚠️ Не удалось запустить mDNS: %v", err))
	} else {
		t.discovery = &mdnsDiscovery{service: mdnsService}
		t.handler.OnLog(LogLevelInfo, "✅ mDNS discovery запущен для локальной сети")
	}

	go t.discoveryLoop()
	go t.maintainPeers()

	t.isRunning = true
	t.handler.OnLog(LogLevelInfo, "🚀 P2P транспорт успешно запущен")

	return nil
}

// Stop останавливает P2P транспорт
func (t *P2PTransport) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.isRunning {
		return
	}
	t.handler.OnLog(LogLevelInfo, "🛑 Остановка P2P транспорта...")

	t.peersMu.Lock()
	for _, peer := range t.peers {
		if peer.Stream != nil {
			peer.Stream.Close()
		}
	}
	t.peers = make(map[string]*P2PeerInfo)
	t.peersMu.Unlock()

	if t.discovery != nil {
		t.discovery.service.Close()
	}

	if t.dht != nil {
		t.dht.Close()
	}

	if t.host != nil {
		t.host.Close()
	}

	t.cancel()
	t.isRunning = false
	t.handler.OnLog(LogLevelInfo, "✅ P2P транспорт остановлен")
}

// SendPacket отправляет пакет через P2P
func (t *P2PTransport) SendPacket(destHash string, packet *pb.Packet) error {
	t.mu.RLock()
	if !t.isRunning {
		t.mu.RUnlock()
		return fmt.Errorf("P2P транспорт не запущен")
	}
	t.mu.RUnlock()

	peerInfo := t.getPeer(destHash)
	if peerInfo == nil {
		t.handler.OnLog(LogLevelInfo, fmt.Sprintf("🔎 Пир %s не найден локально, ищем в DHT...", truncateHash(destHash)))
		if err := t.findPeerInDHT(destHash); err != nil {
			return fmt.Errorf("пир %s не найден в P2P сети: %w", truncateHash(destHash), err)
		}
		time.Sleep(2 * time.Second) // Даем время на установку соединения
		peerInfo = t.getPeer(destHash)
		if peerInfo == nil {
			return fmt.Errorf("не удалось установить соединение с пиром %s", truncateHash(destHash))
		}
	}
	return t.sendToPeer(peerInfo, packet)
}

// IsP2PAvailable проверяет, доступен ли пир через P2P
func (t *P2PTransport) IsP2PAvailable(peerHash string) bool {
	t.mu.RLock()
	if !t.isRunning {
		t.mu.RUnlock()
		return false
	}
	t.mu.RUnlock()
	peerInfo := t.getPeer(peerHash)
	return peerInfo != nil && peerInfo.PeerID != "" && time.Since(peerInfo.LastSeen) < 5*time.Minute
}

// GetP2PPeers возвращает список активных P2P пиров
func (t *P2PTransport) GetP2PPeers() []string {
	t.peersMu.RLock()
	defer t.peersMu.RUnlock()
	var peers []string
	for hash, info := range t.peers {
		if t.IsP2PAvailable(hash) {
			location := "глобальная сеть"
			if info.IsLocal {
				location = "локальная сеть"
			}
			peers = append(peers, fmt.Sprintf("%s (%s)", truncateHash(hash), location))
		}
	}
	return peers
}

// SetMessageHandler устанавливает обработчик сообщений
func (t *P2PTransport) SetMessageHandler(handler P2PMessageHandler) {
	t.messageHandler = handler
}

// SetCore устанавливает ссылку на Core для получения хэшей для анонса
func (t *P2PTransport) SetCore(core interface {
	getP2PHashesForAnnouncement() []string
}) {
	t.core = core
}

// handleStream обрабатывает входящий поток
func (t *P2PTransport) handleStream(stream network.Stream) {
	defer stream.Close()

	var length uint32
	if err := binary.Read(stream, binary.BigEndian, &length); err != nil {
		if err != io.EOF {
			t.handler.OnLog(LogLevelWarning, fmt.Sprintf("⚠️ Не удалось прочитать длину P2P сообщения: %v", err))
		}
		return
	}

	if length > MaxP2PMessageSize {
		t.handler.OnLog(LogLevelError, fmt.Sprintf("❌ Получено слишком большое P2P сообщение (%d байт), разрыв соединения.", length))
		stream.Reset()
		return
	}

	buffer := make([]byte, length)
	if _, err := io.ReadFull(stream, buffer); err != nil {
		t.handler.OnLog(LogLevelError, fmt.Sprintf("❌ Ошибка чтения тела P2P сообщения: %v", err))
		return
	}

	var packet pb.Packet
	if err := proto.Unmarshal(buffer, &packet); err != nil {
		t.handler.OnLog(LogLevelError, fmt.Sprintf("❌ Ошибка десериализации Protobuf пакета: %v", err))
		return
	}

	t.updatePeerInfo(packet.SourceClientIdHash, stream.Conn().RemotePeer(), stream.Conn().RemoteMultiaddr())

	if t.messageHandler != nil {
		if err := t.messageHandler.HandleP2PMessage(&packet); err != nil {
			t.handler.OnLog(LogLevelError, fmt.Sprintf("❌ Ошибка обработки P2P пакета: %v", err))
		}
	}
}

// sendToPeer отправляет сообщение конкретному пиру
func (t *P2PTransport) sendToPeer(peerInfo *P2PeerInfo, packet *pb.Packet) error {
	peerInfo.StreamMu.Lock()
	defer peerInfo.StreamMu.Unlock()

	if peerInfo.Stream == nil || peerInfo.Stream.Conn().IsClosed() {
		ctx, cancel := context.WithTimeout(t.ctx, StreamTimeout)
		defer cancel()
		stream, err := t.host.NewStream(ctx, peerInfo.PeerID, protocol.ID(ProtocolID))
		if err != nil {
			t.removePeer(peerInfo.UsernameHash)
			return fmt.Errorf("не удалось создать поток к пиру: %w", err)
		}
		peerInfo.Stream = stream
	}

	packetData, err := proto.Marshal(packet)
	if err != nil {
		return fmt.Errorf("не удалось сериализовать пакет: %w", err)
	}

	length := uint32(len(packetData))
	if err := binary.Write(peerInfo.Stream, binary.BigEndian, length); err != nil {
		peerInfo.Stream.Reset()
		peerInfo.Stream = nil
		t.removePeer(peerInfo.UsernameHash)
		return fmt.Errorf("не удалось отправить длину сообщения: %w", err)
	}

	if _, err := peerInfo.Stream.Write(packetData); err != nil {
		peerInfo.Stream.Reset()
		peerInfo.Stream = nil
		t.removePeer(peerInfo.UsernameHash)
		return fmt.Errorf("не удалось отправить тело сообщения: %w", err)
	}

	t.handler.OnLog(LogLevelInfo, fmt.Sprintf("✉️ P2P сообщение (%d байт) отправлено пиру %s", length, truncateHash(peerInfo.UsernameHash)))
	return nil
}

// discoveryLoop периодически анонсирует себя в сети
func (t *P2PTransport) discoveryLoop() {
	ticker := time.NewTicker(DiscoveryInterval)
	defer ticker.Stop()

	time.Sleep(15 * time.Second)
	t.announceSelf()

	for {
		select {
		case <-ticker.C:
			t.announceSelf()
		case <-t.ctx.Done():
			return
		}
	}
}

// createDiscoveryCID создает CID для обнаружения в DHT
func createDiscoveryCID(hash string) (cid.Cid, error) {
	prefixedHash := "phantom-discovery-" + hash
	mh, err := multihash.Sum([]byte(prefixedHash), multihash.SHA2_256, -1)
	if err != nil {
		return cid.Undef, err
	}
	return cid.NewCidV1(cid.Raw, mh), nil
}

// announceSelf анонсирует все известные контакты
func (t *P2PTransport) announceSelf() {
	if t.dht == nil || t.myUsernameHash == "" || t.dht.RoutingTable().Size() == 0 {
		return
	}

	var allHashes []string
	if t.core != nil {
		allHashes = t.core.getP2PHashesForAnnouncement()
	} else if t.myUsernameHash != "" {
		allHashes = []string{t.myUsernameHash}
	}

	if len(allHashes) == 0 {
		return
	}

	successCount := 0
	for _, hash := range allHashes {
		ctx, cancel := context.WithTimeout(t.ctx, 45*time.Second)
		discoveryCID, err := createDiscoveryCID(hash)
		if err != nil {
			cancel()
			continue
		}
		if err := t.dht.Provide(ctx, discoveryCID, true); err == nil {
			successCount++
		}
		cancel()
	}
	if successCount > 0 {
		t.handler.OnLog(LogLevelInfo, fmt.Sprintf("📢 Успешно анонсировано %d хэш(ей) в DHT", successCount))
	}
}

// findPeerInDHT ищет пира в DHT
func (t *P2PTransport) findPeerInDHT(usernameHash string) error {
	if t.dht == nil {
		return fmt.Errorf("DHT не инициализирован")
	}

	discoveryCID, err := createDiscoveryCID(usernameHash)
	if err != nil {
		return fmt.Errorf("не удалось создать CID для поиска: %w", err)
	}

	ctx, cancel := context.WithTimeout(t.ctx, 60*time.Second)
	defer cancel()

	t.handler.OnLog(LogLevelInfo, fmt.Sprintf("🔎 Поиск провайдеров для CID: %s...", discoveryCID.String()))
	providers := t.dht.FindProvidersAsync(ctx, discoveryCID, 5)

	var providerFound bool
	for p := range providers {
		if p.ID == t.host.ID() {
			continue // Пропускаем себя
		}

		t.handler.OnLog(LogLevelInfo, fmt.Sprintf("✅ Найден потенциальный пир %s для %s", p.ID, truncateHash(usernameHash)))
		connectCtx, connectCancel := context.WithTimeout(ctx, 30*time.Second)
		if err := t.host.Connect(connectCtx, p); err != nil {
			t.handler.OnLog(LogLevelWarning, fmt.Sprintf("⚠️ Не удалось подключиться к найденному пиру %s: %v", p.ID, err))
			connectCancel()
			continue
		}
		connectCancel()

		t.handler.OnLog(LogLevelInfo, fmt.Sprintf("✅ Успешное подключение к пиру %s", p.ID))
		t.updatePeerInfo(usernameHash, p.ID, p.Addrs...)
		providerFound = true
		break // Достаточно одного успешного подключения
	}

	if !providerFound {
		return fmt.Errorf("пир не найден в DHT")
	}
	return nil
}

// updatePeerInfo обновляет информацию о пире
func (t *P2PTransport) updatePeerInfo(usernameHash string, peerID peer.ID, addrs ...multiaddr.Multiaddr) {
	t.peersMu.Lock()
	defer t.peersMu.Unlock()

	isLocal := false
	if len(addrs) > 0 {
		for _, addr := range addrs {
			if isLocalAddress(addr.String()) {
				isLocal = true
				break
			}
		}
	}

	if info, exists := t.peers[usernameHash]; exists {
		info.LastSeen = time.Now()
		info.PeerID = peerID
		for _, addr := range addrs {
			if !containsAddr(info.Addresses, addr) {
				info.Addresses = append(info.Addresses, addr)
			}
		}
		if isLocal {
			info.IsLocal = true
		}
	} else {
		t.peers[usernameHash] = &P2PeerInfo{
			PeerID:       peerID,
			UsernameHash: usernameHash,
			LastSeen:     time.Now(),
			IsLocal:      isLocal,
			Addresses:    addrs,
		}
		location := "глобальной"
		if isLocal {
			location = "локальной"
		}
		t.handler.OnLog(LogLevelInfo, fmt.Sprintf("🔗 Новый P2P пир %s обнаружен в %s сети", truncateHash(usernameHash), location))
	}
}

// getPeer возвращает информацию о пире
func (t *P2PTransport) getPeer(usernameHash string) *P2PeerInfo {
	t.peersMu.RLock()
	defer t.peersMu.RUnlock()
	return t.peers[usernameHash]
}

// removePeer удаляет пира из списка
func (t *P2PTransport) removePeer(usernameHash string) {
	t.peersMu.Lock()
	defer t.peersMu.Unlock()
	delete(t.peers, usernameHash)
}

// cleanupPeers удаляет устаревших пиров
func (t *P2PTransport) cleanupPeers() {
	t.peersMu.Lock()
	defer t.peersMu.Unlock()

	cutoff := time.Now().Add(-5 * time.Minute)
	for hash, info := range t.peers {
		if info.LastSeen.Before(cutoff) {
			if info.Stream != nil {
				info.Stream.Close()
			}
			delete(t.peers, hash)
			t.handler.OnLog(LogLevelInfo, fmt.Sprintf("🗑️ Пир %s удален (неактивен)", truncateHash(hash)))
		}
	}
}

// maintainPeers поддерживает соединения с пирами
func (t *P2PTransport) maintainPeers() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			t.cleanupPeers()
		case <-t.ctx.Done():
			return
		}
	}
}

// mdnsDiscovery обертка для mDNS сервиса
type mdnsDiscovery struct {
	service mdns.Service
}

// HandlePeerFound вызывается когда mDNS находит пира
func (t *P2PTransport) HandlePeerFound(pi peer.AddrInfo) {
	if pi.ID == t.host.ID() {
		return
	}
	ctx, cancel := context.WithTimeout(t.ctx, 10*time.Second)
	defer cancel()
	if err := t.host.Connect(ctx, pi); err == nil {
		t.handler.OnLog(LogLevelInfo, fmt.Sprintf("📡 Обнаружен и подключен локальный пир через mDNS: %s", pi.ID))
	}
}

// ForceFindPeer принудительно ищет пира в DHT
func (t *P2PTransport) ForceFindPeer(usernameHash string) {
	t.mu.RLock()
	if !t.isRunning {
		t.mu.RUnlock()
		return
	}
	t.mu.RUnlock()

	// ОПТИМИЗАЦИЯ: Если пир уже виден (скорее всего через mDNS), не делаем ничего.
	if t.IsP2PAvailable(usernameHash) {
		t.handler.OnLog(LogLevelInfo, fmt.Sprintf("✅ Пир %s... уже доступен, глобальный поиск пропущен.", truncateHash(usernameHash)))
		return
	}

	go func() {
		t.handler.OnLog(LogLevelInfo, fmt.Sprintf("🚀 Принудительный поиск пира %s в DHT...", truncateHash(usernameHash)))
		_ = t.findPeerInDHT(usernameHash)
	}()
}

// --- Вспомогательные функции ---

func isLocalAddress(addr string) bool {
	return containsAny(addr, []string{
		"/ip4/192.168.", "/ip4/10.", "/ip4/172.16.", "/ip4/172.17.", "/ip4/172.18.",
		"/ip4/172.19.", "/ip4/172.20.", "/ip4/172.21.", "/ip4/172.22.", "/ip4/172.23.",
		"/ip4/172.24.", "/ip4/172.25.", "/ip4/172.26.", "/ip4/172.27.", "/ip4/172.28.",
		"/ip4/172.29.", "/ip4/172.30.", "/ip4/172.31.", "/ip4/127.", "/ip6/::1/",
		"/ip6/fe80::", "/ip6/fc00::", "/ip6/fd00::",
	})
}

func containsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if strings.HasPrefix(s, substr) {
			return true
		}
	}
	return false
}

func containsAddr(addrs []multiaddr.Multiaddr, addr multiaddr.Multiaddr) bool {
	for _, a := range addrs {
		if a.Equal(addr) {
			return true
		}
	}
	return false
}
