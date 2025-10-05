// p2p_bootstrap.go

package phantomcore

import (
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// CustomBootstrapPeers содержит список ваших личных bootstrap- и relay-узлов.
var CustomBootstrapPeers []multiaddr.Multiaddr

// ЗАМЕНИТЕ ЭТОТ АДРЕС НА АДРЕС ВАШЕГО СЕРВЕРА
const myBootstrapNode = "/ip4/80.74.27.30/tcp/4001/p2p/12D3KooWAztrFtmsKXKgc14D9YaqphGZxndoA63pjCDJ8qPfaLZJ"

func init() {
	// Создаем наш главный узел
	addr, err := multiaddr.NewMultiaddr(myBootstrapNode)
	if err != nil {
		panic(err)
	}

	// Начинаем список с НАШЕГО узла, делая его приоритетным
	CustomBootstrapPeers = []multiaddr.Multiaddr{addr}

	// ДОБАВЛЯЕМ публичные узлы как запасной вариант для построения здоровой DHT
	CustomBootstrapPeers = append(CustomBootstrapPeers, dht.DefaultBootstrapPeers...)
}

// addrInfosFromAddrs преобразует multiaddrs в AddrInfo.
func addrInfosFromAddrs(addrs []multiaddr.Multiaddr) []peer.AddrInfo {
	var pis []peer.AddrInfo
	for _, addr := range addrs {
		pi, err := peer.AddrInfoFromP2pAddr(addr)
		if err == nil {
			pis = append(pis, *pi)
		}
	}
	return pis
}
