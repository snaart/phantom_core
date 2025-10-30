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
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// CustomBootstrapPeers содержит список ваших личных bootstrap- и relay-узлов.
var CustomBootstrapPeers []multiaddr.Multiaddr

const myBootstrapNode = "/ip4/{ip_example}/tcp/4001/p2p/{hash_example}"

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
