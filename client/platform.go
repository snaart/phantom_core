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
	"runtime"
)

// Определение платформы для оптимизации P2P конфигурации

// isAndroid проверяет, работаем ли мы на Android
func isAndroid() bool {
	// Android обычно имеет GOOS=android при правильной сборке
	// Также можно проверить через переменные окружения
	return runtime.GOOS == "android"
}

// isIOS проверяет, работаем ли мы на iOS
func isIOS() bool {
	// iOS имеет GOOS=ios или darwin с дополнительными проверками
	if runtime.GOOS == "ios" {
		return true
	}
	// На iOS через gomobile обычно GOOS=darwin, но GOARCH=arm64
	if runtime.GOOS == "darwin" && (runtime.GOARCH == "arm64" || runtime.GOARCH == "arm") {
		// Дополнительная проверка для iOS
		// В реальном приложении можно использовать build tags
		return false // По умолчанию считаем macOS на ARM
	}
	return false
}

// isMobile проверяет, мобильная ли платформа
func isMobile() bool {
	return isAndroid() || isIOS()
}

// isDesktop проверяет, десктопная ли платформа
func isDesktop() bool {
	switch runtime.GOOS {
	case "windows", "darwin", "linux":
		return !isMobile()
	default:
		return false
	}
}

// getP2POptimizations возвращает оптимизации для P2P в зависимости от платформы
func getP2POptimizations() P2POptimizations {
	opts := P2POptimizations{
		EnableMDNS:         true,
		EnableDHT:          true,
		EnableRelay:        true,
		EnableNATTraversal: true,
		MaxConnections:     50,
		KeepAliveInterval:  30,
	}

	if isMobile() {
		// Мобильные оптимизации для экономии батареи
		opts.EnableMDNS = false     // mDNS может не работать на мобильных
		opts.EnableRelay = false    // Relay потребляет батарею
		opts.MaxConnections = 10    // Меньше соединений
		opts.KeepAliveInterval = 60 // Реже пинги
	}

	if isAndroid() {
		// Android-специфичные настройки
		opts.EnableMDNS = false // Android ограничивает multicast
	}

	if isIOS() {
		// iOS-специфичные настройки
		opts.EnableMDNS = false         // iOS ограничивает mDNS
		opts.EnableNATTraversal = false // iOS имеет строгие NAT правила
	}

	return opts
}

// P2POptimizations содержит оптимизации для P2P
type P2POptimizations struct {
	EnableMDNS         bool
	EnableDHT          bool
	EnableRelay        bool
	EnableNATTraversal bool
	MaxConnections     int
	KeepAliveInterval  int // в секундах
}
