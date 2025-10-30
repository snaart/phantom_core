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
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	serverAddress = "{ip_example}"

	// Таймауты для подключения
	connectTimeoutTCP  = 10 * time.Second
	connectTimeoutQUIC = 5 * time.Second
)

// quicStreamConn адаптер для QUIC stream к net.Conn интерфейсу.
type quicStreamConn struct {
	stream     quic.Stream
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *quicStreamConn) Read(b []byte) (n int, err error)  { return c.stream.Read(b) }
func (c *quicStreamConn) Write(b []byte) (n int, err error) { return c.stream.Write(b) }
func (c *quicStreamConn) Close() error                      { return c.stream.Close() }
func (c *quicStreamConn) LocalAddr() net.Addr               { return c.localAddr }
func (c *quicStreamConn) RemoteAddr() net.Addr              { return c.remoteAddr }
func (c *quicStreamConn) SetDeadline(t time.Time) error     { return c.stream.SetDeadline(t) }
func (c *quicStreamConn) SetReadDeadline(t time.Time) error { return c.stream.SetReadDeadline(t) }
func (c *quicStreamConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

// quicConnCloser — это обертка для quic.Connection, реализующая интерфейс io.Closer.
//type quicConnCloser struct {
//	conn quic.Connection
//}
//
//// Close реализует io.Closer.
//func (q *quicConnCloser) Close() error {
//	return q.conn.CloseWithError(0, "connection closed by client")
//}

// createTCPConnection создает обычное TCP соединение.
func createTCPConnection(tlsConfig *tls.Config, timeout time.Duration, handler CoreEventHandler) (*grpc.ClientConn, error) {
	handler.OnLog(LogLevelInfo, "📡 [TCP] Начало установки TCP соединения...")
	creds := credentials.NewTLS(tlsConfig)

	conn, err := grpc.NewClient(
		serverAddress,
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(10*1024*1024)),
	)
	if err != nil {
		handler.OnLog(LogLevelError, fmt.Sprintf("❌ [TCP] Ошибка NewClient: %v", err))
		return nil, fmt.Errorf("создание TCP клиента: %w", err)
	}

	if err := forceConnection(conn, timeout, handler); err != nil {
		err := conn.Close()
		if err != nil {
			return nil, err
		}
		handler.OnLog(LogLevelError, fmt.Sprintf("❌ [TCP] Ошибка forceConnection: %v", err))
		return nil, fmt.Errorf("установка TCP соединения: %w", err)
	}
	handler.OnLog(LogLevelInfo, "✅ [TCP] Соединение установлено и проверено.")
	return conn, nil
}

// createQUICConnection создает QUIC соединение и gRPC клиент поверх него.
//func createQUICConnection(tlsConfig *tls.Config, timeout time.Duration, handler CoreEventHandler) (*grpc.ClientConn, io.Closer, error) {
//	handler.OnLog(LogLevelInfo, "🚀 [QUIC] Начало установки QUIC соединения...")
//	tlsConfig = tlsConfig.Clone()
//	tlsConfig.NextProtos = []string{"h3"}
//	handler.OnLog(LogLevelInfo, fmt.Sprintf("🚀 [QUIC] TLS Config подготовлен. ServerName: '%s', NextProtos: %v", tlsConfig.ServerName, tlsConfig.NextProtos))
//
//	quicConfig := &quic.Config{
//		MaxIdleTimeout:       30 * time.Second,
//		KeepAlivePeriod:      10 * time.Second,
//		HandshakeIdleTimeout: 10 * time.Second,
//	}
//
//	ctx, cancel := context.WithTimeout(context.Background(), timeout)
//	defer cancel()
//
//	handler.OnLog(LogLevelInfo, fmt.Sprintf("🚀 [QUIC] Попытка набора адреса (DialAddr) %s с таймаутом %v...", serverAddress, timeout))
//	quicConn, err := quic.DialAddr(ctx, serverAddress, tlsConfig, quicConfig)
//	if err != nil {
//		handler.OnLog(LogLevelError, fmt.Sprintf("❌ [QUIC] Ошибка DialAddr: %v", err))
//		return nil, nil, fmt.Errorf("не удалось установить QUIC соединение: %w", err)
//	}
//	handler.OnLog(LogLevelInfo, fmt.Sprintf("✅ [QUIC] DialAddr успешно завершен. RemoteAddr: %s, LocalAddr: %s", quicConn.RemoteAddr(), quicConn.LocalAddr()))
//
//	handler.OnLog(LogLevelInfo, "🚀 [QUIC] Создание gRPC клиента с кастомным диалером...")
//	grpcConn, err := grpc.NewClient(
//		serverAddress,
//		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
//			handler.OnLog(LogLevelInfo, "🚀 [QUIC Dialer] Попытка открыть новый stream...")
//			stream, err := quicConn.OpenStreamSync(ctx)
//			if err != nil {
//				handler.OnLog(LogLevelError, fmt.Sprintf("❌ [QUIC Dialer] Не удалось открыть stream: %v", err))
//				return nil, fmt.Errorf("не удалось открыть QUIC stream для gRPC: %w", err)
//			}
//			handler.OnLog(LogLevelInfo, "✅ [QUIC Dialer] Stream успешно открыт.")
//			return &quicStreamConn{
//				stream:     stream,
//				localAddr:  quicConn.LocalAddr(),
//				remoteAddr: quicConn.RemoteAddr(),
//			}, nil
//		}),
//		grpc.WithTransportCredentials(insecure.NewCredentials()),
//		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(10*1024*1024)),
//	)
//	if err != nil {
//		handler.OnLog(LogLevelError, fmt.Sprintf("❌ [QUIC] Ошибка создания gRPC клиента поверх QUIC: %v", err))
//		quicConn.CloseWithError(1, "gRPC setup failed")
//		return nil, nil, fmt.Errorf("не удалось создать gRPC клиент через QUIC: %w", err)
//	}
//	handler.OnLog(LogLevelInfo, "✅ [QUIC] gRPC клиент успешно создан.")
//
//	if err := forceConnection(grpcConn, timeout, handler); err != nil {
//		handler.OnLog(LogLevelError, fmt.Sprintf("❌ [QUIC] Тестовый gRPC вызов не удался: %v", err))
//		grpcConn.Close()
//		quicConn.CloseWithError(1, "gRPC test failed")
//		return nil, nil, fmt.Errorf("тест QUIC соединения: %w", err)
//	}
//
//	handler.OnLog(LogLevelInfo, "✅ QUIC соединение установлено и проверено успешно")
//	return grpcConn, &quicConnCloser{conn: quicConn}, nil
//}

// tryConnect пытается подключиться с учетом выбранного транспорта.
// Возвращает gRPC соединение, io.Closer для низкоуровневого транспорта и имя транспорта.
func tryConnect(transport TransportProtocol, tlsConfig *tls.Config, handler CoreEventHandler) (*grpc.ClientConn, io.Closer, string, error) {
	switch transport {
	case TCP:
		handler.OnLog(LogLevelInfo, "🔌 Попытка подключения через TCP...")
		conn, err := createTCPConnection(tlsConfig, connectTimeoutTCP, handler)
		if err != nil {
			return nil, nil, "", fmt.Errorf("TCP подключение не удалось: %w", err)
		}
		return conn, nil, "TCP", nil
	//case QUIC:
	//	handler.OnLog(LogLevelInfo, "🔌 Попытка подключения через QUIC...")
	//	conn, quicCloser, err := createQUICConnection(tlsConfig, connectTimeoutQUIC, handler)
	//	if err != nil {
	//		return nil, nil, "", fmt.Errorf("QUIC подключение не удалось: %w", err)
	//	}
	//	return conn, quicCloser, "QUIC", nil
	case Auto:
		//handler.OnLog(LogLevelInfo, "🔌 Автоматический выбор транспорта: сначала QUIC, затем TCP...")
		//conn, quicCloser, err := createQUICConnection(tlsConfig, connectTimeoutQUIC, handler)
		//if err == nil {
		//	handler.OnLog(LogLevelInfo, "✅ Успешно подключено через QUIC (основной канал)")
		//	return conn, quicCloser, "QUIC", nil
		//}
		//handler.OnLog(LogLevelWarning, fmt.Sprintf("⚠️ QUIC не удался: %v", err))
		handler.OnLog(LogLevelInfo, "📡 Переключение на резервный канал TCP...")
		tcpConn, err := createTCPConnection(tlsConfig, connectTimeoutTCP, handler)
		if err != nil {
			return nil, nil, "", fmt.Errorf("оба канала не удались. QUIC: см. выше, TCP: %w", err)
		}
		handler.OnLog(LogLevelInfo, "✅ Успешно подключено через TCP (резервный канал)")
		return tcpConn, nil, "TCP", nil
	default:
		return nil, nil, "", fmt.Errorf("неизвестный транспортный протокол: %v", transport)
	}
}

// loadTLSCredentials загружает TLS сертификат и создает конфигурацию.
func loadTLSCredentials(handler CoreEventHandler) (*tls.Config, error) {
	handler.OnLog(LogLevelInfo, "🔐 [TLS] Начало загрузки TLS сертификатов...")
	certPath := "server.crt"
	pemServerCA, err := os.ReadFile(certPath)
	if err != nil {
		handler.OnLog(LogLevelWarning, fmt.Sprintf("⚠️  ВНИМАНИЕ: Файл '%s' не найден.", certPath))
		handler.OnLog(LogLevelInfo, "   Для безопасного соединения необходимо сначала запустить сервер,")
		handler.OnLog(LogLevelInfo, "   чтобы он сгенерировал этот файл, а затем скопировать его")
		handler.OnLog(LogLevelInfo, "   в директорию с клиентом.")
		return nil, fmt.Errorf("файл '%s' не найден: %w", certPath, err)
	}
	handler.OnLog(LogLevelInfo, fmt.Sprintf("✅ [TLS] Файл %s найден, размер: %d байт", certPath, len(pemServerCA)))

	block, _ := pem.Decode(pemServerCA)
	if block == nil {
		handler.OnLog(LogLevelError, "❌ [TLS] Не удалось декодировать PEM блок из server.crt")
		return nil, errors.New("не удалось декодировать PEM блок")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		handler.OnLog(LogLevelError, fmt.Sprintf("❌ [TLS] Не удалось парсить сертификат: %v", err))
		return nil, fmt.Errorf("не удалось парсить сертификат: %w", err)
	}
	handler.OnLog(LogLevelInfo, "📋 [TLS] Информация из сертификата server.crt:")
	handler.OnLog(LogLevelInfo, fmt.Sprintf("   > Subject: %s", cert.Subject.String()))
	handler.OnLog(LogLevelInfo, fmt.Sprintf("   > Issuer: %s", cert.Issuer.String()))
	handler.OnLog(LogLevelInfo, fmt.Sprintf("   > Срок действия: с %v по %v", cert.NotBefore, cert.NotAfter))
	handler.OnLog(LogLevelInfo, fmt.Sprintf("   > Имена DNS: %v", cert.DNSNames))
	handler.OnLog(LogLevelInfo, fmt.Sprintf("   > IP адреса: %v", cert.IPAddresses))

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pemServerCA) {
		handler.OnLog(LogLevelError, "❌ [TLS] Не удалось добавить сертификат сервера в пул доверенных.")
		return nil, errors.New("не удалось добавить сертификат сервера в пул")
	}
	handler.OnLog(LogLevelInfo, "✅ [TLS] Сертификат успешно добавлен в пул доверенных.")

	serverName := strings.Split(serverAddress, ":")[0]
	handler.OnLog(LogLevelInfo, fmt.Sprintf("ℹ️ [TLS] Имя хоста из адреса сервера: %s", serverName))

	if len(cert.DNSNames) > 0 {
		serverName = cert.DNSNames[0]
		handler.OnLog(LogLevelInfo, fmt.Sprintf("⚠️ [TLS] В сертификате найдено DNS-имя. Используется ServerName: %s", serverName))
	} else if len(cert.IPAddresses) > 0 {
		foundMatch := false
		for _, ip := range cert.IPAddresses {
			if ip.String() == serverName {
				foundMatch = true
				break
			}
		}
		if !foundMatch {
			handler.OnLog(LogLevelWarning, fmt.Sprintf("⚠️ [TLS] IP-адрес '%s' из адреса сервера не найден в сертификате %v. Используется первый IP из сертификата: %s", serverName, cert.IPAddresses, cert.IPAddresses[0].String()))
			serverName = cert.IPAddresses[0].String()
		}
	} else {
		handler.OnLog(LogLevelWarning, "⚠️ [TLS] В сертификате нет ни DNS-имен, ни IP-адресов. Верификация может быть ненадёжной.")
	}

	config := &tls.Config{
		RootCAs:            certPool,
		MinVersion:         tls.VersionTLS13,
		ServerName:         serverName,
		InsecureSkipVerify: true,
	}

	handler.OnLog(LogLevelInfo, fmt.Sprintf("✅ [TLS] TLS конфигурация создана (ServerName: %s, MinVersion: TLS 1.3)", config.ServerName))
	return config, nil
}
