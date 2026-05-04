# WebAPI Documentation - Phantom Secure Messenger

**Версия:** 0.3 
**Последнее обновление:** 28 ноября 2025 г.

## Содержание

1. [Обзор](#обзор)
2. [Архитектура](#архитектура)
3. [API Endpoints](#api-endpoints)
4. [WebSocket Events](#websocket-events)
5. [Запуск WebAPI Server](#запуск-webapi-server)
6. [Примеры Использования](#примеры-использования)

---

## Обзор

WebAPI Server предоставляет HTTP/WebSocket интерфейс к Phantom Core, позволяя веб-приложениям взаимодействовать с защищенным мессенджером.

### Ключевые Возможности

- **REST API**: Управление контактами, отправка сообщений, получение истории
- **WebSocket**: Real-time события (новые сообщения, изменения статуса подключения)
- **CORS Support**: Настроено для локальной разработки
- **Event Broadcasting**: Все события Core транслируются подключенным клиентам

---

## Архитектура

```
┌─────────────────┐
│  Web Client     │
│  (Browser)      │
└────────┬────────┘
         │ HTTP/WS
         ▼
┌─────────────────┐
│  WebAPIServer   │◄─── WebAPIEventHandler
│  (HTTP/WS)      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Phantom Core   │
│  (Logic, DB)    │
└─────────────────┘
```

### Компоненты

#### WebAPIServer

- HTTP сервер на базе `gorilla/mux`
- WebSocket upgrader для real-time событий
- Управление списком подключенных клиентов
- Трансляция событий через `BroadcastEvent()`

#### WebAPIEventHandler

- Реализует `CoreEventHandler`
- Мост между Core событиями и WebSocket клиентами
- Обрабатывает:
  - OnMessageReceived
  - OnContactListUpdated
  - OnSessionEstablished
  - OnConnectionStateChanged
  - OnLog
  - OnShutdown
  - OnP2PStateChanged

---

## API Endpoints

### Base URL

```
http://localhost:8080/api
```

### 1. POST /api/init

**Описание**: Проверка статуса Core (Core уже инициализирован при запуске)

**Response:**

```json
{
  "status": "ok",
  "message": "Core is running"
}
```

---

### 2. GET /api/contacts

**Описание**: Получение списка контактов

**Response:**

```json
[
  {
    "Name": "Alice",
    "Hash": "a1b2c3...",
    "IsOnline": false,
    "SessionState": "established",
    "IsP2P": true,
    "P2PLocation": "192.168.1.5"
  }
]
```

---

### 3. POST /api/invite

**Описание**: Создание invite-кода для добавления контакта

**Request:**

```json
{
  "display_name": "My Name"
}
```

**Response:**

```json
{
  "invite_code": "phantom://invite?data=..."
}
```

---

### 4. POST /api/join

**Описание**: Обработка invite-кода и добавление контакта

**Request:**

```json
{
  "invite_code": "phantom://invite?data=..."
}
```

**Response:**

```json
{
  "status": "ok"
}
```

**Error Response:**

```json
{
  "error": "Invalid invite code"
}
```

---

### 5. POST /api/send

**Описание**: Отправка сообщения контакту

**Request:**

```json
{
  "hash": "a1b2c3...",
  "message": "Hello, Alice!"
}
```

**Response:**

```json
{
  "status": "sent"
}
```

---

### 6. GET /api/messages

**Описание**: Получение истории сообщений с контактом

**Query Parameters:**

- `hash` (required): Hash контакта

**Example:**

```
GET /api/messages?hash=a1b2c3...
```

**Response:**

```json
[
  {
    "SessionHash": "a1b2c3...",
    "Content": "Hello!",
    "Timestamp": 1701234567,
    "IsOutgoing": true
  }
]
```

---

### 7. GET /api/events

**Описание**: WebSocket endpoint для real-time событий

**Protocol**: WebSocket

**Connection:**

```javascript
const ws = new WebSocket('ws://localhost:8080/api/events');
```

---

## WebSocket Events

### Формат Сообщения

Все события имеют структуру:

```json
{
  "type": "event_type",
  "data": { ... }
}
```

### Типы Событий

#### message_received

Новое сообщение получено

```json
{
  "type": "message_received",
  "data": {
    "SessionHash": "abc123...",
    "Content": "Hello!",
    "Timestamp": 1701234567,
    "IsOutgoing": false
  }
}
```

#### contact_list_updated

Список контактов обновлен

```json
{
  "type": "contact_list_updated",
  "data": [
    { "Name": "Alice", "Hash": "...", ... }
  ]
}
```

#### session_established

Новая сессия установлена

```json
{
  "type": "session_established",
  "data": {
    "peer_hash": "abc123..."
  }
}
```

#### connection_state_changed

Состояние подключения изменено

```json
{
  "type": "connection_state_changed",
  "data": {
    "state": "connected",
    "error": ""
  }
}
```

#### log

Сообщение лога (если level >= Error)

```json
{
  "type": "log",
  "data": {
    "level": 2,
    "message": "Connection established"
  }
}
```

#### shutdown

Core завершает работу

```json
{
  "type": "shutdown",
  "data": {
    "message": "Shutting down gracefully"
  }
}
```

#### p2p_state_changed

Состояние P2P изменено

```json
{
  "type": "p2p_state_changed",
  "data": {
    "is_active": true,
    "peers": ["peer1", "peer2"]
  }
}
```

---

## Запуск WebAPI Server

### Компиляция

```bash
cd cmd/webapi
go build -o webapi-server
```

### Запуск

```bash
./webapi-server [flags]
```

### Флаги

- `--dir` - Директория для БД (default: `~/.phantom-web`)
- `--pin` - PIN для шифрования БД (default: `1234`)
- `--server` - Адрес Phantom сервера (default: `localhost:9090`)
- `--port` - Порт для WebAPI (default: `:8080`)

### Пример

```bash
./webapi-server --dir ./data --pin mypin123 --port :9000
```

---

## Примеры Использования

### JavaScript/Fetch API

#### Получение Контактов

```javascript
async function getContacts() {
  const response = await fetch('http://localhost:8080/api/contacts');
  const contacts = await response.json();
  console.log(contacts);
}
```

#### Отправка Сообщения

```javascript
async function sendMessage(hash, text) {
  const response = await fetch('http://localhost:8080/api/send', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hash, message: text })
  });
  const result = await response.json();
  return result.status === 'sent';
}
```

#### Создание Invite

```javascript
async function createInvite(displayName) {
  const response = await fetch('http://localhost:8080/api/invite', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ display_name: displayName })
  });
  const data = await response.json();
  return data.invite_code;
}
```

### WebSocket Events

```javascript
const ws = new WebSocket('ws://localhost:8080/api/events');

ws.onopen = () => {
  console.log('Connected to Phantom WebAPI');
};

ws.onmessage = (event) => {
  const message = JSON.parse(event.data);
  
  switch (message.type) {
    case 'message_received':
      console.log('New message:', message.data.Content);
      // Обновить UI
      break;
      
    case 'session_established':
      console.log('Session with', message.data.peer_hash);
      break;
      
    case 'connection_state_changed':
      console.log('Connection:', message.data.state);
      break;
  }
};

ws.onerror = (error) => {
  console.error('WebSocket error:', error);
};

ws.onclose = () => {
  console.log('Disconnected from WebAPI');
};
```

---

## Безопасность

### Локальное Использование

WebAPI Server предназначен для **локального использования**:

- Запускается на `localhost`
- Доступ только с той же машины
- CORS настроен для локальной разработки (`*`)

### Production Deployment

Для production:

1. Настроить CORS для конкретных origin
2. Добавить аутентификацию (JWT, session tokens)
3. Использовать HTTPS
4. Ограничить доступ firewall правилами

---

## Troubleshooting

### WebSocket подключение не устанавливается

- Проверьте, что WebAPI server запущен
- Убедитесь, что порт не занят другим процессом
- Проверьте browser console для CORS ошибок

### Сообщения не отправляются

- Проверьте установлена ли сессия с контактом
- Проверьте логи WebAPI server
- Убедитесь, что Phantom Core подключен к серверу/P2P

### События не приходят через WebSocket

- Убедитесь, что WebSocket соединение активно
- Проверьте network tab в DevTools
- События отправляются только для уровня LogLevelError и выше

---

## Дополнительные Ресурсы

- [README.md](../README.md) - Основная документация
- [TESTING.md](../TESTING.md) - Тестирование
- [client/webapi.go](../client/webapi.go) - Исходный код WebAPI
- [cmd/webapi/main.go](../cmd/webapi/main.go) - Entry point
