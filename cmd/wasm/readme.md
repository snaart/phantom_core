# Phantom WebAssembly (WASM) Module

## Описание

Этот модуль компилирует ядро `phantomcore` в бинарный файл WebAssembly (`.wasm`), предназначенный для выполнения непосредственно в веб-браузере. Это позволяет создавать полностью клиентские веб-приложения, где вся криптография и P2P-логика работают на стороне пользователя, обеспечивая максимальный уровень безопасности и децентрализации.

## Ключевые возможности

-   **End-to-End шифрование в браузере:** Приватные ключи никогда не покидают машину пользователя.
-   **Децентрализация:** Может подключаться к P2P-сети Phantom через WebTransport и WebRTC без необходимости в центральном сервере-посреднике.
-   **Простота развертывания:** Для работы нужен только статический веб-сервер (HTML, JS, CSS, WASM).

## Сборка

Находясь в корневой директории проекта, выполните:

```bash
GOOS=js GOARCH=wasm go build -o static/phantom.wasm ./cmd/phantom_wasm
```

Эта команда создаст файл `phantom.wasm` в директории `static/`. Вам также понадобится файл `wasm_exec.js` из вашей Go-инсталляции:

```bash
cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" static/
```

## Использование

WASM-модуль загружается и инициализируется в JavaScript.

**Пример `index.html`:**

```html
<html>
<head>
    <script src="wasm_exec.js"></script>
    <script>
        const go = new Go();
        WebAssembly.instantiateStreaming(fetch("phantom.wasm"), go.importObject).then((result) => {
            go.run(result.instance);
            // Теперь можно вызывать Go-функции, зарегистрированные в main.go
            // например, sendMessageToGo("PEER_HASH", "Hello from browser!");
        });
    </script>
</head>
<body><h1>Phantom WASM Client</h1></body>
</html>
```

## Для кого это?

-   **Веб-разработчики:** Для создания ультимативно безопасных и децентрализованных веб-клиентов.
-   **Проекты, ориентированные на приватность:** Где требуется минимизировать доверие к серверной инфраструктуре.