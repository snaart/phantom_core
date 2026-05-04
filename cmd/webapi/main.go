package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	phantomcore "phantom/client"
)

func main() {
	homeDir, _ := os.UserHomeDir()
	defaultBaseDir := filepath.Join(homeDir, ".phantom-web")

	dbDir := flag.String("dir", defaultBaseDir, "Directory for database files")
	pin := flag.String("pin", "1234", "User PIN")
	serverAddr := flag.String("server", "localhost:9090", "Phantom Server address")
	apiPort := flag.String("port", ":8080", "WebAPI port (e.g. :8080)")

	flag.Parse()

	// Ensure directory exists
	os.MkdirAll(*dbDir, 0700)

	// 1. Create WebAPI Server (wrapper)
	// We need to create Core first, but Core needs a handler.
	// The handler needs the WebAPIServer to broadcast events.
	// Circular dependency?
	// WebAPIServer needs Core.
	// WebAPIEventHandler needs WebAPIServer.
	// Core needs WebAPIEventHandler.

	// Solution:
	// Create WebAPIServer struct (empty core).
	// Create Handler with ref to WebAPIServer.
	// Create Core with Handler.
	// Inject Core into WebAPIServer.

	webServer := &phantomcore.WebAPIServer{} // We can't use NewWebAPIServer yet because we don't have core
	// Actually NewWebAPIServer returns a struct. We can set core later if we modify it or just construct manually.
	// Let's modify NewWebAPIServer in client/webapi.go? No, let's just construct it here or use a setter.
	// But `client` package fields might be private.
	// `WebAPIServer` fields are private (except exported methods).
	// `NewWebAPIServer` takes `*Core`.

	// Let's use a temporary nil core and set it later?
	// `NewWebAPIServer` initializes maps.
	webServer = phantomcore.NewWebAPIServer(nil)

	handler := &phantomcore.WebAPIEventHandler{
		Server: webServer,
	}

	// 2. Initialize Core
	core, err := phantomcore.NewCore("WebUser", *pin, *dbDir, handler)
	if err != nil {
		log.Fatalf("Failed to initialize Core: %v", err)
	}

	// Inject Core into WebServer
	// We need a way to set core.
	// Since `core` field in `WebAPIServer` is private (lowercase), we can't set it from `main` package.
	// I should have added a SetCore method or exported the field.
	// I will update `client/webapi.go` to add `SetCore` or export `Core`.
	// For now, let's assume I'll fix it.
	// Wait, I just wrote `client/webapi.go`. I can use `replace_file_content` to add `SetCore`.

	// Let's write this file assuming SetCore exists, then I'll add it.
	webServer.SetCore(core)

	// 3. Start Core Network
	go func() {
		log.Printf("Starting Phantom Core network on %s...", *serverAddr)
		if err := core.Start(*serverAddr, phantomcore.Auto); err != nil {
			log.Printf("Core network stopped: %v", err)
		}
	}()

	// 4. Start WebAPI Server
	go func() {
		log.Printf("Starting WebAPI on %s...", *apiPort)
		if err := webServer.Start(*apiPort); err != nil {
			log.Fatalf("WebAPI failed: %v", err)
		}
	}()

	// Wait for shutdown
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	log.Println("Shutting down...")
	webServer.Stop()
	core.Stop()
}
