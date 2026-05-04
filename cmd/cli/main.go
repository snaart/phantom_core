package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	phantomcore "phantom/client"
)

// CLIHandler implements CoreEventHandler
type CLIHandler struct{}

func (h *CLIHandler) OnMessageReceived(msg phantomcore.StoredMessage) {
	fmt.Printf("\n[NEW MESSAGE] From %s: %s\n> ", msg.SessionHash, msg.Content)
}

// ...

func (h *CLIHandler) OnContactListUpdated(contacts []phantomcore.ContactInfo) {
	// fmt.Println("[EVENT] Contact list updated")
}

func (h *CLIHandler) OnSessionEstablished(peerHash string) {
	fmt.Printf("\n[EVENT] Session established with %s\n> ", peerHash)
}

func (h *CLIHandler) OnLog(level phantomcore.LogLevel, message string) {
	if level >= phantomcore.LogLevelError {
		fmt.Printf("\n[LOG] %s\n> ", message)
	}
}

func (h *CLIHandler) OnConnectionStateChanged(state string, err error) {
	if err != nil {
		fmt.Printf("\n[CONN] %s: %v\n> ", state, err)
	} else {
		// fmt.Printf("\n[CONN] %s\n> ", state)
	}
}

func (h *CLIHandler) OnShutdown(message string) {
	fmt.Printf("\n[SHUTDOWN] %s\n", message)
}

func (h *CLIHandler) OnP2PStateChanged(isActive bool, peers []string) {
	// fmt.Printf("\n[P2P] Active: %v, Peers: %d\n> ", isActive, len(peers))
}

func main() {
	homeDir, _ := os.UserHomeDir()
	defaultBaseDir := filepath.Join(homeDir, ".phantom")

	// Global flags
	// Note: We parse global flags manually or assume they come before subcommand?
	// Standard Go flag package stops at first non-flag.
	// So usage: phantom-cli [global flags] command [command flags]

	dbDir := flag.String("dir", defaultBaseDir, "Directory for database files")
	pin := flag.String("pin", "1234", "User PIN")
	server := flag.String("server", "localhost:9090", "Server address")

	flag.Parse()

	if len(flag.Args()) < 1 {
		printUsage()
		os.Exit(1)
	}

	cmd := flag.Arg(0)
	args := flag.Args()[1:]

	// Ensure directory exists
	os.MkdirAll(*dbDir, 0700)

	switch cmd {
	case "init":
		handleInit(*dbDir, *pin)
	case "invite":
		handleInvite(*dbDir, *pin, *server, args)
	case "join":
		handleJoin(*dbDir, *pin, *server, args)
	case "list":
		handleList(*dbDir, *pin, *server)
	case "send":
		handleSend(*dbDir, *pin, *server, args)
	case "read":
		handleRead(*dbDir, *pin, *server, args)
	default:
		fmt.Printf("Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: phantom-cli [flags] <command> [args]")
	fmt.Println("Commands:")
	fmt.Println("  init             Initialize account")
	fmt.Println("  invite           Generate invite code")
	fmt.Println("  join <invite>    Join using invite code")
	fmt.Println("  list             List contacts")
	fmt.Println("  send <hash> <msg> Send message")
	fmt.Println("  read <hash>      Read messages")
	fmt.Println("Flags:")
	flag.PrintDefaults()
}

func startCore(baseDir, pin, serverAddr string) *phantomcore.Core {
	handler := &CLIHandler{}
	// Username is legacy, passing "User"
	core, err := phantomcore.NewCore("User", pin, baseDir, handler)
	if err != nil {
		fmt.Printf("Failed to start core: %v\n", err)
		os.Exit(1)
	}

	// Start networking
	// For some commands we might not need networking, but it doesn't hurt.
	// We use Auto transport by default.
	go func() {
		if err := core.Start(serverAddr, phantomcore.Auto); err != nil {
			// fmt.Printf("Network error: %v\n", err)
		}
	}()

	// Give it a moment to start
	time.Sleep(100 * time.Millisecond)

	return core
}

func handleInit(baseDir, pin string) {
	// NewCore creates account if it doesn't exist
	handler := &CLIHandler{}
	_, err := phantomcore.NewCore("User", pin, baseDir, handler)
	if err != nil {
		fmt.Printf("Failed to initialize: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Initialization complete.")
}

func handleInvite(baseDir, pin, serverAddr string, args []string) {
	core := startCore(baseDir, pin, serverAddr)
	// CreateInvite returns string
	invite, err := core.CreateInvite("User") // Display name
	if err != nil {
		fmt.Printf("Failed to create invite: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Invite code:\n%s\n", invite)
}

func handleJoin(baseDir, pin, serverAddr string, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: join <invite_code>")
		os.Exit(1)
	}
	inviteCode := args[0]

	core := startCore(baseDir, pin, serverAddr)
	err := core.ProcessInvite(inviteCode)
	if err != nil {
		fmt.Printf("Failed to process invite: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Invite accepted. Contact added.")
}

func handleList(baseDir, pin, serverAddr string) {
	core := startCore(baseDir, pin, serverAddr)
	contacts, err := core.GetContacts()
	if err != nil {
		fmt.Printf("Failed to get contacts: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Contacts:")
	for _, c := range contacts {
		fmt.Printf("- %s (Hash: %s)\n", c.Name, c.Hash)
	}
}

func handleSend(baseDir, pin, serverAddr string, args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: send <hash> <message>")
		os.Exit(1)
	}
	hash := args[0]
	msg := strings.Join(args[1:], " ")

	core := startCore(baseDir, pin, serverAddr)
	err := core.SendMessage(hash, msg)
	if err != nil {
		fmt.Printf("Failed to send message: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Message sent.")
}

func handleRead(baseDir, pin, serverAddr string, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: read <hash>")
		os.Exit(1)
	}
	hash := args[0]

	core := startCore(baseDir, pin, serverAddr)
	msgs, err := core.GetMessages(hash, 50)
	if err != nil {
		fmt.Printf("Failed to read messages: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Messages with %s:\n", hash)
	for _, msg := range msgs {
		direction := "IN"
		if msg.IsOutgoing {
			direction = "OUT"
		}
		ts := time.Unix(msg.Timestamp, 0).Format(time.DateTime)
		fmt.Printf("[%s] %s: %s\n", ts, direction, msg.Content)
	}
}
