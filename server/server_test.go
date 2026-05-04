package main

import (
	"context"
	"fmt"
	"testing"

	pb "phantom/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// MockTransmitServer implements pb.Phantom_TransmitServer
type MockTransmitServer struct {
	grpc.ServerStream
	SentPackets []*pb.Packet
	RecvPackets []*pb.Packet
	RecvIndex   int
	Ctx         context.Context
}

func (m *MockTransmitServer) Send(p *pb.Packet) error {
	m.SentPackets = append(m.SentPackets, p)
	return nil
}

func (m *MockTransmitServer) Recv() (*pb.Packet, error) {
	if m.RecvIndex >= len(m.RecvPackets) {
		// Block or return error? For tests, error is easier to stop loop.
		return nil, fmt.Errorf("EOF")
	}
	p := m.RecvPackets[m.RecvIndex]
	m.RecvIndex++
	return p, nil
}

func (m *MockTransmitServer) Context() context.Context {
	if m.Ctx == nil {
		return context.Background()
	}
	return m.Ctx
}

func (m *MockTransmitServer) SetHeader(metadata.MD) error  { return nil }
func (m *MockTransmitServer) SendHeader(metadata.MD) error { return nil }
func (m *MockTransmitServer) SetTrailer(metadata.MD)       {}
func (m *MockTransmitServer) SendMsg(m_ interface{}) error { return nil }
func (m *MockTransmitServer) RecvMsg(m_ interface{}) error { return nil }

func TestPhantomServer_HandleRegistration(t *testing.T) {
	// 1. Setup
	server := newPhantomServer([]byte("test_salt_32_bytes_long_exact_len!"))
	mockStream := &MockTransmitServer{}

	// 2. Create Registration Request
	listenToken := []byte("token_123")
	req := &pb.RegistrationRequest{
		ListenTokens: [][]byte{listenToken},
	}

	// 3. Handle Registration
	// We need to call handleRegistration directly or via Transmit loop.
	// Calling directly is easier for unit test.
	clientHash := "client_hash_1"
	server.handleRegistration(clientHash, req, mockStream, "TCP")

	// 4. Verify Client Registered
	server.mu.RLock()
	client, exists := server.clients[fmt.Sprintf("%x", listenToken)]
	server.mu.RUnlock()

	if !exists {
		t.Fatal("Client not registered by ListenToken")
	}
	if client.idHash != clientHash {
		t.Errorf("Expected client hash %s, got %s", clientHash, client.idHash)
	}
}

func TestPhantomServer_RoutePacket(t *testing.T) {
	// 1. Setup
	server := newPhantomServer([]byte("test_salt_32_bytes_long_exact_len!"))

	// Register a destination client
	destToken := []byte("dest_token")
	destTokenHex := fmt.Sprintf("%x", destToken)
	destStream := &MockTransmitServer{}

	server.mu.Lock()
	server.clients[destTokenHex] = &clientInfo{
		idHash: "dest_client",
		stream: destStream,
	}
	server.mu.Unlock()

	// 2. Create Packet
	packet := &pb.Packet{
		RoutingToken: destToken,
		Payload: &pb.Packet_EncryptedMessage{
			EncryptedMessage: &pb.EncryptedMessage{
				Ciphertext: []byte("secret"),
			},
		},
	}

	// 3. Route Packet
	server.routePacket(packet)

	// 4. Verify Packet Sent to Destination
	if len(destStream.SentPackets) != 1 {
		t.Fatalf("Expected 1 packet sent to dest, got %d", len(destStream.SentPackets))
	}
	if string(destStream.SentPackets[0].GetEncryptedMessage().Ciphertext) != "secret" {
		t.Error("Packet content mismatch")
	}
}
