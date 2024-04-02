package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"hellman/hellman"
)

func main() {
	l, err := net.Listen("tcp", ":5555")
	if err != nil {
		log.Fatalf("error listening: %s", err.Error())
	}
	defer l.Close()
	log.Println("Server started and ready to listen")

	shutdownSignal := make(chan os.Signal, 1)
	signal.Notify(shutdownSignal, syscall.SIGINT, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var connClosed bool
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				if connClosed {
					return
				}
				log.Printf("error accepting connection: %s", err.Error())
				return
			}

			go handleConnection(ctx, conn)
		}
	}()

	<-shutdownSignal
	connClosed = true
	log.Println("Received shutdown signal. Closing server...")
	cancel()
}

func handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()

	alg, err := hellman.New()
	if err != nil {
		log.Printf("Error creating hellman for client %s: %s", clientAddr, err.Error())
		return
	}

	clientPubKey, err := bufio.NewReader(conn).ReadBytes(';')
	if err != nil {
		log.Printf("Error reading client's %s public key: %s", clientAddr, err.Error())
		return
	}
	pubKey := new(big.Int)
	pubKey.SetString(string(clientPubKey), 10)
	log.Printf("Received from client %s: %s", clientAddr, pubKey.String()[:10])

	serverPubKey := alg.PublicKey().String()
	if _, err = conn.Write([]byte(serverPubKey + ";")); err != nil {
		log.Printf("error sending public key: %s", err.Error())
		return
	}
	log.Printf("Sent to client %s: %s", clientAddr, serverPubKey[:10])

	privateKey, err := alg.GenPrivateKey(pubKey)
	if err != nil {
		log.Printf("fail to generate private key from client's (%s) public key: %s", clientAddr, err.Error())
		return
	}
	log.Printf("Generated private key for client %s: %s", clientAddr, privateKey)

	go func() {
		<-ctx.Done()
		log.Printf("Closing client connection %s", clientAddr)
		conn.Close()
	}()

	for {
		message, err := bufio.NewReader(conn).ReadBytes(';')
		if err != nil {
			if errors.Is(err, io.EOF) {
				log.Printf("client %s disconnected", clientAddr)
			} else {
				log.Printf("error reading client's public key: %s", err.Error())
			}
			return
		}
		log.Printf("client %s message accepted", clientAddr)

		receivedHMAC := strings.TrimSpace(string(message[:64]))
		receivedPayload := string(message[64 : len(message)-1])

		ok, err := hellman.VerifyHMAC(receivedHMAC, privateKey, receivedPayload)
		if err != nil {
			log.Printf("error verified message: %s, for client %s", err.Error(), clientAddr)
			continue
		}

		if ok {
			receivedMsg, err := hellman.DES3Decode(receivedPayload, privateKey)
			if err != nil {
				log.Printf("failed to decrypt message: %s, for client %s", err.Error(), clientAddr)
				continue
			}
			log.Printf("client %s received message: %s", clientAddr, receivedMsg)

			encryptedMessage, err := hellman.DES3Encode(fmt.Sprintf("received: %s", receivedMsg), privateKey)
			if err != nil {
				log.Fatalf("failed to encrypt message: %s", err.Error())
			}

			HMAC, err := hellman.HashSHA256WithHMAC(encryptedMessage, privateKey)
			if err != nil {
				log.Fatal(err)
			}

			if _, err = conn.Write([]byte(HMAC + encryptedMessage + ";")); err != nil {
				log.Fatalf("error sending message to server: %s", err.Error())
			}
		}
	}
}
