package main

import (
	"bufio"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"hellman/hellman"
)

var (
	shutdownSignal = make(chan os.Signal, 1)
)

func main() {
	client, err := hellman.New()
	if err != nil {
		log.Fatalf("error creating client: %s", err.Error())
	}

	conn, err := net.Dial("tcp", "localhost:5555")
	if err != nil {
		log.Fatalf("error connecting: %s", err.Error())
	}
	defer conn.Close()
	log.Println("Connected to server")

	signal.Notify(shutdownSignal, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-shutdownSignal
		log.Println("Shutting down client...")
		conn.Close()
		os.Exit(0)
	}()

	publicKey := client.PublicKey().String()
	if _, err = conn.Write([]byte(publicKey + ";")); err != nil {
		log.Fatalf("error sending public key: %s", err.Error())
	}
	log.Println("Sent to server: ", publicKey[:10])

	serverPublicKey, err := bufio.NewReader(conn).ReadBytes(';')
	if err != nil {
		log.Fatalf("error reading server's public key: %s", err.Error())
	}
	serverPubKey := new(big.Int)
	serverPubKey.SetString(string(serverPublicKey), 10)
	log.Println("Received from server: ", serverPubKey.String()[:10])

	privateKey, err := client.GenPrivateKey(serverPubKey)
	if err != nil {
		log.Fatalf("failed to generate private key from server's public key: %s", err.Error())
	}
	log.Println("Generated private key: ", privateKey)

	for {
		log.Print("Enter a message: ")
		message, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			log.Fatalf("error reading input: %s", err.Error())
		}
		message = strings.TrimSpace(message)

		encryptedMessage, err := hellman.DES3Encode(message, privateKey)
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

		response, err := bufio.NewReader(conn).ReadBytes(';')
		if err != nil {
			log.Println(err.Error())
			return
		}

		receivedHMAC := strings.TrimSpace(string(response[:64]))
		receivedPayload := string(response[64 : len(response)-1])

		ok, err := hellman.VerifyHMAC(receivedHMAC, privateKey, receivedPayload)
		if err != nil {
			log.Printf("error verified message from server: %s", err.Error())
			continue
		}

		if ok {
			receivedMsg, err := hellman.DES3Decode(receivedPayload, privateKey)
			if err != nil {
				log.Printf("failed to decrypt message: %s", err.Error())
				continue
			}

			log.Printf("server response: %s", receivedMsg)
		}
	}
}
