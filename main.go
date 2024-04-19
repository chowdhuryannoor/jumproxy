package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"strconv"

	"golang.org/x/crypto/pbkdf2"
)

var aesKey []byte
var nonceSize = 12
var lenHeaderSize = 4

func main() {
	//define command line flags
	var keyFile string
	var listenPort string
	flag.StringVar(&keyFile, "k", "", "-k <filepath>: The file path which contains the key to encrypt/decrypt communication.")
	flag.StringVar(&listenPort, "l", "", "-l <port>: Reverse proxy mode listening on a port")

	//Parse command line flags
	flag.Parse()

	if keyFile == "" {
		log.Fatal("Valid keyfile is not provided")
	}

	//parse the key file and derive a key
	file, err := os.Open(keyFile)
	if err != nil {
		log.Fatal("Error opening the key file.", err)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	var password string
	for scanner.Scan() {
		password += scanner.Text()
	}

	if password == "" {
		log.Fatal("Empty key file.")
	}

	aesKey = pbkdf2.Key([]byte(password), []byte{}, 4096, 32, sha256.New)

	log.SetOutput(os.Stderr)

	//check additional arguments
	args := flag.Args()
	if len(args) > 2 {
		log.Fatal("Too many arguments.")
	}

	ip := args[0]
	port := args[1]

	if ip != "localhost" && net.ParseIP(ip) == nil {
		log.Fatal("Invalid IP Address.")
	}

	if isValidPort(port) {
		log.Fatal("Invalid Port Number.")
	}

	//start Jumproxy
	if listenPort == "" {
		//start in client proxy mode
		clientProxyMode(ip, port)

	} else {
		//check for valid arguments
		if isValidPort(listenPort) {
			log.Fatal("Invalid listen Port Number.")
		}

		//start in reverse proxy mode
		reverseProxyMode(ip, port, listenPort)
	}

}

func isValidPort(portStr string) bool {
	port, err := strconv.Atoi(portStr)
	if err == nil {
		return false
	}
	return port >= 1 && port <= 65535
}

func reverseProxyMode(sshIP string, sshPort string, listenPort string) {
	//create reverse proxy server
	server, err := net.Listen("tcp", ":"+listenPort)
	if err != nil {
		log.Fatal("Error starting server on listen port.")
	}
	defer server.Close()

	//accept connection and reverse proxy the traffic
	for {
		//accept the connection
		clientConn, err := server.Accept()
		if err != nil {
			log.Println("Error accepting client connection.")
		}
		log.Println("Client connected.")

		//connect to the ssh server
		sshConn, err := net.Dial("tcp", sshIP+":"+sshPort)
		if err != nil {
			log.Println("Error connecting to ssh server.")
		}

		//handle clients concurrantly

		go func(sshConn net.Conn, clientConn net.Conn) {
			defer clientConn.Close()
			defer sshConn.Close()

			go func() {
				if _, err := io.Copy(sshConn, &DecryptReader{Source: clientConn}); err != nil && err != io.EOF {
					log.Println("Client closed connection.")
				}
			}()

			if _, err := io.Copy(clientConn, &EncryptReader{Source: sshConn}); err != nil {
				log.Println("Error copying from shh to client.")
			}
		}(sshConn, clientConn)

	}

}

func clientProxyMode(ip string, port string) {
	//connect to the server
	serverConn, err := net.Dial("tcp", ip+":"+port)
	if err != nil {
		log.Fatal("Error connecting to server.")
	}

	defer serverConn.Close()

	go io.Copy(serverConn, &EncryptReader{Source: os.Stdin})
	io.Copy(os.Stdout, &DecryptReader{Source: serverConn})
}

// func copy(dst io.Writer, src io.Reader) (written int64, err error) {
// 	buf := make([]byte, 4096) // Buffer for copying data

// 	for {
// 		n, err := src.Read(buf)
// 		if err != nil && err != io.EOF {
// 			return written, err
// 		}

// 		if n == 0 {
// 			break // End of input reached
// 		}

// 		// Write the read bytes to the destination
// 		if _, err := dst.Write(buf[:n]); err != nil {
// 			return written, err
// 		}

// 		written += int64(n)
// 	}

// 	return written, nil
// }

// custom readers for encryption and decryption
type EncryptReader struct {
	Source io.Reader
}

type DecryptReader struct {
	Source io.Reader
}

func (encryptReader *EncryptReader) Read(p []byte) (int, error) {
	n, err := encryptReader.Source.Read(p)
	if err != nil {
		return n, err
	}

	//encrypt here
	encrypted := encrypt(p[:n])

	//append the length of the cypher text
	num := uint32(len(encrypted))
	cipherLen := make([]byte, lenHeaderSize)
	binary.BigEndian.PutUint32(cipherLen, num)
	encrypted = append(cipherLen, encrypted...)

	//copy the encrypted byte array to p
	copy(p, encrypted)

	return len(encrypted), nil
}

func (decryptReader *DecryptReader) Read(p []byte) (int, error) {
	//check the size of the ciphertext
	numBytes := make([]byte, lenHeaderSize)
	n, err := decryptReader.Source.Read(numBytes)
	if err != nil {
		return n, err
	}
	num := binary.BigEndian.Uint32(numBytes)

	//read until the size is reached
	ciphertext := make([]byte, num)
	n, err = io.ReadFull(decryptReader.Source, ciphertext)
	if err != nil {
		return n + len(numBytes), err
	}

	//decrypt the ciphertext
	plaintext := decrypt(ciphertext)

	//copy the plaintext to the provided buffer
	copy(p, plaintext)

	return len(plaintext), nil
}

// cypher functions
func encrypt(msg []byte) []byte {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		log.Println("Error making a block.")
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Println("Error making a nonce.")
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Println("Error creating a new GCM cipher.")
	}

	ciphertext := aesgcm.Seal(nil, nonce, msg, nil)

	//append the nonce to the ciphertext for decryption
	ciphertext = append(nonce, ciphertext...)

	return ciphertext
}

func decrypt(ciphertext []byte) []byte {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		log.Println("Error making a block.")
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Println("Error creating a new GCM cipher.")
	}

	msg, err := aesgcm.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], nil)
	if err != nil {
		log.Println("Error decoding the message.")
	}

	return msg
}
