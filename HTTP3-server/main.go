package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	_ "net/http/pprof"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/lucas-clemente/quic-go/quicvarint"
)

// dataFrame - struct for description HTTP3 data frame. See: https://tools.ietf.org/id/draft-ietf-quic-http-23.html#rfc.section.7
type dataFrame struct {
	Length uint64
}

func (f *dataFrame) Write(b *bytes.Buffer) {
	quicvarint.Write(b, 0x0)
	quicvarint.Write(b, f.Length)
}

// byteReader - interface for reading bit by bit. Need in function quicvarint.Read
type byteReader interface {
	io.ByteReader
	io.Reader
}

// byteReaderImpl - implementation of byteReader interface
type byteReaderImpl struct{ io.Reader }

func (br *byteReaderImpl) ReadByte() (byte, error) {
	b := make([]byte, 1)
	if _, err := br.Reader.Read(b); err != nil {
		return 0, err
	}
	return b[0], nil
}

// RWStream - interface for bidirectional HTTP3 communication over by QUIC stream.
// Since we now control the QUIC stream ourselves, we should send and receive correct HTTP3 frames ourselves
type RWStream interface {
	io.WriteCloser
	io.Reader
}

// RWStreamImpl - implementation of RWStream interface
type RWStreamImp struct {
	str quic.Stream
}

func (w *RWStreamImp) Write(p []byte) (int, error) {
	df := &dataFrame{Length: uint64(len(p))}
	buf := &bytes.Buffer{}
	df.Write(buf)
	if _, err := w.str.Write(buf.Bytes()); err != nil {
		return 0, err
	}
	return w.str.Write(p)
}

func (w *RWStreamImp) Read(p []byte) (int, error) {
	var bytesRemainingInFrame uint64

	// Read HTTP3 frame

	br, ok := w.str.(byteReader)
	if !ok {
		br = &byteReaderImpl{w.str}
	}
	t, err := quicvarint.Read(br)
	if err != nil {
		return 0, err
	}
	l, err := quicvarint.Read(br)
	if err != nil {
		return 0, err
	}

	// Receive only HTTP3 data frames
	if t != 0x0 {
		return 0, fmt.Errorf("Incorrect HTTP3 frame type! Expected: Data frame (0x0). Got: %x", t)
	}

	bytesRemainingInFrame = l

	var n int
	if bytesRemainingInFrame < uint64(len(p)) {
		n, err = w.str.Read(p[:bytesRemainingInFrame])
	} else {
		n, err = w.str.Read(p)
	}
	return n, err
}

func (w *RWStreamImp) Close() error {
	return w.str.Close()
}

func NewRWStream(str quic.Stream) RWStream {
	return &RWStreamImp{
		str: str,
	}
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-echo-example"},
	}
}

type Server struct{}

// Main handler
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("New request")

	// Need for unlock client.Do function and notify the client about the change of communication protocol
	w.WriteHeader(http.StatusSwitchingProtocols)

	// From this moment on, the management of the QUIC streamer is entirely on the server's shoulders
	str := w.(http3.DataStreamer).DataStream()

	RWStr := NewRWStream(str)
	defer RWStr.Close()

	buf := make([]byte, 100)
	for i := 0; i < 10; i++ {
		_, err := RWStr.Write([]byte("PING"))
		if err != nil {
			log.Printf("Error while writing message in stream. Error: %v", err)
			return
		}

		log.Printf("Ping message was successfully sent")

		_, err = RWStr.Read(buf)
		if err != nil {
			log.Printf("Error while reading message from stream. Error: %v", err)
			return
		}

		log.Printf("Message from client: %s", buf)
		time.Sleep(1 * time.Second)
	}
}

func main() {
	server := http3.Server{
		Server: &http.Server{
			Addr:      "localhost:8081",
			Handler:   &Server{},
			TLSConfig: generateTLSConfig(),
		},
	}

	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
}
