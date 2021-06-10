package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/lucas-clemente/quic-go/http3"
)

func main() {
	// Create a pipe - an object that implements `io.Reader` and `io.Writer`.
	// Whatever is written to the writer part will be read by the reader part.
	pr, pw := io.Pipe()

	// Create an `http.Request` and set its body as the reader part of the
	// pipe - after sending the request, whatever will be written to the pipe,
	// will be sent as the request body.
	// This makes the request content dynamic, so we don't need to define it
	// before sending the request.
	req, err := http.NewRequest(http3.MethodGet0RTT, "https://localhost:8081", ioutil.NopCloser(pr))
	if err != nil {
		log.Fatal(err)
	}

	// Send the request
	client := http.Client{
		Transport: &http3.RoundTripper{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	resp, err := client.Do(req)
	log.Printf("Request was sent")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Got: %d", resp.StatusCode)

	str := resp.Body
	defer str.Close()

	buf := make([]byte, 100)
	for {
		_, err := str.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatalf("Error while reading from QUIC stream. Error: %v", err)
		}

		// Receive PING request from server
		log.Printf("MSG FROM SERVER: %s", buf)

		// Send PONG request to server
		fmt.Fprintf(pw, "PONG")
	}
}
