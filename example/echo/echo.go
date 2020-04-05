package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"math/big"
	"time"

	"github.com/lucas-clemente/quic-go"
)

var (
	Address string
	Role    string
	Message int
	Par     int

	Help    bool

	message []byte
)

func init()  {
	flag.StringVar(&Address,"addr","0.0.0.0:1000","listen udp port")
	flag.IntVar(&Message,"msg",1024,"message size len")
	flag.StringVar(&Role,"role","server","server/client")
	flag.IntVar(&Par,"par",10,"par message for send/recv")

	flag.BoolVar(&Help,"help",false,"usage help")
}

func main() {

	flag.Parse()
	if Help {
		flag.Usage()
		return
	}

	if Role == "server" {
		log.Printf("quic server start")
		log.Fatal(Server())
		return
	}

	message = make([]byte, Message)
	for i:=0;i<Message;i++{
		message[i] = byte('a')
	}

	if Role == "client" {
		log.Printf("quic client start")
		Client()
	}
}

// Start a server that echos all data on the first stream opened by the client
func Server() error {
	listener, err := quic.ListenAddr(Address, generateTLSConfig(), nil)
	if err != nil {
		return err
	}
	for {
		sess, err := listener.Accept()
		if err != nil {
			log.Printf("listen accept fail %s", err.Error())
			continue
		}

		log.Printf("accept session %s", sess.RemoteAddr())
		go func() {
			for {
				stream, err := sess.AcceptStream()
				if err != nil {
					log.Printf("session accept stream %s", err.Error())
					return
				}

				log.Printf("new stream success: %d", stream.StreamID())

				go func() {

					bufer := make([]byte,8192)
					for {
						cnt,err := stream.Read(bufer)
						if err != nil {
							log.Printf("stream read fail:%s",err.Error())
							break
						}

						StatAdd(cnt)

						_, err = stream.Write(bufer[:cnt])
						if err != nil {
							log.Printf("stream write fail:%s",err.Error())
							break
						}
					}

				}()
			}
		}()
	}
}

func Client() error {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-echo-example"},
	}
	session, err := quic.DialAddr(Address, tlsConf, nil)
	if err != nil {
		return err
	}

	for i:=0; i<Par ; i++ {

		go func() {
			stream, err := session.OpenStreamSync()
			if err != nil {
				log.Printf("open stream fail : %s", err.Error())
				return
			}

			recvBuf := make([]byte,8192)
			var writeCnt int
			var readCnt int

			log.Printf("new stream success %d", stream.StreamID())

			for {
				writeCnt, err = stream.Write([]byte(message))
				if err != nil {
					log.Printf("stream write fail : %s", err.Error())
					return
				}
				readCnt, err = stream.Read(recvBuf)
				if err != nil {
					log.Printf("stream read fail : %s", err.Error())
					return
				}
				StatAdd(readCnt+writeCnt)
			}
		}()

	}

	time.Sleep(3600*time.Second)

	return nil
}

// A wrapper for io.Writer that also logs the message.
type loggingWriter struct{ io.Writer }

func (w loggingWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
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
