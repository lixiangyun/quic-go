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

	quic "github.com/lucas-clemente/quic-go"
)

var (
	ADDRESS  string
	PARALNUM int
	RUNTIME  int
	BODYLEN  int
	MODE     string
	HELP     bool
)

func init() {
	flag.StringVar(&ADDRESS, "add", "localhost:6666", "address.")
	flag.IntVar(&PARALNUM, "par", 1, "parallel stream to connect.")
	flag.IntVar(&BODYLEN, "body", 64, "body length (KB).")
	flag.IntVar(&RUNTIME, "time", 3600, "runtime (second).")
	flag.StringVar(&MODE, "mode", "server", "run server/client mode.")
	flag.BoolVar(&HELP, "help", false, "this help.")
}

func main() {

	flag.Parse()

	if HELP || (MODE != "server" && MODE != "client") {
		flag.Usage()
		return
	}
	BODYLEN = BODYLEN * 1024

	if MODE == "server" {
		Server()
	} else {
		Client()
	}
}

func writefull(w io.Writer, buf []byte) error {

	readcnt := len(buf)
	sendcnt := 0

	for {
		cnt, err := w.Write(buf[sendcnt:readcnt])
		if err != nil {
			return err
		}
		sendcnt += cnt
		if sendcnt >= readcnt {
			break
		}
	}

	return nil
}

func ServerStream(stream quic.Stream) {

	defer stream.Close()

	var buffer [64 * 1024]byte

	for {
		cnt, err := stream.Read(buffer[:])
		if err != nil {
			log.Println(err.Error())
			break
		}

		StatAdd(cnt, 0)

		writefull(stream, buffer[:cnt])
	}
}

func ServerStreamProcess(sess quic.Session) {
	defer sess.Close()
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			log.Println(err.Error())
			break
		}
		go ServerStream(stream)
	}
}

func Server() error {
	listener, err := quic.ListenAddr(ADDRESS, generateTLSConfig(), nil)
	if err != nil {
		return err
	}
	for {
		sess, err := listener.Accept()
		if err != nil {
			log.Println(err.Error())
			continue
		}
		go ServerStreamProcess(sess)
	}
}

func ClientStreamProcess(stream quic.Stream) {

	body := make([]byte, BODYLEN)

	for {
		err := writefull(stream, body)
		if err != nil {
			log.Println(err.Error())
			break
		}

		buf := make([]byte, BODYLEN)
		cnt, err := io.ReadFull(stream, buf)
		if err != nil {
			log.Println(err.Error())
			break
		}

		StatAdd(cnt, 0)
	}
}

func Client() error {

	session, err := quic.DialAddr(ADDRESS, &tls.Config{InsecureSkipVerify: true}, nil)
	if err != nil {
		log.Println(err.Error())
		return err
	}

	defer session.Close()

	for i := 0; i < PARALNUM; i++ {
		stream, err := session.OpenStreamSync()
		if err != nil {
			log.Println(err.Error())
			return err
		}

		go ClientStreamProcess(stream)
	}

	time.Sleep(time.Duration(RUNTIME) * time.Second)

	return nil
}

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
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}}
}
