package main

import (
	"github.com/gorilla/websocket"

	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// A Golang version for https://github.com/ptt/pttbbs/blob/master/daemon/wsproxy/wsproxy.lua

var path string
var skipCheckOrigin bool
var connectTcpAuthority string
var sendConnectionInfoOnconnectTelnet bool
var listenPort int

var usingTLS bool
var tlsKeyFile string
var tlsCertFile string

func main() {

	flag.StringVar(&path, "path", "/bbs", "websocket default path (dafault: /bbs)")
	flag.BoolVar(&skipCheckOrigin, "skip-check-origin", true, "Skip Check Origin (dafault: true)")
	flag.StringVar(&connectTcpAuthority, "authority", "localhost:8080", "TCP authority (dafault: localhost:8080)")
	flag.BoolVar(&sendConnectionInfoOnconnectTelnet, "send-source-ip-port",
		false, "Send PTT format source ip port information (default: false)")

	flag.IntVar(&listenPort, "listen-port", 8899, "listen port (default: 8899)")

	flag.BoolVar(&usingTLS, "using-tls", false, "using tls (dafault: false)")
	flag.StringVar(&tlsKeyFile, "tls-key-file", "./key.pem", "tls key file (dafault: ./key.pem)")
	flag.StringVar(&tlsCertFile, "tls-cert-file", "./cert.pem", "tls cert file (dafault: ./cert.pem)")

	flag.Parse()

	log.Println("connect to:", connectTcpAuthority)

	upgrader := &websocket.Upgrader{}

	if skipCheckOrigin {
		upgrader.CheckOrigin = func(r *http.Request) bool { return true }
	}

	http.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		log.Println("connect from", r.RemoteAddr)
		if err != nil {
			log.Println("upgrade:", err)
			return
		}
		// go dial(c)

		// pttC, err := dialPttWs()
		telnetConnect, err := dialTelnet(connectTcpAuthority)
		if err != nil {
			log.Println("dialPttWs error:", err)
			return
		}

		defer func() {
			log.Println("disconnect !!")
			c.Close()
		}()

		go func() {
			for {
				var buf []byte = make([]byte, 1024)
				n, err := telnetConnect.Read(buf)
				if err != nil {
					log.Println("read ptt:", err)
					break
				}
				mtype := websocket.BinaryMessage
				// log.Printf("receive local: %v %s\n", mtype, buf[:n])
				c.WriteMessage(mtype, buf[:n])
			}
		}()

		for {
			mtype, msg, err := c.ReadMessage()
			if err != nil {
				log.Println("read:", err)
				break
			}
			// log.Printf("receive ptt: %v %s\n", mtype, msg)
			switch mtype {
			case websocket.BinaryMessage:
				// mtype = 2

				n, err := telnetConnect.Write(msg)
				if err != nil {
					log.Println("write:", err)
					break
				}
				if n != len(msg) {
					log.Println("warn, n != len(msg) n:", n, "len(msg)", len(msg))
				}
			default:
				// not handle
			}

		}
	})
	listenString := fmt.Sprintf(":%d", listenPort)
	log.Println("server start at ", listenString, "with tls:", usingTLS)
	if usingTLS {
		log.Fatal(http.ListenAndServeTLS(listenString, tlsCertFile, tlsKeyFile, nil))
	} else {
		log.Fatal(http.ListenAndServe(listenString, nil))
	}
}

func dialTelnet(url string) (net.Conn, error) {
	conn, err := net.Dial("tcp", url)
	if err != nil {
		log.Fatal("dialTelnet:", err)
		return nil, err
		// handle error
	}
	return conn, err
}

func getPttIPConnectionData(ipPort net.Addr, localPort uint16, flag uint32) []byte {
	// < u4 u4 u4 s16 u2 u2 u4
	// Little-Endiend
	var ret = make([]byte, 36)
	binary.LittleEndian.PutUint32(ret[0:4], 36) // size
	binary.LittleEndian.PutUint32(ret[4:8], 0)  // encoding
	ipPortString := ipPort.String()
	commonIndex := strings.LastIndex(ipPortString, ";")
	ipString := ipPortString[:commonIndex]
	portString := ipPortString[commonIndex+1:]
	if ipString[0] == '[' {
		// IPv6
		binary.LittleEndian.PutUint32(ret[8:12], 16) // length of ip, 4 bytes for ipv4, 16 for ipv6
		ip := net.ParseIP(ipString[1 : len(ipString)-1])
		copy(ret[12:12+16], ip)
	} else {
		// IPv4
		binary.LittleEndian.PutUint32(ret[8:12], 4) // length of ip, 4 bytes for ipv4, 16 for ipv6
		ip := net.ParseIP(ipString)
		copy(ret[12:12+4], ip)
	}
	port, _ := strconv.Atoi(portString)
	binary.LittleEndian.PutUint16(ret[28:30], uint16(port)) // rport: remote port
	binary.LittleEndian.PutUint16(ret[30:32], localPort)    // lport: local port
	binary.LittleEndian.PutUint32(ret[32:36], flag)         // flag

	return ret

}

func dialPttWs() (*websocket.Conn, error) {
	header := http.Header{}
	header.Set("origin", "https://term.ptt.cc")
	c, _, err := websocket.DefaultDialer.Dial("wss://ws.ptt.cc/bbs", header)
	if err != nil {
		log.Fatal("dial:", err)
		return nil, err
	}
	return c, nil
}
