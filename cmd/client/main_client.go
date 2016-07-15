package main

import (
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/golang/snappy"
	"github.com/xtaci/kcp-go"

	"github.com/hashicorp/yamux"
	cmm "github.com/loveuall/kcptun/common"
	"github.com/urfave/cli"
	"golang.org/x/crypto/pbkdf2"
)

type ClosingFn func() error

var (
	// VERSION is injected by buildflags
	VERSION = "SELFBUILD"
	// SALT is use for pbkdf2 key expansion
	SALT             = "kcp-go"
	errAddrType      = errors.New("socks addr type not supported")
	errVer           = errors.New("socks version not supported")
	errMethod        = errors.New("socks only support 1 method now")
	errAuthExtraData = errors.New("socks authentication get extra data")
	errReqExtraData  = errors.New("socks request get extra data")
	errCmd           = errors.New("socks command not supported")
	errConnection    = errors.New("error connection")

	gMgr *clientManager = nil
)

const (
	ReadTimeout     = (2 * time.Second)
	SocksVer5       = 5
	SocksCmdConnect = 1
	SO_ORIGINAL_DST = 80
)

type clientManager struct {
	config cmm.Config
	conns  chan localConn
}

type localConn struct {
	conn *net.TCPConn
	do   func(*clientManager, net.Conn, net.Conn) error
}

type compStream struct {
	conn net.Conn
	w    *snappy.Writer
	r    *snappy.Reader
}

func (c *compStream) Read(p []byte) (n int, err error) {
	return c.r.Read(p)
}

func (c *compStream) Write(p []byte) (n int, err error) {
	n, err = c.w.Write(p)
	err = c.w.Flush()
	return n, err
}

func (c *compStream) Close() error {
	return c.conn.Close()
}

func newCompStream(conn net.Conn) *compStream {
	c := new(compStream)
	c.conn = conn
	c.w = snappy.NewBufferedWriter(conn)
	c.r = snappy.NewReader(conn)
	return c
}

func handleSocks5Client(mgr *clientManager, p1, p2 net.Conn) (err error) {
	//p1 tcpconn, p2 mux conn
	closed := false
	var addr string

	defer func() {
		log.Println("closed addr", addr)
		if !closed {
			p1.Close()
			p2.Close()
		}
	}()

	obuf := make([]byte, 304)
	if err = handShake(obuf, p1); err != nil {
		log.Println("socks handshake:", err)
		return
	}
	rawaddr, addr, err := getRequest(obuf, p1)
	log.Println("new socks5 conn by", addr)
	if err != nil {
		log.Println("error getting request:", err)
		return
	}
	// Sending connection established message immediately to client.
	// This some round trip time for creating socks connection with the client.
	// But if connection failed, the client will get connection reset error.
	_, err = p1.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x43})
	if err != nil {
		log.Println("send connection confirmation", err)
		return
	}

	p2.Write(rawaddr)

	closed = true
	handleClient(p1, p2)
	return
}

func handleRedirClient(mgr *clientManager, p1, p2 net.Conn) (err error) {
	var rawaddr []byte

	closed := false
	defer func() {
		if !closed {
			p1.Close()
			p2.Close()
		}
	}()

	rawaddr, _, err = getOriginalDst(p1.(*net.TCPConn))
	if err != nil {
		return
	}
	log.Println("new redir conn by", rawaddr)

	p2.Write(rawaddr)

	closed = true
	handleClient(p1, p2)
	return
}

func getOriginalDst(conn *net.TCPConn) (rawaddr []byte, host string, err error) {
	if f, err2 := conn.File(); err != nil {
		err = err2
	} else {
		defer f.Close()

		fd := int(f.Fd())

		//TODO for ipv6
		addr, err2 := GetMreq(fd, syscall.IPPROTO_IP, SO_ORIGINAL_DST)
		if err2 != nil {
			err = err2
			return
		}

		//idType ipv4 port = 1 + 4 + 2
		rawaddr = make([]byte, 7)

		rawaddr[0] = 1 // typeIPv4, type is ipv4 address
		copy(rawaddr[1:5], addr[4:8])
		copy(rawaddr[5:7], addr[2:4])

		//Just for debug
		//port := binary.BigEndian.Uint16(rawaddr[5:7])
		//host = net.JoinHostPort(net.IP(rawaddr[1:5]).String(), strconv.Itoa(int(port)))

	}

	return
}

func handShake(obuf []byte, conn net.Conn) (err error) {
	const (
		idVer     = 0
		idNmethod = 1
	)
	// version identification and method selection message in theory can have
	// at most 256 methods, plus version and method field in total 258 bytes
	// the current rfc defines only 3 authentication methods (plus 2 reserved),
	// so it won't be such long in practice

	buf := obuf[:258]

	var n int
	conn.SetReadDeadline(time.Now().Add(ReadTimeout))

	// make sure we get the nmethod field
	if n, err = io.ReadAtLeast(conn, buf, idNmethod+1); err != nil {
		return
	}
	if buf[idVer] != SocksVer5 {
		return errVer
	}
	nmethod := int(buf[idNmethod])
	msgLen := nmethod + 2
	if n == msgLen { // handshake done, common case
		// do nothing, jump directly to send confirmation
	} else if n < msgLen { // has more methods to read, rare case
		if _, err = io.ReadFull(conn, buf[n:msgLen]); err != nil {
			return
		}
	} else { // error, should not get extra data
		return errAuthExtraData
	}
	// send confirmation: version 5, no authentication required
	_, err = conn.Write([]byte{SocksVer5, 0})
	return
}

func getRequest(obuf []byte, conn net.Conn) (rawaddr []byte, host string, err error) {
	const (
		idVer   = 0
		idCmd   = 1
		idType  = 3 // address type index
		idIP0   = 4 // ip addres start index
		idDmLen = 4 // domain address length index
		idDm0   = 5 // domain address start index

		typeIPv4 = 1 // type is ipv4 address
		typeDm   = 3 // type is domain address
		typeIPv6 = 4 // type is ipv6 address

		lenIPv4   = 3 + 1 + net.IPv4len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv4 + 2port
		lenIPv6   = 3 + 1 + net.IPv6len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv6 + 2port
		lenDmBase = 3 + 1 + 1 + 2           // 3 + 1addrType + 1addrLen + 2port, plus addrLen
	)
	// refer to getRequest in server.go for why set buffer size to 263
	buf := obuf[:263]

	var n int
	conn.SetReadDeadline(time.Now().Add(ReadTimeout))
	// read till we get possible domain length field
	if n, err = io.ReadAtLeast(conn, buf, idDmLen+1); err != nil {
		return
	}
	// check version and cmd
	if buf[idVer] != SocksVer5 {
		err = errors.New("version error")
		return
	}
	if buf[idCmd] != SocksCmdConnect {
		err = errCmd
		return
	}

	reqLen := -1
	switch buf[idType] {
	case typeIPv4:
		reqLen = lenIPv4
	case typeIPv6:
		reqLen = lenIPv6
	case typeDm:
		reqLen = int(buf[idDmLen]) + lenDmBase
	default:
		err = errAddrType
		return
	}

	if n == reqLen {
		// common case, do nothing
	} else if n < reqLen { // rare case
		if _, err = io.ReadFull(conn, buf[n:reqLen]); err != nil {
			return
		}
	} else {
		err = errReqExtraData
		return
	}

	rawaddr = buf[idType:reqLen]
	//log.Println("n=", n, reqLen)

	switch buf[idType] {
	case typeIPv4:
		host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
	case typeIPv6:
		host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
	case typeDm:
		host = string(buf[idDm0 : idDm0+buf[idDmLen]])
	}
	port := binary.BigEndian.Uint16(buf[reqLen-2 : reqLen])
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))

	conn.SetReadDeadline(time.Time{})
	return
}

//copy p2 to p1 first
func handleClient(p1, p2 io.ReadWriteCloser) {
	//log.Println("stream opened")
	//defer log.Println("stream closed")
	defer p1.Close()
	defer p2.Close()

	// start tunnel
	p1die := make(chan struct{})
	go func() {
		io.Copy(p1, p2)
		close(p1die)
	}()

	p2die := make(chan struct{})
	go func() {
		io.Copy(p2, p1)
		close(p2die)
	}()

	// wait for tunnel termination
	select {
	case <-p1die:
	case <-p2die:
	}
}

func newManagerByContext(c *cli.Context) (mgr *clientManager) {
	var err error
	mgr = &clientManager{
		conns: make(chan localConn, 32),
	}
	config := &mgr.config

	path := c.String("c")

	config.Sndwnd = c.Int("sndwnd")
	config.Rcvwnd = c.Int("rcvwnd")
	config.Mtu = c.Int("mtu")
	config.Mode = c.String("mode")
	config.Acknodelay = c.Bool("acknodelay")
	config.Dscp = c.Int("dscp")
	config.Nodelay = c.Int("nodelay")
	config.Interval = c.Int("interval")
	config.Resend = c.Int("resend")
	config.Nc = c.Int("nc")
	config.Conn = c.Int("conn")
	config.Crypt = c.String("crypt")
	config.Nocomp = c.Bool("nocomp")
	config.Datashard = c.Int("datashard")
	config.Parityshard = c.Int("parityshard")

	if path == "" {
		ss := strings.Split(c.String("remoteaddr"), ":")
		config.Server = ss[0]
		config.ServerPort, err = strconv.Atoi(ss[1])
		checkError(err)

		ss = strings.Split(c.String("localaddr"), ":")
		config.Socks5Port, err = strconv.Atoi(ss[1])
		checkError(err)
	} else {
		if c.String("localaddr") != ":12948" {
			log.Println("Cannot use config.json with localaddr option")
			os.Exit(-1)
		}
		if c.String("remoteaddr") != "vps:29900" {
			log.Println("Cannot use config.json with remoteaddr option")
			os.Exit(-1)
		}

		if err = cmm.ParseConfig(config, path); err != nil {
			log.Println(err)
			os.Exit(-1)
		}
	}

	if config.Server == "" || config.ServerPort == 0 {
		log.Println("Server not found")
		os.Exit(-1)
	}

	return
}

func (mgr *clientManager) runSocks5() {
	addr, err := net.ResolveTCPAddr("tcp", ":"+strconv.Itoa(mgr.config.Socks5Port))
	checkError(err)
	listener, err := net.ListenTCP("tcp", addr)
	checkError(err)
	log.Println("listening socks5 on:", listener.Addr())

	for {
		lConn := localConn{do: handleSocks5Client}

		lConn.conn, err = listener.AcceptTCP()
		if err != nil {
			log.Println(err)
			continue
		}

		//lConn.conn.SetNoDelay(false)
		mgr.conns <- lConn
	}
}

func (mgr *clientManager) runRedirect() {
	addr, err := net.ResolveTCPAddr("tcp", ":"+strconv.Itoa(mgr.config.RedirPort))
	checkError(err)
	listener, err := net.ListenTCP("tcp", addr)
	checkError(err)
	log.Println("listening redir on:", listener.Addr())

	for {
		lConn := localConn{do: handleRedirClient}

		lConn.conn, err = listener.AcceptTCP()
		if err != nil {
			log.Println(err)
			continue
		}

		//lConn.conn.SetNoDelay(false)
		mgr.conns <- lConn
	}
}

func checkError(err error) {
	if err != nil {
		log.Println(err)
		os.Exit(-1)
	}
}

func main() {
	rand.Seed(int64(time.Now().Nanosecond()))
	myApp := cli.NewApp()
	myApp.Name = "kcptun"
	myApp.Usage = "kcptun client"
	myApp.Version = VERSION
	myApp.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "localaddr,l",
			Value: ":12948",
			Usage: "local listen address",
		},
		cli.StringFlag{
			Name:  "remoteaddr, r",
			Value: "vps:29900",
			Usage: "kcp server address",
		},
		cli.StringFlag{
			Name:   "key",
			Value:  "it's a secrect",
			Usage:  "key for communcation, must be the same as kcptun server",
			EnvVar: "KCPTUN_KEY",
		},
		cli.StringFlag{
			Name:  "crypt",
			Value: "aes",
			Usage: "methods for encryption: aes, tea, xor, none",
		},
		cli.StringFlag{
			Name:  "mode",
			Value: "fast",
			Usage: "mode for communication: fast3, fast2, fast, normal",
		},
		cli.IntFlag{
			Name:  "conn",
			Value: 1,
			Usage: "establish N physical connections as specified by 'conn' to server",
		},
		cli.IntFlag{
			Name:  "mtu",
			Value: cmm.MTU,
			Usage: "set MTU of UDP packets, suggest 'tracepath' to discover path mtu",
		},
		cli.IntFlag{
			Name:  "sndwnd",
			Value: cmm.SNDWND,
			Usage: "set send window size(num of packets)",
		},
		cli.IntFlag{
			Name:  "rcvwnd",
			Value: cmm.RCVWND,
			Usage: "set receive window size(num of packets)",
		},
		cli.BoolFlag{
			Name:  "nocomp",
			Usage: "disable compression",
		},
		cli.IntFlag{
			Name:  "datashard",
			Value: 10,
			Usage: "set reed-solomon erasure coding - datashard",
		},
		cli.IntFlag{
			Name:  "parityshard",
			Value: 3,
			Usage: "set reed-solomon erasure coding - parityshard",
		},
		cli.BoolFlag{
			Name:  "acknodelay",
			Usage: "flush ack immediately when a packet is received",
		},
		cli.IntFlag{
			Name:  "dscp",
			Value: 0,
			Usage: "set DSCP(6bit)",
		},
		cli.IntFlag{
			Name:   "nodelay",
			Value:  0,
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "interval",
			Value:  40,
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "resend",
			Value:  0,
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "nc",
			Value:  0,
			Hidden: true,
		},
		cli.StringFlag{
			Name:  "c",
			Value: "",
			Usage: "path of config.json file",
		},
	}

	myApp.Action = func(c *cli.Context) {
		log.Println("version:", VERSION)
		mgr := newManagerByContext(c)
		config := mgr.config
		gMgr = mgr
		pass := pbkdf2.Key([]byte(config.Password), []byte(SALT), 4096, 32, sha1.New)

		switch config.Mode {
		case "normal":
			config.Nodelay, config.Interval, config.Resend, config.Nc = 0, 30, 2, 1
		case "fast":
			config.Nodelay, config.Interval, config.Resend, config.Nc = 0, 20, 2, 1
		case "fast2":
			config.Nodelay, config.Interval, config.Resend, config.Nc = 1, 20, 2, 1
		case "fast3":
			config.Nodelay, config.Interval, config.Resend, config.Nc = 1, 10, 2, 1
		}

		log.Println("communication mode:", config.Mode)
		log.Println("encryption:", config.Crypt)
		log.Println("nodelay parameters:", config.Nodelay, config.Interval, config.Resend, config.Nc)
		log.Println("sndwnd:", config.Sndwnd, "rcvwnd:", config.Rcvwnd)
		log.Println("acknodelay:", config.Acknodelay)
		log.Println("dscp:", config.Dscp)
		log.Println("compression:", !config.Nocomp)
		log.Println("datashard:", config.Datashard, "parityshard:", config.Parityshard)

		if config.RedirPort > 0 {
			go mgr.runRedirect()
		}

		if config.Socks5Port > 0 {
			go mgr.runSocks5()
		}

		createConn := func() *yamux.Session {
			var block kcp.BlockCrypt
			switch config.Crypt {
			case "tea":
				block, _ = kcp.NewTEABlockCrypt(pass[:16])
			case "xor":
				block, _ = kcp.NewSimpleXORBlockCrypt(pass)
			case "none":
				block, _ = kcp.NewNoneBlockCrypt(pass)
			default:
				block, _ = kcp.NewAESBlockCrypt(pass)
			}

			remoteAddr := config.Server + ":" + strconv.Itoa(config.ServerPort)
			log.Println("remote address:", remoteAddr)

			kcpconn, err := kcp.DialWithOptions(remoteAddr, block, config.Datashard, config.Parityshard)
			checkError(err)
			kcpconn.SetNoDelay(config.Nodelay, config.Interval, config.Resend, config.Nc)
			kcpconn.SetWindowSize(config.Sndwnd, config.Rcvwnd)
			kcpconn.SetMtu(config.Mtu)
			kcpconn.SetACKNoDelay(config.Acknodelay)
			kcpconn.SetDSCP(config.Dscp)

			// stream multiplex
			yconfig := &yamux.Config{
				AcceptBacklog:          256,
				EnableKeepAlive:        true,
				KeepAliveInterval:      30 * time.Second,
				ConnectionWriteTimeout: 30 * time.Second,
				MaxStreamWindowSize:    16777216,
				LogOutput:              os.Stderr,
			}
			var session *yamux.Session
			if config.Nocomp {
				session, err = yamux.Client(kcpconn, yconfig)
			} else {
				session, err = yamux.Client(newCompStream(kcpconn), yconfig)
			}
			checkError(err)
			return session
		}

		numconn := config.Conn
		var muxes []*yamux.Session
		for i := 0; i < numconn; i++ {
			muxes = append(muxes, createConn())
		}

		rr := 0
		for p1 := range mgr.conns {
			mux := muxes[rr%numconn]
			p2, err := mux.Open()
			if err != nil { // yamux failure
				log.Println(err)
				p1.conn.Close()
				mux.Close()
				muxes[rr%numconn] = createConn()
				continue
			}

			go p1.do(mgr, p1.conn, p2)
			rr++
		}
	}
	myApp.Run(os.Args)
}
