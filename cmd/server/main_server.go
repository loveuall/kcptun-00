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
	"time"

	"github.com/golang/snappy"
	"golang.org/x/crypto/pbkdf2"

	cmm "github.com/loveuall/kcptun/common"
	"github.com/xtaci/kcp-go"

	"github.com/hashicorp/yamux"
	"github.com/urfave/cli"
)

var (
	VERSION     = "SELFBUILD"
	SALT        = "kcp-go"
	ReadTimeout = (10 * time.Second)
)

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

func (c *compStream) LocalAddr() net.Addr {
	return nil
}

func (c *compStream) RemoteAddr() net.Addr {
	return nil
}

func (c *compStream) SetDeadline(t time.Time) error {
	return nil
}
func (c *compStream) SetReadDeadline(t time.Time) error {
	return nil
}
func (c *compStream) SetWriteDeadline(t time.Time) error {
	return nil
}

func newCompStream(conn net.Conn) *compStream {
	c := new(compStream)
	c.conn = conn
	c.w = snappy.NewBufferedWriter(conn)
	c.r = snappy.NewReader(conn)
	return c
}

func runMux(config *cmm.Config, port string, password string) {
	listen := config.Server + ":" + port
	log.Println("listening at", listen)

	pass := pbkdf2.Key([]byte(password), []byte(SALT), 4096, 32, sha1.New)
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

	lis, err := kcp.ListenWithOptions(listen, block, config.Datashard, config.Parityshard)
	if err != nil {
		log.Fatal(err)
	}

	if err := lis.SetDSCP(config.Dscp); err != nil {
		log.Println("SetDSCP:", err)
	}
	if err := lis.SetReadBuffer(config.Sockbuf); err != nil {
		log.Println("SetReadBuffer:", err)
	}
	if err := lis.SetWriteBuffer(config.Sockbuf); err != nil {
		log.Println("SetWriteBuffer:", err)
	}
	for {
		if conn, err := lis.Accept(); err == nil {
			log.Println("remote address:", conn.RemoteAddr())
			conn.SetStreamMode(true)
			conn.SetNoDelay(config.Nodelay, config.Interval, config.Resend, config.Nc)
			conn.SetMtu(config.Mtu)
			conn.SetWindowSize(config.Rcvwnd, config.Rcvwnd)
			conn.SetACKNoDelay(config.Acknodelay)
			if config.Nocomp {
				go handleMux(conn, config)
			} else {
				go handleMux(newCompStream(conn), config)
			}
		} else {
			log.Println(err)
		}
	}
}

// handle multiplex-ed connection
func handleMux(conn net.Conn, config *cmm.Config) {
	// stream multiplex
	var mux *yamux.Session
	yconfig := &yamux.Config{
		AcceptBacklog:          256,
		EnableKeepAlive:        true,
		KeepAliveInterval:      30 * time.Second,
		ConnectionWriteTimeout: 30 * time.Second,
		MaxStreamWindowSize:    uint32(config.Sockbuf),
		LogOutput:              os.Stderr,
	}
	m, err := yamux.Server(conn, yconfig)
	if err != nil {
		log.Println(err)
		return
	}
	mux = m
	defer mux.Close()

	for {
		p1, err := mux.Accept()
		if err != nil {
			log.Println("mux:", err)
			return
		}
		go handleSocks5(p1)
	}
}

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

func handleSocks5(conn net.Conn) (err error) {
	var host string
	var extra []byte

	closed := false
	defer func() {
		log.Println("closed", host)
		if !closed {
			conn.Close()
		}
	}()

	host, extra, err = getRequest(conn)
	log.Println("connecting to", host)
	if err != nil {
		return
	}

	var remote *net.TCPConn
	if addr, err2 := net.ResolveTCPAddr("tcp", host); err2 == nil {
		remote, err = net.DialTCP("tcp", nil, addr)
		if err != nil {
			return
		}
	} else {
		err = err2
		return
	}
	remote.SetNoDelay(false)

	if extra != nil && len(extra) > 0 {
		if _, err = remote.Write(extra); err != nil {
			log.Println("write request extra error:", err)
			return
		}
	}

	closed = true
	handleClient(remote, conn)
	return
}

func getRequest(conn net.Conn) (host string, extra []byte, err error) {
	const (
		idType  = 0 // address type index
		idIP0   = 1 // ip addres start index
		idDmLen = 1 // domain address length index
		idDm0   = 2 // domain address start index

		typeIPv4 = 1 // type is ipv4 address
		typeDm   = 3 // type is domain address
		typeIPv6 = 4 // type is ipv6 address

		lenIPv4   = 1 + net.IPv4len + 2 // 1addrType + ipv4 + 2port
		lenIPv6   = 1 + net.IPv6len + 2 // 1addrType + ipv6 + 2port
		lenDmBase = 1 + 1 + 2           // 1addrType + 1addrLen + 2port, plus addrLen
	)

	// buf size should at least have the same size with the largest possible
	// request size (when addrType is 3, domain name has at most 256 bytes)
	// 1(addrType) + 1(lenByte) + 256(max length address) + 2(port)
	buf := make([]byte, 260)
	var n int
	// read till we get possible domain length field
	if n, err = io.ReadAtLeast(conn, buf, idDmLen+1); err != nil {
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
		err = errors.New("addr type not supported")
		return
	}

	if n < reqLen { // rare case
		if _, err = io.ReadFull(conn, buf[n:reqLen]); err != nil {
			return
		}
	} else if n > reqLen {
		// it's possible to read more than just the request head
		extra = buf[reqLen:n]
	}

	// Return string for typeIP is not most efficient, but browsers (Chrome,
	// Safari, Firefox) all seems using typeDm exclusively. So this is not a
	// big problem.
	switch buf[idType] {
	case typeIPv4:
		host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
	case typeIPv6:
		host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
	case typeDm:
		host = string(buf[idDm0 : idDm0+buf[idDmLen]])
	}
	// parse port
	port := binary.BigEndian.Uint16(buf[reqLen-2 : reqLen])
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	return
}

func newConfigFromContext(c *cli.Context) (config *cmm.Config) {
	config = &cmm.Config{}
	path := c.String("c")

	config.Rcvwnd = c.Int("rcvwnd")
	config.Mtu = c.Int("mtu")
	config.Mode = c.String("mode")
	config.PortPassword = make(map[string]string)
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
		ss := strings.Split(c.String("listen"), ":")
		config.Server = ss[0]
		config.PortPassword[ss[1]] = c.String("key")
	} else {
		if c.String("listen") != ":29900" {
			log.Println("Cannot use config.json with localaddr option")
			os.Exit(-1)
		}

		if err := cmm.ParseConfig(config, path); err != nil {
			log.Println(err)
			os.Exit(-1)
		}

		if config.Server == "" {
			log.Println("Server not found")
			os.Exit(-1)
		}

		if len(config.PortPassword) == 0 {
			config.PortPassword[strconv.Itoa(config.ServerPort)] = config.Password
		}
	}

	return
}

func main() {
	rand.Seed(int64(time.Now().Nanosecond()))
	if VERSION == "SELFBUILD" {
		// add more log flags for debugging
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}
	myApp := cli.NewApp()
	myApp.Name = "kcptun"
	myApp.Usage = "kcptun server"
	myApp.Version = VERSION
	myApp.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "listen,l",
			Value: ":29900",
			Usage: "kcp server listen address",
		},
		cli.StringFlag{
			Name:   "key",
			Value:  "it's a secrect",
			Usage:  "key for communcation, must be the same as kcptun client",
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
			Name:  "mtu",
			Value: cmm.MTU,
			Usage: "set MTU of UDP packets, suggest 'tracepath' to discover path mtu",
		},
		cli.IntFlag{
			Name:  "sndwnd",
			Value: cmm.RCVWND,
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
			Name:   "acknodelay",
			Usage:  "flush ack immediately when a packet is received",
			Hidden: true,
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
		cli.IntFlag{
			Name:   "sockbuf",
			Value:  4194304, // socket buffer size in bytes
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "keepalive",
			Value:  10, // nat keepalive interval in seconds
			Hidden: true,
		},
		cli.StringFlag{
			Name:  "c",
			Value: "",
			Usage: "path of config.json file",
		},
	}
	myApp.Action = func(c *cli.Context) error {
		log.Println("version:", VERSION)

		config := newConfigFromContext(c)
		if len(config.PortPassword) == 0 {
			log.Println("config error")
			os.Exit(-1)
		}

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
		log.Println("sndwnd:", config.Rcvwnd, "rcvwnd:", config.Rcvwnd)
		log.Println("acknodelay:", config.Acknodelay)
		log.Println("dscp:", config.Dscp)
		log.Println("compression:", !config.Nocomp)
		log.Println("datashard:", config.Datashard, "parityshard:", config.Parityshard)
		log.Println("sockbuf:", config.Sockbuf)
		log.Println("keepalive:", config.KeepAlive)

		i := 0
		for ok, ov := range config.PortPassword {
			i++

			k, v := ok, ov
			if i == len(config.PortPassword) {
				//The last port/password, block current goroutine
				runMux(config, k, v)
				break
			}

			go runMux(config, k, v)
		}

		return nil
	}
	myApp.Run(os.Args)
}
