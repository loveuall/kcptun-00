package common

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

type Config struct {
	Server      string `json:"server"`
	ServerPort  int    `json:"server_port"`
	Password    string `json:"password"`
	RedirPort   int    `json:"redir_port"`
	Socks5Port  int    `json:"socks5_port"`
	Mode        string `json:"mode"`
	Conn        int    `json:"conn"`
	Crypt       string `json:"crypt"`
	Mtu         int    `json:"mtu"`
	Sndwnd      int    `json:"sndwnd"`
	Rcvwnd      int    `json:"rcvwnd"`
	Nocomp      bool   `json: "nocomp"`
	Datashard   int    `json:datashard`
	Parityshard int    `json:parityshard`

	Acknodelay bool `json:"acknodelay"`
	Dscp       int  `json:"dscp"`
	Nodelay    int  `json:"nodelay"`
	Interval   int  `json:"interval"`
	Resend     int  `json:"resend"`
	Nc         int  `json:"nc"`

	// following options are only used by server
	PortPassword map[string]string `json:"port_password"`
}

func ParseConfig(config *Config, path string) (err error) {
	file, err := os.Open(path) // For read access.
	if err != nil {
		return
	}
	defer file.Close()

	if err = json.NewDecoder(file).Decode(config); err != nil {
		return
	}

	return
}

