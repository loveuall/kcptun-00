package main

import (
	"net"
	"time"
)

type errConn struct {
	err error
}

var errConnSingle = &errConn{errConnection}

func (s *errConn) Write(b []byte) (n int, err error) {
	return 0, errConnection
}
func (s *errConn) SetReadDeadline(t time.Time) error {
	return nil
}
func (s *errConn) SetWriteDeadline(t time.Time) error {
	return nil
}
func (s *errConn) Read(b []byte) (n int, err error) {
	return 0, errConnection
}
func (s *errConn) SetDeadline(t time.Time) error {
	return nil
}
func (s *errConn) Close() error {
	return nil
}
func (s *errConn) LocalAddr() net.Addr {
	return nil
}
func (s *errConn) RemoteAddr() net.Addr {
	return nil
}
