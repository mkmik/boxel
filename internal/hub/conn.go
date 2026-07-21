package hub

import (
	"bufio"
	"net"
)

// bufConn is a net.Conn whose reads drain a bufio.Reader first. After an HTTP
// connection hijack (hub side) or http.ReadResponse (agent side), bytes of the
// HTTP/2 stream may already sit in the buffered reader; losing them would
// corrupt the preface.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// WrapConn returns conn with reads served from r (which must wrap conn).
func WrapConn(conn net.Conn, r *bufio.Reader) net.Conn {
	return &bufConn{Conn: conn, r: r}
}
