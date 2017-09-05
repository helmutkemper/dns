package dns

import (
	"io"
	"net"
)

type packetSession struct {
	*session
}

func (s packetSession) Read(b []byte) (int, error) {
	msg, err := s.recv()
	if err != nil {
		return 0, err
	}

	buf, err := msg.AppendPack(b[:0:len(b)])
	if err != nil {
		return len(buf), err
	}
	if len(buf) > len(b) {
		return len(buf), io.ErrShortBuffer
	}
	return len(buf), nil
}

func (s packetSession) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := s.Read(b)
	return n, s.addr, err
}

func (s packetSession) Write(b []byte) (int, error) {
	msg := new(Message)
	if err := msg.Unpack(b); err != nil {
		return 0, err
	}

	query := &Query{
		RemoteAddr: s.addr,
		Message:    msg,
	}

	go s.do(query)

	return len(b), nil
}

func (s packetSession) WriteTo(b []byte, addr net.Addr) (int, error) {
	return s.Write(b)
}

type streamSession struct {
	*session

	rbuf []byte
}

func (s streamSession) Read(b []byte) (int, error) {
	if len(s.rbuf) > 0 {
		return s.read(b)
	}

	msg, err := s.recv()
	if err != nil {
		return 0, err
	}

	if s.rbuf, err = msg.AppendPack(s.rbuf[:0]); err != nil {
		return 0, err
	}

	b[0] = byte(len(s.rbuf) >> 8)
	b[1] = byte(len(s.rbuf))

	if len(b) == 2 {
		return 2, nil
	}

	n, err := s.read(b[2:])
	return 2 + n, err
}

func (s streamSession) read(b []byte) (int, error) {
	if len(s.rbuf) > len(b) {
		copy(b, s.rbuf[:len(b)])
		s.rbuf = s.rbuf[len(b):]
		return len(b), nil
	}

	n := len(s.rbuf)
	copy(b, s.rbuf)
	s.rbuf = s.rbuf[:0]
	return n, nil
}

func (s streamSession) Write(b []byte) (int, error) {
	if len(b) < 2 {
		return 0, io.ErrShortWrite
	}

	mlen := int(b[0])<<8 | int(b[1])
	buf := b[2:]

	if len(buf) != mlen {
		return 0, io.ErrShortWrite
	}

	msg := new(Message)
	if err := msg.Unpack(buf); err != nil {
		return 0, err
	}

	query := &Query{
		RemoteAddr: s.addr,
		Message:    msg,
	}

	go s.do(query)

	return len(b), nil
}

type session struct {
	Conn

	addr net.Addr

	client *Client

	msgerrc chan msgerr
}

type msgerr struct {
	msg *Message
	err error
}

func (s *session) do(query *Query) {
	msg, err := s.client.do(s.Conn, query)
	s.msgerrc <- msgerr{msg, err}
}

func (s *session) recv() (*Message, error) {
	me, ok := <-s.msgerrc
	if !ok {
		panic("impossible")
	}
	return me.msg, me.err
}
