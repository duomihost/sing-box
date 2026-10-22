package shadowsocks

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestUpdateServiceUsersKeysByName(t *testing.T) {
	const method = "2022-blake3-aes-128-gcm"
	iPSK := randomKey(16)
	handler := &recordingHandler{}
	service, err := shadowaead_2022.NewMultiService[string](method, iPSK, 300, handler, nil)
	if err != nil {
		t.Fatal(err)
	}

	users := make([]option.ShadowsocksUser, 5)
	for i := range users {
		users[i] = option.ShadowsocksUser{Name: string(rune('a' + i)), Password: base64.StdEncoding.EncodeToString(randomKey(16))}
	}
	if err = updateServiceUsers(service, users); err != nil {
		t.Fatal(err)
	}
	// Dropping earlier users shifts positions; the remaining user must keep its name.
	last := users[4]
	if err = updateServiceUsers(service, users[3:]); err != nil {
		t.Fatal(err)
	}
	uPSK, _ := base64.StdEncoding.DecodeString(last.Password)
	client, err := shadowaead_2022.New(method, [][]byte{iPSK, uPSK}, nil)
	if err != nil {
		t.Fatal(err)
	}
	capture := &memConn{r: bytes.NewReader(nil)}
	if _, err = client.DialEarlyConn(capture, M.ParseSocksaddr("test.com:443")).Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err = service.NewConnection(context.Background(), &memConn{r: bytes.NewReader(capture.w.Bytes())}, M.Metadata{}); err != nil {
		t.Fatal(err)
	}
	if handler.user != last.Name {
		t.Fatalf("connection attributed to %q, want %q", handler.user, last.Name)
	}
}

func TestUpdateServiceUsersRejectsDuplicateNames(t *testing.T) {
	service, err := shadowaead_2022.NewMultiService[string]("2022-blake3-aes-128-gcm", randomKey(16), 300, &recordingHandler{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	password := base64.StdEncoding.EncodeToString(randomKey(16))
	err = updateServiceUsers(service, []option.ShadowsocksUser{{Name: "same", Password: password}, {Name: "same", Password: password}})
	if err == nil {
		t.Fatal("duplicate user names accepted")
	}
}

func TestUserFromKey(t *testing.T) {
	if user, named := userFromKey("alice"); user != "alice" || !named {
		t.Fatalf("named user: got %q %v", user, named)
	}
	if user, named := userFromKey(unnamedUserPrefix + "3"); user != "3" || named {
		t.Fatalf("unnamed user: got %q %v", user, named)
	}
}

type recordingHandler struct {
	user string
}

func (h *recordingHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	h.user, _ = auth.UserFromContext[string](ctx)
	return nil
}

func (h *recordingHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	return nil
}

func (h *recordingHandler) NewError(ctx context.Context, err error) {}

type memConn struct {
	r *bytes.Reader
	w bytes.Buffer
}

func (c *memConn) Read(p []byte) (int, error)         { return c.r.Read(p) }
func (c *memConn) Write(p []byte) (int, error)        { return c.w.Write(p) }
func (c *memConn) Close() error                       { return nil }
func (c *memConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *memConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *memConn) SetDeadline(t time.Time) error      { return nil }
func (c *memConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *memConn) SetWriteDeadline(t time.Time) error { return nil }

func randomKey(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}
