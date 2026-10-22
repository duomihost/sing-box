package shadowsocks

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"net"
)

func TestPrepareServiceUsersCommitsOnlyOnCommit(t *testing.T) {
	const method = "2022-blake3-aes-128-gcm"
	iPSK := randomKey(16)
	handler := &epochHandler{}
	service, err := shadowaead_2022.NewMultiService[string](method, iPSK, 300, handler, nil)
	if err != nil {
		t.Fatal(err)
	}
	uPSK := randomKey(16)
	user := option.ShadowsocksUser{Name: "alice", Password: base64.StdEncoding.EncodeToString(uPSK)}

	if _, err = prepareServiceUsers(service, []option.ShadowsocksUser{user, user}, 3); err == nil {
		t.Fatal("duplicate user names accepted")
	}
	commit, err := prepareServiceUsers(service, []option.ShadowsocksUser{user}, 3)
	if err != nil {
		t.Fatal(err)
	}
	client, err := shadowaead_2022.New(method, [][]byte{iPSK, uPSK}, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := func() []byte {
		capture := &memConn{r: bytes.NewReader(nil)}
		if _, err := client.DialEarlyConn(capture, M.ParseSocksaddr("test.com:443")).Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		return capture.w.Bytes()
	}
	if err = service.NewConnection(context.Background(), &memConn{r: bytes.NewReader(request())}, M.Metadata{}); err == nil {
		t.Fatal("prepared users were live before Commit")
	}
	commit.Commit()
	if err = service.NewConnection(context.Background(), &memConn{r: bytes.NewReader(request())}, M.Metadata{}); err != nil {
		t.Fatal(err)
	}
	if handler.epoch != 3 {
		t.Fatalf("request epoch = %d, want 3", handler.epoch)
	}
}

func TestPrepareServiceUsersLegacyIsAtomic(t *testing.T) {
	handler := &epochHandler{}
	service, err := shadowaead.NewMultiService[string]("aes-128-gcm", 300, handler)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := prepareServiceUsers(service, []option.ShadowsocksUser{{Name: "a", Password: "p"}}, 7)
	if err != nil {
		t.Fatal(err)
	}
	method, err := shadowaead.New("aes-128-gcm", nil, "p")
	if err != nil {
		t.Fatal(err)
	}
	request := func() []byte {
		capture := &memConn{r: bytes.NewReader(nil)}
		if _, err := method.DialEarlyConn(capture, M.ParseSocksaddr("test.com:443")).Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		return capture.w.Bytes()
	}
	if err = service.NewConnection(context.Background(), &memConn{r: bytes.NewReader(request())}, M.Metadata{}); err == nil {
		t.Fatal("published before commit")
	}
	commit.Commit()
	if err = service.NewConnection(context.Background(), &memConn{r: bytes.NewReader(request())}, M.Metadata{}); err != nil {
		t.Fatal(err)
	}
	if handler.epoch != 7 {
		t.Fatal("legacy request lost epoch", handler.epoch)
	}
}
func TestManagedInboundRejectsOutOfTransactionWrites(t *testing.T) {
	h := &MultiInbound{ctx: shadowsocks.ContextWithManagedUsers(context.Background())}
	if h.UpdateUsers([]string{"a"}, []string{"p"}) == nil {
		t.Fatal("SSM bypass accepted")
	}
	if h.UpdateUsersByOptions([]option.ShadowsocksUser{{Name: "a", Password: "p"}}) == nil {
		t.Fatal("direct bypass accepted")
	}
}

type epochHandler struct {
	epoch uint64
}

func (h *epochHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	h.epoch, _ = shadowsocks.UserEpochFromContext(ctx)
	return nil
}

func (h *epochHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	return nil
}

func (h *epochHandler) NewError(ctx context.Context, err error) {}
