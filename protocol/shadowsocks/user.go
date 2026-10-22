package shadowsocks

import (
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-shadowsocks"
	E "github.com/sagernet/sing/common/exceptions"
)

// Multi-user services key users by name instead of by position, so a
// connection authenticated against one user list keeps the right identity
// when a hot update replaces the list. Unnamed users fall back to their
// position, which is only used for logging, as before.
const unnamedUserPrefix = "\x00"

var _ adapter.PreparableShadowsocksInbound = (*MultiInbound)(nil)

func (h *MultiInbound) UpdateUsersByOptions(users []option.ShadowsocksUser) error {
	if shadowsocks.ManagedUsers(h.ctx) {
		return E.New("managed updates require prepare/commit")
	}
	return updateServiceUsers(h.service, users)
}

// PrepareUsersByOptions validates users and builds the complete protocol user
// table without publishing it; Commit publishes it. Services without a
// preparer return adapter.ErrUsersNotPreparable.
func (h *MultiInbound) PrepareUsersByOptions(users []option.ShadowsocksUser, epoch uint64) (adapter.UserCommit, error) {
	return prepareServiceUsers(h.service, users, epoch)
}

func prepareServiceUsers(service shadowsocks.MultiService[string], users []option.ShadowsocksUser, epoch uint64) (adapter.UserCommit, error) {
	preparer, ok := service.(shadowsocks.UserPreparer[string])
	if !ok {
		return nil, adapter.ErrUsersNotPreparable
	}
	keys, passwords, err := serviceUserKeys(users)
	if err != nil {
		return nil, err
	}
	prepared, err := preparer.PrepareUsersWithPasswords(keys, passwords, epoch)
	if err != nil {
		return nil, err
	}
	return userCommit{prepared}, nil
}

type userCommit struct {
	prepared shadowsocks.UserCommit
}

func (c userCommit) Commit() { c.prepared.Publish() }

func updateServiceUsers(service shadowsocks.MultiService[string], users []option.ShadowsocksUser) error {
	keys, passwords, err := serviceUserKeys(users)
	if err != nil {
		return err
	}
	return service.UpdateUsersWithPasswords(keys, passwords)
}

// serviceUserKeys returns the service keys and passwords of users.
func serviceUserKeys(users []option.ShadowsocksUser) (keys []string, passwords []string, err error) {
	keys = make([]string, len(users))
	passwords = make([]string, len(users))
	seen := make(map[string]struct{}, len(users))
	for i, user := range users {
		key := user.Name
		if key == "" {
			key = unnamedUserPrefix + strconv.Itoa(i)
		}
		if _, loaded := seen[key]; loaded {
			return nil, nil, E.New("duplicate shadowsocks user name: ", key)
		}
		seen[key] = struct{}{}
		keys[i] = key
		passwords[i] = user.Password
	}
	return keys, passwords, nil
}

func userFromKey(key string) (user string, named bool) {
	if strings.HasPrefix(key, unnamedUserPrefix) {
		return strings.TrimPrefix(key, unnamedUserPrefix), false
	}
	name, _, _ := strings.Cut(key, "\x00uid:")
	return name, true
}
