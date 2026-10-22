package shadowsocks

import (
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-shadowsocks"
	E "github.com/sagernet/sing/common/exceptions"
)

// Multi-user services key users by name instead of by position, so a
// connection authenticated against one user list keeps the right identity
// when a hot update replaces the list. Unnamed users fall back to their
// position, which is only used for logging, as before.
const unnamedUserPrefix = "\x00"

func (h *MultiInbound) UpdateUsersByOptions(users []option.ShadowsocksUser) error {
	return updateServiceUsers(h.service, users)
}

func updateServiceUsers(service shadowsocks.MultiService[string], users []option.ShadowsocksUser) error {
	keys := make([]string, len(users))
	passwords := make([]string, len(users))
	seen := make(map[string]struct{}, len(users))
	for i, user := range users {
		key := user.Name
		if key == "" {
			key = unnamedUserPrefix + strconv.Itoa(i)
		}
		if _, loaded := seen[key]; loaded {
			return E.New("duplicate shadowsocks user name: ", key)
		}
		seen[key] = struct{}{}
		keys[i] = key
		passwords[i] = user.Password
	}
	return service.UpdateUsersWithPasswords(keys, passwords)
}

func userFromKey(key string) (user string, named bool) {
	if strings.HasPrefix(key, unnamedUserPrefix) {
		return strings.TrimPrefix(key, unnamedUserPrefix), false
	}
	return key, true
}
