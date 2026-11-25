package ipv6ddns

import (
	"fmt"
	"maps"
	"slices"

	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/resolver"
)

// updateKeys are the keys of a resolver's dynamic updates, each with a grant of each of its
// permissions: none without updates.
func (w *Worker) updateKeys(resolverName string, u *config.Updates) ([]resolver.UpdateKey, error) {
	if u == nil {
		return nil, nil
	}
	var keys []resolver.UpdateKey
	for _, name := range slices.Sorted(maps.Keys(u.Keys)) {
		k := u.Keys[name]
		key := k.Spec
		key.Grants = nil
		for i, p := range k.Permissions {
			path := fmt.Sprintf("resolvers.%s.updates.keys.%s.permissions[%d].%s", resolverName, name, i, p.Kind())
			g, err := w.grant(path, p)
			if err != nil {
				return nil, err
			}
			key.Grants = append(key.Grants, g)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// grant is the grant of a permission: where what the key sends goes.
func (w *Worker) grant(path string, p config.Permission) (resolver.Grant, error) {
	return nil, fmt.Errorf("%s: permissions of %s aren't taken yet", path, p.Kind())
}
