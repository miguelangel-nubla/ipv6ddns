package ddns

import "fmt"

// providerRecord is a record of a provider that keeps each record apart, by an id: its value, and
// its TTL.
type providerRecord struct {
	ID    string
	Value string
	TTL   int
}

// recordChanges are how a provider that keeps each record apart makes, deletes and sets the TTL
// of one.
type recordChanges struct {
	create func(value string) error
	remove func(r providerRecord) error
	setTTL func(r providerRecord) error
}

// reconcile makes the records current, of one name and type, the values, of ttl, by changes: the
// missing ones made first, so the name always has some, then those of other values, and the
// second of a value, deleted, and the TTL of those kept made ttl. canonical is a value as values
// have it, false for one that isn't of the type.
func reconcile(current []providerRecord, values []string, ttl int, canonical func(string) (string, bool), changes recordChanges) error {
	have := make(map[string]bool)
	for _, r := range current {
		v, ok := canonical(r.Value)
		if !ok {
			return fmt.Errorf("a record isn't of its type: %s", r.Value)
		}
		have[v] = true
	}
	want := make(map[string]bool)
	for _, v := range values {
		want[v] = true
		if have[v] {
			continue
		}
		if err := changes.create(v); err != nil {
			return fmt.Errorf("making the record %s: %w", v, err)
		}
	}
	kept := make(map[string]bool)
	for _, r := range current {
		v, _ := canonical(r.Value)
		if !want[v] || kept[v] {
			if err := changes.remove(r); err != nil {
				return fmt.Errorf("deleting the record %s: %w", v, err)
			}
			continue
		}
		kept[v] = true
		if r.TTL != ttl {
			if err := changes.setTTL(r); err != nil {
				return fmt.Errorf("setting the TTL of the record %s: %w", v, err)
			}
		}
	}
	return nil
}
