package collector

import "sort"

// Truncate applies a per-surface cap to a slice. If len(items) is within the cap,
// the slice is returned unchanged with droppedCount=0 and truncated=false. Otherwise
// the slice is sorted stably with the provided less function and the first maxItems
// rows are returned; remaining rows are dropped and truncated=true.
//
// Surfaces use this to keep internal-level output bounded for very large orgs. The
// sort order is the surface's choice so on cap-hit the most useful rows stick:
// users ACTIVE-first then login-asc, groups member-count-desc, system log
// published-desc.
func Truncate[T any](items []T, maxItems int, less func(a, b T) bool) (kept []T, droppedCount int, truncated bool) {
	if len(items) <= maxItems {
		return items, 0, false
	}
	sort.SliceStable(items, func(i, j int) bool { return less(items[i], items[j]) })
	return items[:maxItems], len(items) - maxItems, true
}
