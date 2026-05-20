package collector

import "testing"

func TestTruncate_WithinCap(t *testing.T) {
	items := []int{3, 1, 2}
	kept, dropped, truncated := Truncate(items, 5, func(a, b int) bool { return a < b })

	if truncated {
		t.Error("expected truncated=false when within cap")
	}
	if dropped != 0 {
		t.Errorf("expected dropped=0, got %d", dropped)
	}
	// Within-cap returns the slice unchanged (not sorted).
	if len(kept) != 3 || kept[0] != 3 {
		t.Errorf("expected unchanged slice, got %v", kept)
	}
}

func TestTruncate_AtCap(t *testing.T) {
	items := []int{3, 1, 2}
	_, dropped, truncated := Truncate(items, 3, func(a, b int) bool { return a < b })

	if truncated {
		t.Error("expected truncated=false at exactly cap")
	}
	if dropped != 0 {
		t.Errorf("expected dropped=0, got %d", dropped)
	}
}

func TestTruncate_OverCap(t *testing.T) {
	items := []int{5, 1, 4, 2, 3}
	kept, dropped, truncated := Truncate(items, 2, func(a, b int) bool { return a < b })

	if !truncated {
		t.Error("expected truncated=true over cap")
	}
	if dropped != 3 {
		t.Errorf("expected dropped=3, got %d", dropped)
	}
	// Sorted ascending, first 2 kept: 1, 2.
	if len(kept) != 2 || kept[0] != 1 || kept[1] != 2 {
		t.Errorf("expected [1 2], got %v", kept)
	}
}

func TestTruncate_StableOrder(t *testing.T) {
	type row struct {
		key int
		seq int
	}
	items := []row{
		{key: 1, seq: 0},
		{key: 1, seq: 1},
		{key: 1, seq: 2},
		{key: 0, seq: 3},
	}
	kept, _, truncated := Truncate(items, 3, func(a, b row) bool { return a.key < b.key })
	if !truncated {
		t.Fatal("expected truncated=true")
	}
	// key=0 sorts first; the three key=1 rows keep their original relative order.
	if kept[0].key != 0 || kept[1].seq != 0 || kept[2].seq != 1 {
		t.Errorf("stable sort violated: %+v", kept)
	}
}
