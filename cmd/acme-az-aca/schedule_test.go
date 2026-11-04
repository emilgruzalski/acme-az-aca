package main

import (
	"testing"
	"time"
)

func TestJitterStaysWithinTenPercent(t *testing.T) {
	for _, d := range []time.Duration{24 * time.Hour, time.Hour, time.Minute, 10 * time.Nanosecond} {
		lo, hi := d-d/10, d+d/10
		for range 1000 {
			if got := jitter(d); got < lo || got > hi {
				t.Fatalf("jitter(%s) = %s, want within [%s, %s]", d, got, lo, hi)
			}
		}
	}
}

func TestJitterSpreadsWaits(t *testing.T) {
	d := 24 * time.Hour
	seen := map[time.Duration]bool{}
	var below, above int
	for range 1000 {
		got := jitter(d)
		seen[got] = true
		switch {
		case got < d:
			below++
		case got > d:
			above++
		}
	}
	// 1000 draws from ~1.7e13 values: a repeat or a one-sided run means the
	// wait is not actually randomized.
	if len(seen) < 990 {
		t.Errorf("only %d distinct waits out of 1000", len(seen))
	}
	if below < 300 || above < 300 {
		t.Errorf("waits not spread around %s: %d below, %d above", d, below, above)
	}
}

func TestJitterLeavesTinyWaitsAlone(t *testing.T) {
	// Below 10ns the spread rounds to zero; the wait must still be positive
	// and unchanged rather than panicking in rand.N.
	for _, d := range []time.Duration{1, 9} {
		if got := jitter(d); got != d {
			t.Errorf("jitter(%d) = %d, want unchanged", d, got)
		}
	}
}
