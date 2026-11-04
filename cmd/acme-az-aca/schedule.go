package main

import (
	"math/rand/v2"
	"time"
)

// jitterFraction is how far, either way, each wait between cycles may
// drift from its configured length.
const jitterFraction = 10 // ±1/10 = ±10%

// jitter returns d moved by a uniformly random amount within ±10%, so that
// instances started together (one pipeline deploying many Container Apps,
// a platform-wide restart) drift apart instead of hitting Let's Encrypt in
// the same second every day, as Let's Encrypt asks of ACME clients.
func jitter(d time.Duration) time.Duration {
	spread := d / jitterFraction
	if spread <= 0 {
		return d
	}
	return d - spread + rand.N(2*spread+1)
}
