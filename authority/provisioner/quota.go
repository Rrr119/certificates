package provisioner

import (
	"context"
	stderrors "errors"
	"fmt"
	"sync"
	"time"
)

// ErrQuotaExceeded is returned when a provisioner has reached its configured
// issuance quota.
var ErrQuotaExceeded = stderrors.New("provisioner quota exceeded")

// Quota configures per-provisioner issuance quotas. It is intended for
// internal CAs that issue short-lived certificates to multiple teams, where
// each team gets its own provisioner with its own quota.
type Quota struct {
	// MaxActive is the maximum number of active (not expired, not revoked)
	// certificates the provisioner is allowed to have at any point in time.
	// Certificates that expire or are revoked free up their slot. A value
	// of 0 (or an unset Quota) means no quota is enforced.
	MaxActive int `json:"maxActive,omitempty"`
}

// Validate returns an error if the quota configuration is invalid.
func (q *Quota) Validate() error {
	if q == nil {
		return nil
	}
	if q.MaxActive < 0 {
		return fmt.Errorf("quota maxActive cannot be negative")
	}
	return nil
}

// QuotaLimiter is implemented by provisioners that enforce an issuance
// quota. The authority acquires a slot before signing a certificate and
// releases it when the certificate is revoked.
type QuotaLimiter interface {
	// AcquireQuota reserves a quota slot for a new certificate. It returns
	// a nil reservation and no error when no quota is configured.
	AcquireQuota(ctx context.Context) (*QuotaReservation, error)
	// ReleaseQuota frees the quota slot held by the certificate with the
	// given (decimal) serial number.
	ReleaseQuota(serialNumber string)
}

// quotaProvider is implemented by provisioners that expose a quota
// configuration.
type quotaProvider interface {
	GetQuota() *Quota
}

// quotaTracker tracks the number of active certificates for a single
// provisioner. It is safe for concurrent use.
type quotaTracker struct {
	mu        sync.Mutex
	maxActive int
	counter   uint64
	reserved  map[string]struct{}  // reservation IDs holding a slot
	active    map[string]time.Time // certificate serial number -> NotAfter
}

// newQuotaTracker returns a quotaTracker enforcing maxActive active
// certificates.
func newQuotaTracker(maxActive int) *quotaTracker {
	return &quotaTracker{
		maxActive: maxActive,
		reserved:  make(map[string]struct{}),
		active:    make(map[string]time.Time),
	}
}

// acquire reserves a quota slot, returning a reservation that must either be
// committed once the certificate has been signed or rolled back when signing
// fails. Expired certificates are purged lazily, so short-lived certificates
// automatically free their slot once their validity period ends.
func (t *quotaTracker) acquire(now time.Time) (*QuotaReservation, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.purgeExpiredLocked(now)

	if t.maxActive > 0 && len(t.reserved)+len(t.active) >= t.maxActive {
		return nil, ErrQuotaExceeded
	}

	t.counter++
	id := fmt.Sprintf("reservation-%d", t.counter)
	t.reserved[id] = struct{}{}

	return &QuotaReservation{tracker: t, id: id}, nil
}

// release frees the slot held by the certificate with the given serial
// number. It is a no-op if the serial number is not tracked.
func (t *quotaTracker) release(serialNumber string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.active, serialNumber)
}

// count returns the number of currently held slots, including uncommitted
// reservations. Expired entries are purged first.
func (t *quotaTracker) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.purgeExpiredLocked(time.Now())
	return len(t.reserved) + len(t.active)
}

// purgeExpiredLocked removes entries for certificates that have expired.
// Callers must hold t.mu.
func (t *quotaTracker) purgeExpiredLocked(now time.Time) {
	for serial, notAfter := range t.active {
		if now.After(notAfter) {
			delete(t.active, serial)
		}
	}
}

// QuotaReservation represents a reserved quota slot for a certificate that
// is being signed. Exactly one of Commit or Rollback has an effect; calling
// either more than once is a no-op.
type QuotaReservation struct {
	tracker *quotaTracker
	id      string
	mu      sync.Mutex
	done    bool
}

// Commit converts the reservation into an active slot for the certificate
// with the given (decimal) serial number and expiration time.
func (r *QuotaReservation) Commit(serialNumber string, notAfter time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done {
		return
	}
	r.done = true

	t := r.tracker
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.reserved, r.id)
	t.active[serialNumber] = notAfter
}

// Rollback frees the reserved slot, e.g. when signing the certificate
// failed.
func (r *QuotaReservation) Rollback() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done {
		return
	}
	r.done = true

	t := r.tracker
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.reserved, r.id)
}
