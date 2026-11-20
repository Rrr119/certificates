package provisioner

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestQuota_Validate(t *testing.T) {
	tests := map[string]struct {
		quota *Quota
		err   error
	}{
		"ok/nil":        {quota: nil, err: nil},
		"ok/zero":       {quota: &Quota{}, err: nil},
		"ok/positive":   {quota: &Quota{MaxActive: 10}, err: nil},
		"fail/negative": {quota: &Quota{MaxActive: -1}, err: errors.New("quota maxActive cannot be negative")},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := tc.quota.Validate()
			if tc.err != nil {
				require.EqualError(t, err, tc.err.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestQuotaTracker_AcquireCommitRelease(t *testing.T) {
	now := time.Now()
	tracker := newQuotaTracker(2)

	r1, err := tracker.acquire(now)
	require.NoError(t, err)
	r2, err := tracker.acquire(now)
	require.NoError(t, err)

	// both slots reserved: the next acquire must fail
	_, err = tracker.acquire(now)
	require.ErrorIs(t, err, ErrQuotaExceeded)

	r1.Commit("1001", now.Add(time.Hour))
	require.Equal(t, 2, tracker.count())

	// a committed certificate still holds its slot
	_, err = tracker.acquire(now)
	require.ErrorIs(t, err, ErrQuotaExceeded)

	// releasing an unknown serial is a no-op
	tracker.release("unknown")
	require.Equal(t, 2, tracker.count())

	// releasing a revoked certificate frees its slot
	tracker.release("1001")
	require.Equal(t, 1, tracker.count())

	r3, err := tracker.acquire(now)
	require.NoError(t, err)
	r3.Commit("1002", now.Add(time.Hour))
	require.Equal(t, 2, tracker.count())

	// rolling back a reservation frees its slot
	r2.Rollback()
	require.Equal(t, 1, tracker.count())

	// commit and rollback are idempotent
	r2.Rollback()
	r3.Rollback()
	require.Equal(t, 1, tracker.count())
}

func TestQuotaTracker_Expiry(t *testing.T) {
	now := time.Now()
	tracker := newQuotaTracker(1)

	r, err := tracker.acquire(now)
	require.NoError(t, err)
	// commit a short-lived certificate
	r.Commit("1001", now.Add(time.Minute))

	// after the certificate expired, its slot is freed lazily
	_, err = tracker.acquire(now.Add(2 * time.Minute))
	require.NoError(t, err)
}

func TestQuotaTracker_ConcurrentAcquire(t *testing.T) {
	const maxActive = 8
	const goroutines = 64

	tracker := newQuotaTracker(maxActive)
	now := time.Now()

	var acquired atomic.Int64
	var exceeded atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, err := tracker.acquire(now)
			if err != nil {
				require.ErrorIs(t, err, ErrQuotaExceeded)
				exceeded.Add(1)
				return
			}
			acquired.Add(1)
			r.Commit(fmt.Sprintf("%d", 1000+i), now.Add(time.Hour))
		}(i)
	}
	wg.Wait()

	require.Equal(t, int64(maxActive), acquired.Load())
	require.Equal(t, int64(goroutines-maxActive), exceeded.Load())
	require.Equal(t, maxActive, tracker.count())
}

func TestACME_Quota(t *testing.T) {
	newProvisioner := func(t *testing.T, quota *Quota) *ACME {
		p := &ACME{
			Type:  "ACME",
			Name:  "acme",
			Quota: quota,
		}
		require.NoError(t, p.Init(Config{
			Claims:    globalProvisionerClaims,
			Audiences: testAudiences,
		}))
		return p
	}

	t.Run("ok/enforced", func(t *testing.T) {
		p := newProvisioner(t, &Quota{MaxActive: 1})

		r1, err := p.AcquireQuota(t.Context())
		require.NoError(t, err)
		require.NotNil(t, r1)
		require.Equal(t, 1, p.ctl.ActiveQuotaCount())

		_, err = p.AcquireQuota(t.Context())
		require.ErrorIs(t, err, ErrQuotaExceeded)

		r1.Commit("1001", time.Now().Add(time.Hour))
		p.ReleaseQuota("1001")
		require.Equal(t, 0, p.ctl.ActiveQuotaCount())

		r2, err := p.AcquireQuota(t.Context())
		require.NoError(t, err)
		r2.Rollback()
	})

	t.Run("ok/not-configured", func(t *testing.T) {
		p := newProvisioner(t, nil)
		r, err := p.AcquireQuota(t.Context())
		require.NoError(t, err)
		require.Nil(t, r)
		require.Equal(t, 0, p.ctl.ActiveQuotaCount())
		p.ReleaseQuota("1001") // no-op
	})

	t.Run("fail/negative", func(t *testing.T) {
		p := &ACME{
			Type:  "ACME",
			Name:  "acme",
			Quota: &Quota{MaxActive: -1},
		}
		err := p.Init(Config{
			Claims:    globalProvisionerClaims,
			Audiences: testAudiences,
		})
		require.EqualError(t, err, "quota maxActive cannot be negative")
	})
}
