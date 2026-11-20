package authority

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/errs"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/x509util"
)

// testAuthorityWithACMETeams returns a test authority with one ACME
// provisioner per team, each with its own issuance quota. A quota of 0
// means the team gets no quota configured.
func testAuthorityWithACMETeams(t *testing.T, teams map[string]int, opts ...Option) *Authority {
	p := provisioner.List{}
	for name, maxActive := range teams {
		prov := &provisioner.ACME{
			Name: name,
			Type: "ACME",
		}
		if maxActive > 0 {
			prov.Quota = &provisioner.Quota{MaxActive: maxActive}
		}
		p = append(p, prov)
	}
	c := &Config{
		Address:          "127.0.0.1:443",
		Root:             []string{"testdata/certs/root_ca.crt"},
		IntermediateCert: "testdata/certs/intermediate_ca.crt",
		IntermediateKey:  "testdata/secrets/intermediate_ca_key",
		DNSNames:         []string{"example.com"},
		Password:         "pass",
		AuthorityConfig: &AuthConfig{
			Provisioners: p,
		},
	}
	a, err := New(c, opts...)
	assert.FatalError(t, err)
	return a
}

// acmeTeamSign signs a certificate for cn using the team's ACME provisioner,
// mirroring the way acme.Order.Finalize signs certificates.
func acmeTeamSign(t *testing.T, a *Authority, prov *provisioner.ACME, cn string) ([]*x509.Certificate, error) {
	t.Helper()
	_, priv, err := keyutil.GenerateDefaultKeyPair()
	require.NoError(t, err)
	csr := getCSR(t, priv, func(c *x509.CertificateRequest) {
		c.Subject.CommonName = cn
		c.DNSNames = []string{cn}
	})
	ctx := provisioner.NewContextWithMethod(context.Background(), provisioner.SignMethod)
	signOps, err := prov.AuthorizeSign(ctx, "")
	require.NoError(t, err)
	data := x509util.NewTemplateData()
	data.SetCommonName(cn)
	data.SetSubjectAlternativeNames(x509util.SubjectAlternativeName{
		Type:  x509util.DNSType,
		Value: cn,
	})
	templateOptions, err := provisioner.CustomTemplateOptions(prov.GetOptions(), data, x509util.DefaultLeafTemplate)
	require.NoError(t, err)
	signOps = append(signOps, templateOptions)
	return a.SignWithContext(context.Background(), csr, provisioner.SignOptions{}, signOps...)
}

func mustACMETeam(t *testing.T, a *Authority, name string) *provisioner.ACME {
	t.Helper()
	p, ok := a.provisioners.LoadByName(name)
	require.True(t, ok, "provisioner %q not found", name)
	acmeProv, ok := p.(*provisioner.ACME)
	require.True(t, ok, "provisioner %q is not an ACME provisioner", name)
	return acmeProv
}

// TestAuthority_MultiTeamConcurrentSignQuota simulates multiple teams
// concurrently issuing short-lived certificates, each team through its own
// ACME provisioner with its own quota. The quota must never be exceeded, no
// matter how the sign operations interleave, and teams must not affect each
// other's quota.
func TestAuthority_MultiTeamConcurrentSignQuota(t *testing.T) {
	teams := map[string]int{
		"team-a": 4,
		"team-b": 2,
		"team-c": 0,
	}
	attempts := map[string]int{
		"team-a": 16,
		"team-b": 8,
		"team-c": 6,
	}
	auth := testAuthorityWithACMETeams(t, teams)
	var wg sync.WaitGroup
	succeeded := make(map[string]*atomic.Int64)
	quotaExceeded := make(map[string]*atomic.Int64)
	for name := range teams {
		succeeded[name] = &atomic.Int64{}
		quotaExceeded[name] = &atomic.Int64{}
	}
	for name := range teams {
		prov := mustACMETeam(t, auth, name)
		for i := 0; i < attempts[name]; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				cn := fmt.Sprintf("svc-%d.%s.example.com", i, name)
				chain, err := acmeTeamSign(t, auth, prov, cn)
				if err != nil {
					require.ErrorIs(t, err, provisioner.ErrQuotaExceeded)
					var sc *errs.Error
					require.True(t, errors.As(err, &sc))
					require.Equal(t, http.StatusTooManyRequests, sc.StatusCode())
					quotaExceeded[name].Add(1)
					return
				}
				require.Len(t, chain, 2)
				succeeded[name].Add(1)
			}(i)
		}
	}
	wg.Wait()
	for name, maxActive := range teams {
		if maxActive == 0 {
			require.Equal(t, int64(attempts[name]), succeeded[name].Load(), "team %s", name)
			require.Zero(t, quotaExceeded[name].Load(), "team %s", name)
			continue
		}
		require.Equal(t, int64(maxActive), succeeded[name].Load(), "team %s", name)
		require.Equal(t, int64(attempts[name]-maxActive), quotaExceeded[name].Load(), "team %s", name)
	}
}

// TestAuthority_RevokeReleasesQuota verifies the revocation linkage: revoking
// a certificate frees the provisioner quota slot it held, so a new
// certificate can be issued.
func TestAuthority_RevokeReleasesQuota(t *testing.T) {
	mockDB := &db.MockAuthDB{
		MStoreCertificate: func(crt *x509.Certificate) error {
			return nil
		},
		MRevoke: func(rci *db.RevokedCertificateInfo) error {
			return nil
		},
	}
	auth := testAuthorityWithACMETeams(t, map[string]int{"team-a": 1}, WithDatabase(mockDB))
	prov := mustACMETeam(t, auth, "team-a")
	chain, err := acmeTeamSign(t, auth, prov, "svc-1.team-a.example.com")
	require.NoError(t, err)
	require.Len(t, chain, 2)
	_, err = acmeTeamSign(t, auth, prov, "svc-2.team-a.example.com")
	require.ErrorIs(t, err, provisioner.ErrQuotaExceeded)
	leaf := chain[0]
	err = auth.Revoke(context.Background(), &RevokeOptions{
		Serial:     leaf.SerialNumber.String(),
		ReasonCode: 4,
		ACME:       true,
		Crt:        leaf,
	})
	require.NoError(t, err)
	chain, err = acmeTeamSign(t, auth, prov, "svc-3.team-a.example.com")
	require.NoError(t, err)
	require.Len(t, chain, 2)
	_, err = acmeTeamSign(t, auth, prov, "svc-4.team-a.example.com")
	require.ErrorIs(t, err, provisioner.ErrQuotaExceeded)
}
