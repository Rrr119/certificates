package provisioner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestACMEPolicy_Validate(t *testing.T) {
	tests := map[string]struct {
		policy *ACMEPolicy
		err    string
	}{
		"ok/nil":     {policy: nil},
		"ok/empty":   {policy: &ACMEPolicy{}},
		"ok/dns-ip":  {policy: &ACMEPolicy{AllowedIdentifierTypes: []ACMEIdentifierType{DNS, IP}}},
		"ok/wire":    {policy: &ACMEPolicy{AllowedIdentifierTypes: []ACMEIdentifierType{WireUser, WireDevice}}},
		"fail/bogus": {policy: &ACMEPolicy{AllowedIdentifierTypes: []ACMEIdentifierType{"zar"}}, err: `acme policy allowedIdentifierTypes "zar" is not supported`},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := tc.policy.Validate()
			if tc.err != "" {
				require.EqualError(t, err, tc.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestACME_AuthorizeOrderIdentifier_Policy(t *testing.T) {
	falsePtr := func() *bool { b := false; return &b }

	newProvisioner := func(t *testing.T, policy *ACMEPolicy) *ACME {
		p := &ACME{
			Type:   "ACME",
			Name:   "acme",
			Policy: policy,
		}
		require.NoError(t, p.Init(Config{
			Claims:    globalProvisionerClaims,
			Audiences: testAudiences,
		}))
		return p
	}

	tests := map[string]struct {
		policy     *ACMEPolicy
		identifier ACMEIdentifier
		err        string
	}{
		"ok/no-policy/dns": {
			policy:     nil,
			identifier: ACMEIdentifier{Type: DNS, Value: "test.example.com"},
		},
		"ok/no-policy/wildcard": {
			policy:     nil,
			identifier: ACMEIdentifier{Type: DNS, Value: "*.example.com"},
		},
		"ok/dns-allowed": {
			policy:     &ACMEPolicy{AllowedIdentifierTypes: []ACMEIdentifierType{DNS}},
			identifier: ACMEIdentifier{Type: DNS, Value: "test.example.com"},
		},
		"fail/ip-not-allowed": {
			policy:     &ACMEPolicy{AllowedIdentifierTypes: []ACMEIdentifierType{DNS}},
			identifier: ACMEIdentifier{Type: IP, Value: "192.168.0.1"},
			err:        `acme identifier type "ip" is not allowed by provisioner "acme" policy`,
		},
		"ok/ip-allowed": {
			policy:     &ACMEPolicy{AllowedIdentifierTypes: []ACMEIdentifierType{IP}},
			identifier: ACMEIdentifier{Type: IP, Value: "192.168.0.1"},
		},
		"fail/wildcard-not-allowed": {
			policy:     &ACMEPolicy{AllowWildcardNames: falsePtr()},
			identifier: ACMEIdentifier{Type: DNS, Value: "*.example.com"},
			err:        `wildcard names are not allowed by provisioner "acme" policy`,
		},
		"ok/wildcard-allowed-by-default": {
			policy:     &ACMEPolicy{AllowedIdentifierTypes: []ACMEIdentifierType{DNS}},
			identifier: ACMEIdentifier{Type: DNS, Value: "*.example.com"},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			p := newProvisioner(t, tc.policy)
			err := p.AuthorizeOrderIdentifier(t.Context(), tc.identifier)
			if tc.err != "" {
				require.EqualError(t, err, tc.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
