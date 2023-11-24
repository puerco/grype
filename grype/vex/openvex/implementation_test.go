package openvex

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIdentifiersFromInput(t *testing.T) {
	for _, tc := range []struct {
		name     string
		input    string
		expected []string
		mustErr  bool
	}{
		{
			name:  "basic image name",
			input: "alpine",
			//input:    "alpine@sha256:eece025e432126ce23f223450a0326fbebde39cdf496a85d8c016293fc851978",
			expected: []string{"a"},
			mustErr:  false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := identifiersFromInput(tc.input, "linux", "amd64")
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, res, tc.expected)
		})
	}
}

func TestIdentifiersFromDigests(t *testing.T) {
	for _, tc := range []struct {
		sut      string
		expected []string
	}{
		{
			"alpine@sha256:124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
			[]string{
				"alpine@sha256:124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
				"pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126?repository_url=index.docker.io/library",
				"124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
			},
		},
		{
			"cgr.dev/chainguard/curl@sha256:9543ed09a38605c25c75486573cf530bd886615b993d5e1d1aa58fe5491287bc",
			[]string{
				"cgr.dev/chainguard/curl@sha256:9543ed09a38605c25c75486573cf530bd886615b993d5e1d1aa58fe5491287bc",
				"pkg:oci/curl@sha256%3A9543ed09a38605c25c75486573cf530bd886615b993d5e1d1aa58fe5491287bc?repository_url=cgr.dev/chainguard",
				"9543ed09a38605c25c75486573cf530bd886615b993d5e1d1aa58fe5491287bc",
			},
		},
		{
			"alpine",
			[]string{"alpine"},
		},
	} {
		res := identifiersFromDigests([]string{tc.sut})
		require.Equal(t, tc.expected, res)
	}
}
