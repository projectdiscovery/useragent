package useragent

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPick(t *testing.T) {
	uas, err := Pick(2)
	require.Nil(t, err, "could not pick user agent")
	require.Len(t, uas, 2, "unexpected length")
}

func TestPickWithFilters(t *testing.T) {
	uas, err := PickWithFilters(1, Computer)
	require.Nil(t, err, "could not pick user agent")
	require.Len(t, uas, 1, "unexpected length")
}

func TestPickWithFiltersListsEachMatchOnce(t *testing.T) {
	// "ua -t chrome,windows -l -1" asks for every agent carrying either tag, so the
	// listing holds each of them once, including the ones carrying both.
	var want int
	for _, ua := range UserAgents {
		if Chrome(ua) || Windows(ua) {
			want++
		}
	}

	uas, err := PickWithFilters(-1, Chrome, Windows)
	require.Nil(t, err, "could not pick user agents")

	seen := make(map[string]struct{}, len(uas))
	for _, ua := range uas {
		seen[ua.Raw] = struct{}{}
	}

	require.Equal(t, want, len(uas), "listing holds %d agents, %d match the filters", len(uas), want)
	require.Equal(t, len(uas), len(seen), "listing repeats %d agents", len(uas)-len(seen))
}

func TestPickWithFiltersBoundedCount(t *testing.T) {
	uas, err := PickWithFilters(10, Chrome, Windows)
	require.Nil(t, err, "could not pick user agents")
	require.Len(t, uas, 10, "unexpected length")
}
