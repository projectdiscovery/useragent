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
	uas, err := PickWithFilters(1, Desktop)
	require.Nil(t, err, "could not pick user agent")
	require.Len(t, uas, 1, "unexpected length")
}
