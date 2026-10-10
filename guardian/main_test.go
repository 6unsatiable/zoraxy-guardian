package guardian

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	runFeedLoop = false
	os.Exit(m.Run())
}
