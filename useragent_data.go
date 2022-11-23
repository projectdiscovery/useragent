package useragent

import (
	_ "embed"
	"encoding/json"
	"math/rand"
	"time"
)

//go:embed useragent_data.json
var userAgentsData string

// initialize user agents data
func init() {
	rand.Seed(time.Now().UnixNano())
	if err := json.Unmarshal([]byte(userAgentsData), &UserAgents); err != nil {
		panic(err)
	}
}
