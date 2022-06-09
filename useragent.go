package useragent

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"time"
)

// initialize user agents data
func init() {
	rand.Seed(time.Now().UnixNano())
	if err := json.Unmarshal([]byte(userAgentsData), &UserAgents); err != nil {
		panic(err)
	}
}

// UserAgents of the package
var UserAgents []*UserAgent

// UserAgent with tags
type UserAgent struct {
	Tags []string
	Raw  string
}

// String returns the user agent raw value
func (userAgent *UserAgent) String() string {
	return userAgent.Raw
}

// Pick n items randomly from the available ones
func Pick(n int) ([]*UserAgent, error) {
	return PickWithFilters(n)
}

// Pick n items randomly for the available ones with optional filtering
func PickWithFilters(n int, filters ...Filter) ([]*UserAgent, error) {
	if n > len(UserAgents) {
		return nil, fmt.Errorf("the database does not contain %d items", n)
	}
	// filters out wanted ones
	var filteredUserAgents []*UserAgent
	if len(filters) > 0 {
		for _, ua := range UserAgents {
			for _, filter := range filters {
				if !filter(ua) {
					continue
				}
				filteredUserAgents = append(filteredUserAgents, ua)
			}
		}
	} else {
		filteredUserAgents = UserAgents
	}

	if n > len(filteredUserAgents) {
		return nil, fmt.Errorf("the filtered database does not contain %d items", n)
	}

	var userAgents []*UserAgent
	for i := 0; i < n; i++ {
		randomIndex := rand.Intn(len(filteredUserAgents))
		userAgent := filteredUserAgents[randomIndex]
		userAgents = append(userAgents, userAgent)
	}
	return userAgents, nil
}
