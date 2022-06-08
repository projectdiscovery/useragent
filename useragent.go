package useragent

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
	if err := json.Unmarshal([]byte(userAgentsData), &UserAgents); err != nil {
		panic(err)
	}
}

var UserAgents []*UserAgent

type UserAgent struct {
	Tags []string
	Raw  string
}

func (userAgent *UserAgent) String() string {
	return userAgent.Raw
}

func Pick(n int) ([]*UserAgent, error) {
	if n > len(UserAgents) {
		return nil, fmt.Errorf("the database does not contain %d items", n)
	}
	var userAgents []*UserAgent
	for i := 0; i < n; i++ {
		randomIndex := rand.Intn(len(UserAgents))
		userAgent := UserAgents[randomIndex]
		userAgents = append(userAgents, userAgent)
	}
	return userAgents, nil
}

func PickWithFilters(n int, filters ...Filter) ([]*UserAgent, error) {
	if n > len(UserAgents) {
		return nil, fmt.Errorf("the database does not contain %d items", n)
	}
	// filters out wanted ones
	var filteredUserAgents []*UserAgent
	for _, ua := range UserAgents {
		for _, filter := range filters {
			if !filter(ua) {
				continue
			}
			filteredUserAgents = append(filteredUserAgents, ua)
		}
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
