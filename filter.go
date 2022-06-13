package useragent

import (
	"strings"

	"github.com/projectdiscovery/stringsutil"
)

// Filter represent the function signature for a filter
type Filter func(*UserAgent) bool

// ContainsTagsAny returns true if the user agent contains any of the provided tags
func ContainsTagsAny(userAgent *UserAgent, tags ...string) bool {
	for _, tag := range userAgent.Tags {
		if stringsutil.ContainsAny(tag, tags...) {
			return true
		}
	}
	return false
}

// ContainsTags returns true if the user agent contains all provided tags
func ContainsTags(userAgent *UserAgent, tags ...string) bool {
	foundTags := make(map[string]struct{})
	for _, tag := range userAgent.Tags {
		for _, wantedTag := range tags {
			if strings.Contains(tag, wantedTag) {
				foundTags[tag] = struct{}{}
			}
		}
	}
	return len(foundTags) == len(tags)
}

// Mobile checks if the user agent has typical mobile tags
func Mobile(userAgent *UserAgent) bool {
	return ContainsTags(userAgent, "mobile")
}

// Mobile checks if the user agent has typical desktop tags
func Desktop(userAgent *UserAgent) bool {
	return ContainsTags(userAgent, "desktop")
}

// Mobile checks if the user agent has typical apple tags
func Apple(userAgent *UserAgent) bool {
	return ContainsTags(userAgent, "Apple Computer, Inc.")
}

// Mobile checks if the user agent has typical windows tags
func Windows(userAgent *UserAgent) bool {
	return ContainsTagsAny(userAgent, "Win32", "Windows")
}

// Mobile checks if the user agent has typical bot tags
func Bot(userAgent *UserAgent) bool {
	return ContainsTagsAny(userAgent, "Spiders - Search")
}
