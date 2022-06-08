package useragent

import (
	"strings"

	"github.com/projectdiscovery/stringsutil"
)

type Filter func(*UserAgent) bool

func ContainsTagsAny(userAgent *UserAgent, tags ...string) bool {
	for _, tag := range userAgent.Tags {
		if stringsutil.ContainsAny(tag, tags...) {
			return true
		}
	}
	return false
}

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

func Mobile(userAgent *UserAgent) bool {
	return ContainsTags(userAgent, "mobile")
}

func Desktop(userAgent *UserAgent) bool {
	return ContainsTags(userAgent, "desktop")
}

func Apple(userAgent *UserAgent) bool {
	return ContainsTags(userAgent, "Apple Computer, Inc.")
}

func Windows(userAgent *UserAgent) bool {
	return ContainsTagsAny(userAgent, "Win32", "Windows")
}

func Bot(userAgent *UserAgent) bool {
	return ContainsTagsAny(userAgent, "Spiders - Search")
}
