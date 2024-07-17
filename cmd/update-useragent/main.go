package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"

	"github.com/projectdiscovery/useragent"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

var (
	userAgentData = flag.String("user-agents", "../../useragent_data.json", "File to write user agents to")
	browsers      = []string{"chrome", "edge", "safari", "firefox", "firefox-esr"}
)

func main() {
	flag.Parse()

	userAgents := getUserAgents()
	if len(userAgents) == 0 {
		log.Fatal("Couldn't get user agents. The user agent data will remain unchanged.")
	}
	data, err := json.Marshal(userAgents)
	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile(*userAgentData, data, 0644)
	if err != nil {
		log.Fatal(err)
	}

}

func getUserAgents() []*useragent.UserAgent {
	var userAgents []*useragent.UserAgent

	httpClient := buildHttpClient()
	for _, browser := range browsers {
		whatismybrowserApiUrl := fmt.Sprintf(`https://api.whatismybrowser.com/api/v2/user_agent_database_search?order_by=times_seen%%20desc&hardware_type=computer&limit=300&offset=500&software_name=%s`, browser)
		req, err := http.NewRequest("GET", whatismybrowserApiUrl, nil)
		if err != nil {
			continue
		}
		apiKey := os.Getenv("WHATISMYBROWSER_KEY")
		if apiKey == "" {
			log.Fatal("API key is empty. Please set the WHATISMYBROWSER_KEY environment variable.")
		}
		req.Header.Add("X-API-KEY", apiKey)

		resp, err := httpClient.Do(req)
		if err != nil {
			continue
		}

		data, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		var whatismybrowserResponse WhatismybrowserResponse
		err = json.Unmarshal(data, &whatismybrowserResponse)
		if err != nil {
			continue
		}
		for _, userAgent := range whatismybrowserResponse.SearchResults.UserAgents {
			if stringsutil.ContainsAnyI(userAgent.UserAgent,
				"sleep", "timeout", "get-help", "start", "system",
				"Functionize", "Edg/", "assetnote", "gzip", "norton",
				"avast", "ccleaner", "avg", "xtpt", "promptmanager", "SznProhlizec",
				"(0-0)", "unknown", "ddg", "opx", "RDDocuments", "Reeder",
				"Topee", "TulipSAT", "Opendium", "DingTalk", "Gear",
				"GoodAccess", "uacq") ||
				hasUidSuffix(userAgent.UserAgent) {
				continue
			}

			tags := buildTags(userAgent)
			userAgent := &useragent.UserAgent{
				Raw:  userAgent.UserAgent,
				Tags: sliceutil.Dedupe(sliceutil.PruneEmptyStrings(tags)),
			}
			userAgents = append(userAgents, userAgent)
		}
	}
	return userAgents
}

func hasUidSuffix(s string) bool {
	var guidPattern = regexp.MustCompile(`\(?[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}\)?$`)
	return guidPattern.MatchString(s)
}

func buildTags(userAgent UserAgents) []string {
	var tags []string
	tags = append(tags, userAgent.Parse.SimpleSoftwareString)
	tags = append(tags, fmt.Sprintf("%v", userAgent.Parse.SimpleSubDescriptionString))
	tags = append(tags, fmt.Sprintf("%v", userAgent.Parse.SimpleOperatingPlatformString))
	tags = append(tags, userAgent.Parse.Software)
	tags = append(tags, userAgent.Parse.SoftwareName)
	tags = append(tags, userAgent.Parse.SoftwareNameCode)
	tags = append(tags, userAgent.Parse.SoftwareVersion)
	tags = append(tags, userAgent.Parse.SoftwareVersionFull)
	tags = append(tags, userAgent.Parse.OperatingSystem)
	tags = append(tags, userAgent.Parse.OperatingSystemName)
	tags = append(tags, userAgent.Parse.OperatingSystemNameCode)
	tags = append(tags, userAgent.Parse.OperatingSystemVersion)
	tags = append(tags, userAgent.Parse.OperatingSystemVersionFull)
	tags = append(tags, fmt.Sprintf("%v", userAgent.Parse.OperatingPlatform))
	tags = append(tags, fmt.Sprintf("%v", userAgent.Parse.OperatingPlatformCode))
	tags = append(tags, fmt.Sprintf("%v", userAgent.Parse.OperatingPlatformVendorName))
	tags = append(tags, userAgent.Parse.SoftwareType)
	tags = append(tags, userAgent.Parse.SoftwareSubType)
	tags = append(tags, userAgent.Parse.HardwareType)
	tags = append(tags, fmt.Sprintf("%v", userAgent.Parse.HardwareSubType))
	tags = append(tags, fmt.Sprintf("%v", userAgent.Parse.HardwareSubSubType))
	tags = append(tags, userAgent.Parse.SoftwareTypeSpecific)
	tags = append(tags, userAgent.Parse.HardwareTypeSpecific)
	tags = append(tags, userAgent.Parse.LayoutEngineName)

	return tags
}

// buildHttpClient with common options
func buildHttpClient() *http.Client {
	transport := http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	return &http.Client{Transport: &transport}
}

type UserAgentMetaData struct {
	ID         int    `json:"id"`
	TimesSeen  int    `json:"times_seen"`
	LastSeenAt string `json:"last_seen_at"`
}

type Parse struct {
	SimpleSoftwareString          string `json:"simple_software_string"`
	SimpleSubDescriptionString    any    `json:"simple_sub_description_string"`
	SimpleOperatingPlatformString any    `json:"simple_operating_platform_string"`
	Software                      string `json:"software"`
	SoftwareName                  string `json:"software_name"`
	SoftwareNameCode              string `json:"software_name_code"`
	SoftwareVersion               string `json:"software_version"`
	SoftwareVersionFull           string `json:"software_version_full"`
	OperatingSystem               string `json:"operating_system"`
	OperatingSystemName           string `json:"operating_system_name"`
	OperatingSystemNameCode       string `json:"operating_system_name_code"`
	OperatingSystemVersion        string `json:"operating_system_version"`
	OperatingSystemVersionFull    string `json:"operating_system_version_full"`
	OperatingPlatform             any    `json:"operating_platform"`
	OperatingPlatformCode         any    `json:"operating_platform_code"`
	OperatingPlatformVendorName   any    `json:"operating_platform_vendor_name"`
	SoftwareType                  string `json:"software_type"`
	SoftwareSubType               string `json:"software_sub_type"`
	HardwareType                  string `json:"hardware_type"`
	HardwareSubType               any    `json:"hardware_sub_type"`
	HardwareSubSubType            any    `json:"hardware_sub_sub_type"`
	SoftwareTypeSpecific          string `json:"software_type_specific"`
	HardwareTypeSpecific          string `json:"hardware_type_specific"`
	LayoutEngineName              string `json:"layout_engine_name"`
}

type UserAgents struct {
	UserAgent         string            `json:"user_agent"`
	UserAgentMetaData UserAgentMetaData `json:"user_agent_meta_data"`
	Parse             Parse             `json:"parse"`
}

type SearchParameters struct {
	SoftwareName string `json:"software_name"`
	HardwareType string `json:"hardware_type"`
}

type SearchMetaData struct {
	NumOfResultsReturned   int              `json:"num_of_results_returned"`
	SearchTookMilliseconds int              `json:"search_took_milliseconds"`
	SearchParameters       SearchParameters `json:"search_parameters"`
}

type Result struct {
	Code        string `json:"code"`
	MessageCode string `json:"message_code"`
	Message     string `json:"message"`
}

type SearchResults struct {
	UserAgents     []UserAgents   `json:"user_agents"`
	SearchMetaData SearchMetaData `json:"search_meta_data"`
}

type WhatismybrowserResponse struct {
	SearchResults SearchResults `json:"search_results"`
	Result        Result        `json:"result"`
}
