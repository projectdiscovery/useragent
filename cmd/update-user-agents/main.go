package main

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/antchfx/xmlquery"
	"github.com/projectdiscovery/sliceutil"
	"github.com/projectdiscovery/stringsutil"
	"github.com/projectdiscovery/useragent"
)

var (
	userAgentData = flag.String("user-agents", "../../useragent_data.json", "File to write user agents to")
)

func main() {
	// load user agents from
	flag.Parse()

	uas, err := parseSources()
	if err != nil {
		log.Fatal(err)
	}

	data, err := json.Marshal(uas)
	if err != nil {
		log.Fatal(err)
	}

	// dump to output file
	err = os.WriteFile(*userAgentData, data, 0644)
	if err != nil {
		log.Fatal(err)
	}

}

// getHttpClient with common options
func getHttpClient() *http.Client {
	transport := http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	return &http.Client{Transport: &transport}
}

// parseSources and retrieve a list of user agents with metadata
func parseSources() ([]*useragent.UserAgent, error) {
	uas1, err := parseTechPattern()
	if err != nil {
		return nil, err
	}
	uas2, err := parseGhRepo()
	if err != nil {
		return nil, err
	}

	return append(uas1, uas2...), nil
}

const UrlTechPattern = "https://techpatterns.com/downloads/firefox/useragentswitcher.xml"

// Parses source at "https://techpatterns.com/downloads/firefox/useragentswitcher.xml"
func parseTechPattern() ([]*useragent.UserAgent, error) {
	httpClient := getHttpClient()

	resp, err := httpClient.Get(UrlTechPattern)
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	doc, err := xmlquery.Parse(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	var userAgents []*useragent.UserAgent
	folders := doc.SelectElements("//folder")
	for _, folder := range folders {
		folderDescription := folder.SelectAttr("description")
		if stringsutil.EqualFoldAny(folderDescription, "UA List :: About") {
			continue
		}
		folderAgents := folder.SelectElements("//useragent")
		for _, folderAgent := range folderAgents {
			var tags []string
			tags = append(tags, folder.SelectAttr("description"))
			tags = append(tags, folderAgent.SelectAttr("description"))
			tags = append(tags, folderAgent.SelectAttr("appcodename"))
			tags = append(tags, folderAgent.SelectAttr("appname"))
			tags = append(tags, folderAgent.SelectAttr("appversion"))
			tags = append(tags, folderAgent.SelectAttr("platform"))
			tags = append(tags, folderAgent.SelectAttr("vendor"))
			tags = append(tags, folderAgent.SelectAttr("vendorsub"))

			// add parent folder as tag
			userAgent := &useragent.UserAgent{
				Raw:  folderAgent.SelectAttr("useragent"),
				Tags: sliceutil.Dedupe(sliceutil.PruneEmptyStrings(tags)),
			}
			userAgents = append(userAgents, userAgent)
		}
	}

	return userAgents, nil
}

const UrlGhRepository = "https://github.com/intoli/user-agents/raw/master/src/user-agents.json.gz"

// parseGhRepo at UrlGhRepository
func parseGhRepo() ([]*useragent.UserAgent, error) {
	httpClient := getHttpClient()

	resp, err := httpClient.Get(UrlGhRepository)
	if err != nil {
		return nil, err
	}

	r, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	data, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var uas []intoliUserAgent

	if err := json.Unmarshal(data, &uas); err != nil {
		return nil, err
	}

	var userAgents []*useragent.UserAgent
	for _, ua := range uas {
		var tags []string
		tags = append(tags, ua.AppName)
		tags = append(tags, ua.DeviceCategory)
		tags = append(tags, ua.Platform)
		tags = append(tags, ua.Vendor)

		// add parent folder as tag
		userAgent := &useragent.UserAgent{
			Raw:  ua.UserAgent,
			Tags: sliceutil.Dedupe(sliceutil.PruneEmptyStrings(tags)),
		}
		userAgents = append(userAgents, userAgent)
	}

	return userAgents, nil
}

type intoliConnection struct {
	DownLink      float64 `json:"downlink"`
	EffectiveType string  `json:"effectiveType"`
	RTT           int     `json:"rtt"`
}

type intoliUserAgent struct {
	AppName        string           `json:"appName"`
	Connection     intoliConnection `json:"connection"`
	Platform       string           `json:"platform"`
	PluginsLength  int              `json:"pluginsLength"`
	Vendor         string           `json:"vendor"`
	UserAgent      string           `json:"userAgent"`
	ViewportHeight int              `json:"viewportHeight"`
	ViewportWidth  int              `json:"viewportWidth"`
	DeviceCategory string           `json:"deviceCategory"`
	ScreenHeight   int              `json:"screenHeight"`
	ScreenWidth    int              `json:"screenWidth"`
	Weight         float64          `json:"weight"`
}
