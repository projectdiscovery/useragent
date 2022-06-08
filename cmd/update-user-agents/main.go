package main

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
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
	userAgentData = flag.String("user-agents", "../../useragent_data.go", "File to write user agents to")
)

func main() {
	// load user agents from
	flag.Parse()
	uastp, err := parseTechPattern()
	if err != nil {
		log.Fatal(err)
	}
	uasi, err := parseIntoli()
	if err != nil {
		log.Fatal(err)
	}

	data, err := json.Marshal(append(uastp, uasi...))
	if err != nil {
		log.Fatal(err)
	}

	// dump to output file
	fout, err := os.Create(*userAgentData)
	if err != nil {
		log.Fatal(err)
	}
	defer fout.Close()
	_, _ = fout.WriteString(fmt.Sprintf("package useragent\n\nvar userAgentsData = `%s`", string(data)))
}

func getHttpClient() *http.Client {
	transport := http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	return &http.Client{Transport: &transport}
}

func parseTechPattern() ([]*useragent.UserAgent, error) {
	URL := "https://techpatterns.com/downloads/firefox/useragentswitcher.xml"
	httpClient := getHttpClient()

	resp, err := httpClient.Get(URL)
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// data, err := os.ReadFile("useragentswitcher.xml")
	// if err != nil {
	// 	return nil, err
	// }

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
			tags = append(tags, folderAgent.SelectAttr("description"))
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

func parseIntoli() ([]*useragent.UserAgent, error) {
	URL := "https://github.com/intoli/user-agents/raw/master/src/user-agents.json.gz"
	httpClient := getHttpClient()

	resp, err := httpClient.Get(URL)
	if err != nil {
		return nil, err
	}

	r, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	// f, err := os.Open("user-agents.json.gz")
	// if err != nil {
	// 	return nil, err
	// }
	// defer f.Close()

	// r, err := gzip.NewReader(f)
	// if err != nil {
	// 	return nil, err
	// }
	// defer r.Close()

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
