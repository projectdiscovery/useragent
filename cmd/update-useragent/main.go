package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"

	"github.com/projectdiscovery/useragent"
)

var (
	userAgentData = flag.String("user-agents", "../../useragent_data.json", "File to write user agents to")
)

func main() {
	// load user agents from
	flag.Parse()

	userAgentClient := useragent.NewUserAgentClient()
	uas, err := userAgentClient.GetUserAgents()
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
