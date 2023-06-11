package main

import (
	"fmt"
	"log"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/useragent"
)

type Options struct {
	List bool
	Max  int
	Tags goflags.StringSlice
}

func main() {
	opts := parseInput()

	if opts.List {
		for tag := range useragent.FilterMap {
			fmt.Println(tag)
		}
	} else if len(opts.Tags) != 0 {
		signatures := []useragent.Filter{}
		for _, v := range opts.Tags {
			if v == "all" {
				for _, filter := range useragent.FilterMap {
					signatures = append(signatures, filter)
				}
				break
			}

			if sig, ok := useragent.FilterMap[v]; ok {
				signatures = append(signatures, sig)
			} else {
				log.Fatalf("tag `%v` not found", v)
			}
		}

		uas, err := useragent.PickWithFilters(opts.Max, signatures...)
		if err != nil {
			panic(err)
		}

		for _, v := range uas {
			fmt.Println(v.Raw)
		}
	}

}

func parseInput() *Options {
	opts := Options{}

	flagset := goflags.NewFlagSet()

	flagset.SetDescription("ua is simple tool to query and filter user agents")

	flagset.BoolVar(&opts.List, "list", false, "list all the categorized tags of user-agent")
	flagset.IntVarP(&opts.Max, "limit", "l", 10, "number of user-agent to list (use -1 to list all)")
	flagset.StringSliceVarP(&opts.Tags, "tag", "t", []string{}, "list user-agent for given tag", goflags.CommaSeparatedStringSliceOptions)

	if err := flagset.Parse(); err != nil {
		panic(err)
	}

	return &opts

}
