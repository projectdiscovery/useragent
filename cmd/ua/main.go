package main

import (
	"fmt"

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

			signatures = append(signatures, useragent.FilterMap[v])
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

	flagset.BoolVar(&opts.List, "list", false, "list all tags")
	flagset.IntVar(&opts.Max, "max", 5, "maximum number of user agents (use -1 to fetch all)")
	flagset.StringSliceVar(&opts.Tags, "tags", []string{}, "filter user agents using tags (csv)", goflags.CommaSeparatedStringSliceOptions)

	if err := flagset.Parse(); err != nil {
		panic(err)
	}

	return &opts

}
