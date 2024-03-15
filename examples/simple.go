package main

import (
	"fmt"

	"github.com/projectdiscovery/useragent"
)

func main() {
	filters := []useragent.Filter{
		useragent.Chrome,
		useragent.Mozilla,
	}

	max := 10
	uas, err := useragent.PickWithFilters(max, filters...)
	if err != nil {
		panic(err)
	}

	for _, v := range uas {
		fmt.Println(v.Raw)
	}
}
