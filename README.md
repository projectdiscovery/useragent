# useragent
Curated list of categorized User Agents


## Install Instructions

```sh
go install -v github.com/projectdiscovery/useragent/cmd/ua@latest
```

# Usage

~~~
  ua -h
~~~

This will display help for the tool . Here are all the flags it supports:


```sh
ua is simple tool to query and filter user agents

Usage:
  ./ua [flags]

Flags:
   -list           list all tags
   -max int        maximum number of user agents (use -1 to fetch all) (default 5)
   -tags string[]  filter user agents using tags (csv)
```

