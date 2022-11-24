# useragent
Curated list of categorized User Agents


# Usage

- [ua](cmd/ua/main.go)

```sh
ua is a simple user agent query tool which parses user agents from multiple sources

Usage:
  ./ua [flags]

Flags:
   -list           list all tags
   -count int      maximum number of user agents (default 5)
   -tags string[]  filter user agents using tags (csv)
```

- [update-user-agents](cmd/update-user-agents/main.go)

```sh
Usage of ./update-user-agents:
  -user-agents string
    	File to write user agents to (default "../../useragent_data.json")
```