package main

import (
	"encoding/xml"
	"flag"
	"fmt"
	"github.com/scottdware/go-rested"
	"os"
	"strings"
)

type CVE struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	Description string `xml:"description"`
	Date        string `xml:"date"`
}

type Vulnerabilities struct {
	XMLName xml.Name `xml:"RDF"`
	CVEs    []CVE    `xml:"item"`
}

var (
	rssNormal   = "https://nvd.nist.gov/download/nvd-rss.xml"
	rssAnalyzed = "https://nvd.nist.gov/download/nvd-rss-analyzed.xml"
	vulns       Vulnerabilities
	l           bool
	cve         string
	a           bool
)

func init() {
	flag.Usage = func() {
		fmt.Println("cveget - List recent CVE's and view information about them.\n")
		fmt.Println("Usage: cveget [OPTIONS]\n")
		flag.PrintDefaults()
		os.Exit(0)
	}
	flag.BoolVar(&l, "l", false, "List all CVE's within the previous eight days.")
	flag.BoolVar(&a, "a", false, "Provides only vulnerabilities which have been analyzed within the previous eight days.")
	flag.StringVar(&cve, "cve", "", "Specify a CVE to view information on.")
	flag.Parse()

	if !l && cve == "" {
		flag.Usage()
	}
}

func main() {
	feedData := rested.Send(rssNormal, nil)
	if feedData.Error != nil {
		fmt.Println(feedData.Error)
	}

	if a {
		feedData = rested.Send(rssAnalyzed, nil)
		if feedData.Error != nil {
			fmt.Println(feedData.Error)
		}
	}

	if err := xml.Unmarshal(feedData.Body, &vulns); err != nil {
		fmt.Println(err)
	}

	for _, c := range vulns.CVEs {
		if l {
			fmt.Println(c.Title)
		}

		if !l {
			if strings.Contains(c.Title, cve) {
				fmt.Printf("%s\n\n", c.Title)
				fmt.Printf("Published: %s\n", c.Date)
				fmt.Printf("%s\n\n", c.Link)
				fmt.Printf("%s\n\n", c.Description)
			}
		}
	}
}
