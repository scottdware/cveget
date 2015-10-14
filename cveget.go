package main

import (
	"crypto/tls"
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
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

func request(uri string) ([]byte, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	url := fmt.Sprintf("%s", uri)
	client := &http.Client{Transport: tr}
	req, _ := http.NewRequest("GET", url, nil)
	res, err := client.Do(req)
	defer res.Body.Close()

	if err != nil {
		return nil, fmt.Errorf("error: %s\n", err)
	}

	data, _ := ioutil.ReadAll(res.Body)

	return data, nil
}

var (
	rssNormal   = "https://nvd.nist.gov/download/nvd-rss.xml"
	rssAnalyzed = "https://nvd.nist.gov/download/nvd-rss-analyzed.xml"
	vulns       Vulnerabilities
	list        bool
	cve         string
	analyzed    bool
)

func init() {
	flag.Usage = func() {
		fmt.Println("cveget - List recent CVE's and view information about them.\n")
		fmt.Println("Usage: cveget [OPTIONS]\n")
		flag.PrintDefaults()
		os.Exit(0)
	}
	flag.BoolVar(&list, "list", false, "List all CVE's within the previous eight days.")
	flag.BoolVar(&analyzed, "analyzed", false, "Provides only vulnerabilities which have been analyzed within the previous eight days.")
	flag.StringVar(&cve, "cve", "", "Specify a CVE to view information on.")
	flag.Parse()
	
	if !list && cve == "" {
		flag.Usage()
	}
}

func main() {
	var feedData []byte

	feedData, err := request(rssNormal)
	if err != nil {
		fmt.Println(err)
	}

	if analyzed {
		feedData, err = request(rssAnalyzed)
		if err != nil {
			fmt.Println(err)
		}
	}

	if err := xml.Unmarshal(feedData, &vulns); err != nil {
		fmt.Println(err)
	}
	
	matches := len(vulns.CVEs)
	
	fmt.Printf("%d total CVE's\n\n", matches)
	
	for n, c := range vulns.CVEs {
		if list {
			fmt.Println(c.Title)
		}

		if !list {
			if strings.Contains(c.Title, cve) {
				fmt.Printf("%d) %s\n\n", n, c.Title)
				fmt.Printf("Published: %s\n", c.Date)
				fmt.Printf("%s\n\n", c.Link)
				fmt.Printf("%s\n\n", c.Description)
			}
		}
	}
}
