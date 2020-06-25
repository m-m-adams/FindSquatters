package domain

import (
	"fmt"
	"strings"

	"golang.org/x/net/idna"
)

//Domain represents a domain as a struct of Subdomains...SLD.TLD
type Domain struct {
	Original  string
	TLD       string
	SLD       string
	Subdomain string
}

//FromURL generates a domain from a url string
func FromURL(url string) (dom Domain, err error) {

	dom.Original = url

	parts := strings.Split(url, ".")

	if len(parts) < 2 {
		err := fmt.Errorf("Error in domain %s: domain must have a tld and sld", url)
		return *new(Domain), err
	}

	dom.TLD = parts[len(parts)-1]

	dom.SLD = parts[len(parts)-2]

	if len(parts) > 2 {
		dom.Subdomain = strings.Join(parts[:len(parts)-2], ".")
	}

	return dom, nil
}

//ToURL recomposes a domain to a string with punycode encoding for UTF
func (dom Domain) ToURL() (url string, err error) {

	unicode := strings.Join([]string{dom.SLD, dom.TLD}, ".")

	url, err = idna.ToASCII(unicode)

	if err != nil {
		fmt.Println(err)
		return "", err
	}

	return url, nil
}

//ToString converts a domain directly to its string representation
func (dom Domain) ToString() (url string) {
	if len(dom.Subdomain) > 0 {
		url = strings.Join([]string{dom.Subdomain, dom.SLD, dom.TLD}, ".")
	} else {
		url = strings.Join([]string{dom.SLD, dom.TLD}, ".")
	}
	return
}
