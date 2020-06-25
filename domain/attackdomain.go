package domain

import (
	"fmt"
	"net"

	"github.com/likexian/whois-go"
	whoisparser "github.com/likexian/whois-parser-go"
)

//AttackDomain contains information about a possible maliciously registered domain
type AttackDomain struct {
	Original         string
	Modified         string
	SLD              string
	IPaddr           []string
	Registrar        string
	RegistrarContact string
	Created          string
	Updated          string
}

//AttackFromURL takes a domain, does a dns request, and if getwhois and dns request work does a whois
func AttackFromURL(modified Domain, getwhois bool) (attack AttackDomain, err error) {
	attack.Original = modified.Original
	attack.Modified = modified.ToString()

	attack.SLD, err = modified.ToURL()
	if err != nil {
		return attack, err
	}

	err = attack.lookupIP()

	if err != nil {
		return attack, err
	}
	if getwhois {
		err = attack.lookupWhoIs()

		if err != nil {
			return attack, err
		}
	}
	return attack, nil
}

func (att *AttackDomain) lookupIP() (err error) {

	ipaddr, err := net.LookupHost(att.SLD)

	if err != nil {
		return err
	}
	att.IPaddr = ipaddr
	return nil

}

func (att *AttackDomain) lookupWhoIs() (err error) {

	who, err := whois.Whois(att.SLD)

	if err != nil {
		fmt.Println(err)
		return err
	}
	//fmt.Println(who)
	result, err := whoisparser.Parse(who)

	if err != nil {
		fmt.Println(err)
		return err
	}
	att.Registrar = result.Registrar.Name
	att.RegistrarContact = result.Registrar.ReferralURL
	att.Created = result.Domain.CreatedDate
	att.Updated = result.Domain.UpdatedDate

	return nil

}
