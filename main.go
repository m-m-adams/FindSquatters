package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/m-m-adams/squatcobbler/attacks"
	"github.com/m-m-adams/squatcobbler/domain"
)

type domaincheck struct {
	result domain.AttackDomain
	err    error
}

func getDomainInfo(modified domain.Domain, whoisLookup bool, c chan domaincheck) {
	att, err := domain.AttackFromURL(modified, whoisLookup)

	c <- domaincheck{att, err}

}

func unique(input []domain.Domain) (output []domain.Domain) {
	inmap := make(map[string]domain.Domain)

	for _, dom := range input {
		url, _ := dom.ToURL()
		inmap[url] = dom
	}

	for _, v := range inmap {
		output = append(output, v)
	}
	return
}

func generateTypos(input []string) (uniquetypos []domain.Domain) {
	squatted := []domain.Domain{}
	for _, inputdomain := range input {
		original, err := domain.FromURL(inputdomain)
		if err != nil {
			fmt.Println(err)
		} else {
			for _, attack := range attacks.All {
				squatted = append(squatted, attack(original)...)
			}
		}

	}

	uniquetypos = unique(squatted)
	return
}

func typosquatter(input []string, output *bufio.Writer, whoisLookup bool) (code int) {

	uniquetypos := generateTypos(input)
	output.WriteString("[")
	results := make(chan domaincheck)

	counter := 0
	for _, typo := range uniquetypos {
		counter++

		go getDomainInfo(typo, whoisLookup, results)
	}

	domainArr := make([]domain.AttackDomain, counter)
	for i := 0; i < counter; i++ {
		r := <-results

		domainArr[i] = r.result

	}

	for i, d := range domainArr {
		fmt.Println(d)

		if len(d.IPaddr) > 0 {
			att, _ := json.MarshalIndent(d, "", "	")
			var err error
			if i == (len(domainArr) - 1) {
				_, err = output.WriteString(string(att))
				if err != nil {
					fmt.Println(err)
					return -1
				}
			} else {
				_, err = output.WriteString(string(att) + ",")
				if err != nil {
					fmt.Println(err)
					return -1
				}
			}

			if err != nil {
				fmt.Println(err)
			}
		}
	}

	output.WriteString("]\n")
	if output.Buffered() < 4 {
		return -1
	}
	output.Flush()
	return 0
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func main() {
	inputlist := flag.String("i", "", "a file to read input from or a single domain input")
	outputfile := flag.String("o", "", "a file to write output to, otherwise goes to stdout")
	whoisLookup := flag.Bool("whois", false, "if true lookup whois for all domains")

	flag.Parse()

	var domains []string

	if len(*inputlist) == 0 {
		fmt.Println("No input domains given")
		os.Exit(-1)
	}
	if _, err := os.Stat(*inputlist); os.IsNotExist(err) {
		domains = []string{*inputlist}
	} else {
		domains, err = readLines(*inputlist)
		if err != nil {
			fmt.Println(err)
			panic(err)
		}
	}

	var output io.Writer
	if len(*outputfile) == 0 {
		output = os.Stdout
		writer := bufio.NewWriter(output)
		os.Exit(typosquatter(domains, writer, *whoisLookup))
	} else {
		output, err := os.Create(*outputfile)

		if err != nil {
			fmt.Println(err)
			panic(err)
		}

		defer output.Close()
		writer := bufio.NewWriter(output)
		os.Exit(typosquatter(domains, writer, *whoisLookup))
	}

}
