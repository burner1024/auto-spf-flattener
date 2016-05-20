package main

import (
	"fmt"
	dns "github.com/lordbyron/auto-spf-flattener/dns"
	cf "github.com/lordbyron/auto-spf-flattener/dns/cloudflare"
	spf "github.com/lordbyron/auto-spf-flattener/spf"
	flag "github.com/spf13/pflag"
	"io/ioutil"
	"os"
	"strings"
)

var topDomain string
var spfSubdomainPrefix string
var spfFile string

func init() {
	flag.StringVarP(&spfFile, "spf-file", "f", "", "File that contains a valid spf format TXT record (required)")
	flag.StringVarP(&spfSubdomainPrefix, "spf-prefix", "p", "_spf", "Prefix for subdomains when multiple are needed.")
	flag.Parse()

	if flag.NArg() != 1 || spfFile == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -f spf-file [-p subdomain-prefix] domain\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Use the SPF record you would have put in your DNS if you weren't worried about too many lookups or too large a response\n")
		fmt.Fprintf(os.Stderr, "Environment variables CF_API_EMAIL and CF_API_KEY are required\n\n")
		flag.PrintDefaults()
		os.Exit(1)
	}
	topDomain = flag.Arg(0)
}

func main() {

	//printer := &dns.DNSPrinter{}
	client := cf.NewCloudflareAPIClient(topDomain)

	updater := dns.NewDNSUpdater(client, topDomain, spfSubdomainPrefix)

	dat, err := ioutil.ReadFile(spfFile)
	if err != nil {
		panic(err)
	}
	spfString := strings.TrimSpace(string(dat))

	idealSPF := spf.NewSPF()
	idealSPF.Parse(spfString)

	err = updater.Update(idealSPF)
	if err != nil {
		fmt.Println(err)
	}
}
