package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/miekg/dns"
)

// DNSQuerier handles DNS queries
type DNSQuerier struct {
	client *dns.Client
	server string
}

// NewDNSQuerier creates a new DNS querier
func NewDNSQuerier(server string) *DNSQuerier {
	if server == "" {
		server = "8.8.8.8:53" // Default to Google DNS
	}
	return &DNSQuerier{
		client: &dns.Client{},
		server: server,
	}
}

// QueryRecord performs a DNS query for the specified record type
func (dq *DNSQuerier) QueryRecord(domain string, recordType uint16) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), recordType)
	msg.RecursionDesired = true

	response, _, err := dq.client.Exchange(msg, dq.server)
	if err != nil {
		return nil, fmt.Errorf("DNS query failed: %v", err)
	}

	if response.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS query failed with rcode: %d", response.Rcode)
	}

	return response, nil
}

// PrintRecord prints DNS records in a readable format
func (dq *DNSQuerier) PrintRecord(domain string, recordType uint16) error {
	response, err := dq.QueryRecord(domain, recordType)
	if err != nil {
		return err
	}

	recordTypeName := dns.TypeToString[recordType]
	fmt.Printf("\n=== %s Records for %s ===\n", recordTypeName, domain)

	if len(response.Answer) == 0 {
		fmt.Printf("No %s records found\n", recordTypeName)
		return nil
	}

	for _, record := range response.Answer {
		switch r := record.(type) {
		case *dns.A:
			fmt.Printf("A: %s\n", r.A)
		case *dns.AAAA:
			fmt.Printf("AAAA: %s\n", r.AAAA)
		case *dns.CNAME:
			fmt.Printf("CNAME: %s\n", r.Target)
		case *dns.MX:
			fmt.Printf("MX: %d %s\n", r.Preference, r.Mx)
		case *dns.TXT:
			fmt.Printf("TXT: %s\n", strings.Join(r.Txt, " "))
		case *dns.NS:
			fmt.Printf("NS: %s\n", r.Ns)
		case *dns.PTR:
			fmt.Printf("PTR: %s\n", r.Ptr)
		case *dns.SOA:
			fmt.Printf("SOA: %s %s %d %d %d %d %d\n",
				r.Ns, r.Mbox, r.Serial, r.Refresh, r.Retry, r.Expire, r.Minttl)
		case *dns.SRV:
			fmt.Printf("SRV: %d %d %d %s\n", r.Priority, r.Weight, r.Port, r.Target)
		default:
			fmt.Printf("%s: %s\n", recordTypeName, record.String())
		}
	}

	return nil
}

// QueryAllCommonRecords queries multiple common record types
func (dq *DNSQuerier) QueryAllCommonRecords(domain string) {
	recordTypes := map[string]uint16{
		"A":     dns.TypeA,
		"AAAA":  dns.TypeAAAA,
		"CNAME": dns.TypeCNAME,
		"MX":    dns.TypeMX,
		"TXT":   dns.TypeTXT,
		"NS":    dns.TypeNS,
		"SOA":   dns.TypeSOA,
		"SRV":   dns.TypeSRV,
	}

	for name, recordType := range recordTypes {
		fmt.Printf("\n--- Querying %s records ---\n", name)
		if err := dq.PrintRecord(domain, recordType); err != nil {
			fmt.Printf("Error querying %s records: %v\n", name, err)
		}
	}
}

// GetRecordTypeFromString converts string to DNS record type
func GetRecordTypeFromString(recordTypeStr string) (uint16, error) {
	recordTypeStr = strings.ToUpper(recordTypeStr)

	// Handle common record types
	recordTypes := map[string]uint16{
		"A":     dns.TypeA,
		"AAAA":  dns.TypeAAAA,
		"CNAME": dns.TypeCNAME,
		"MX":    dns.TypeMX,
		"TXT":   dns.TypeTXT,
		"NS":    dns.TypeNS,
		"SOA":   dns.TypeSOA,
		"PTR":   dns.TypePTR,
		"SRV":   dns.TypeSRV,
		"CAA":   dns.TypeCAA,
		"DNAME": dns.TypeDNAME,
		"ANY":   dns.TypeANY,
	}

	if recordType, exists := recordTypes[recordTypeStr]; exists {
		return recordType, nil
	}

	return 0, fmt.Errorf("unsupported record type: %s", recordTypeStr)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <domain> [record_type] [dns_server]\n", os.Args[0])
		fmt.Println("Examples:")
		fmt.Printf("  %s example.com\n", os.Args[0])
		fmt.Printf("  %s example.com A\n", os.Args[0])
		fmt.Printf("  %s example.com TXT 1.1.1.1:53\n", os.Args[0])
		fmt.Println("\nSupported record types: A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, SRV, CAA, DNAME, ANY")
		os.Exit(1)
	}

	domain := os.Args[1]
	var dnsServer string

	// Set DNS server if provided
	if len(os.Args) >= 4 {
		dnsServer = os.Args[3]
		// Add port if not specified
		if !strings.Contains(dnsServer, ":") {
			dnsServer += ":53"
		}
	}

	querier := NewDNSQuerier(dnsServer)

	// If record type is specified
	if len(os.Args) >= 3 {
		recordTypeStr := os.Args[2]
		recordType, err := GetRecordTypeFromString(recordTypeStr)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		fmt.Printf("Querying %s record for %s using DNS server %s\n",
			strings.ToUpper(recordTypeStr), domain, querier.server)

		if err := querier.PrintRecord(domain, recordType); err != nil {
			log.Fatalf("Query failed: %v", err)
		}
	} else {
		// Query all common record types
		fmt.Printf("Querying all common records for %s using DNS server %s\n",
			domain, querier.server)
		querier.QueryAllCommonRecords(domain)
	}
}
