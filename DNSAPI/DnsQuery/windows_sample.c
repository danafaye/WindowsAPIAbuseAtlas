#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <windns.h>
#include <winsock2.h>
#include <ws2tcpip.h>

// Define DNS_TYPE_TXT if not defined
#ifndef DNS_TYPE_TXT
#define DNS_TYPE_TXT 16
#endif

// Define DNS_TYPE_CAA if not defined
#ifndef DNS_TYPE_CAA
#define DNS_TYPE_CAA 257
#endif

#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "ws2_32.lib")

// Function to get record type name
const char* get_record_type_name(WORD type) {
    switch(type) {
        case DNS_TYPE_A: return "A";
        case DNS_TYPE_NS: return "NS";
        case DNS_TYPE_CNAME: return "CNAME";
        case DNS_TYPE_SOA: return "SOA";
        case DNS_TYPE_PTR: return "PTR";
        case DNS_TYPE_MX: return "MX";
        case DNS_TYPE_TXT: return "TXT";
        case DNS_TYPE_AAAA: return "AAAA";
        case DNS_TYPE_SRV: return "SRV";
        case DNS_TYPE_CAA: return "CAA";
        default: return "UNKNOWN";
    }
}

// Function to get record type from string
WORD get_record_type(const char* type_str) {
    if(_stricmp(type_str, "A") == 0) return DNS_TYPE_A;
    if(_stricmp(type_str, "NS") == 0) return DNS_TYPE_NS;
    if(_stricmp(type_str, "CNAME") == 0) return DNS_TYPE_CNAME;
    if(_stricmp(type_str, "SOA") == 0) return DNS_TYPE_SOA;
    if(_stricmp(type_str, "PTR") == 0) return DNS_TYPE_PTR;
    if(_stricmp(type_str, "MX") == 0) return DNS_TYPE_MX;
    if(_stricmp(type_str, "TXT") == 0) return DNS_TYPE_TXT;
    if(_stricmp(type_str, "AAAA") == 0) return DNS_TYPE_AAAA;
    if(_stricmp(type_str, "SRV") == 0) return DNS_TYPE_SRV;
    if(_stricmp(type_str, "CAA") == 0) return DNS_TYPE_CAA;
    return 0;
}

// Function to print A record
void print_a_record(PDNS_RECORD pRecord) {
    struct in_addr addr;
    addr.s_addr = pRecord->Data.A.IpAddress;
    printf("A: %s (TTL: %d)\n", inet_ntoa(addr), pRecord->dwTtl);
}

// Function to print AAAA record
void print_aaaa_record(PDNS_RECORD pRecord) {
    char ipv6_str[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, &pRecord->Data.AAAA.Ip6Address, ipv6_str, INET6_ADDRSTRLEN) != NULL) {
        printf("AAAA: %s (TTL: %d)\n", ipv6_str, pRecord->dwTtl);
    } else {
        printf("AAAA: [Invalid IPv6 address] (TTL: %d)\n", pRecord->dwTtl);
    }
}

// Function to print CNAME record
void print_cname_record(PDNS_RECORD pRecord) {
    printf("CNAME: %s (TTL: %d)\n", pRecord->Data.CNAME.pNameHost, pRecord->dwTtl);
}

// Function to print NS record
void print_ns_record(PDNS_RECORD pRecord) {
    printf("NS: %s (TTL: %d)\n", pRecord->Data.NS.pNameHost, pRecord->dwTtl);
}

// Function to print MX record
void print_mx_record(PDNS_RECORD pRecord) {
    printf("MX: %d %s (TTL: %d)\n", 
           pRecord->Data.MX.wPreference, 
           pRecord->Data.MX.pNameExchange, 
           pRecord->dwTtl);
}

// Function to print TXT record
void print_txt_record(PDNS_RECORD pRecord) {
    printf("TXT: \"");
    for (DWORD i = 0; i < pRecord->Data.TXT.dwStringCount; i++) {
        if (i > 0) printf(" ");
        printf("%s", pRecord->Data.TXT.pStringArray[i]);
    }
    printf("\" (TTL: %d)\n", pRecord->dwTtl);
}

// Function to print PTR record
void print_ptr_record(PDNS_RECORD pRecord) {
    printf("PTR: %s (TTL: %d)\n", pRecord->Data.PTR.pNameHost, pRecord->dwTtl);
}

// Function to print SOA record
void print_soa_record(PDNS_RECORD pRecord) {
    printf("SOA: %s %s %d %d %d %d %d (TTL: %d)\n",
           pRecord->Data.SOA.pNamePrimaryServer,
           pRecord->Data.SOA.pNameAdministrator,
           pRecord->Data.SOA.dwSerialNo,
           pRecord->Data.SOA.dwRefresh,
           pRecord->Data.SOA.dwRetry,
           pRecord->Data.SOA.dwExpire,
           pRecord->Data.SOA.dwDefaultTtl,
           pRecord->dwTtl);
}

// Function to print SRV record
void print_srv_record(PDNS_RECORD pRecord) {
    printf("SRV: %d %d %d %s (TTL: %d)\n",
           pRecord->Data.SRV.wPriority,
           pRecord->Data.SRV.wWeight,
           pRecord->Data.SRV.wPort,
           pRecord->Data.SRV.pNameTarget,
           pRecord->dwTtl);
}

// Function to print CAA record
void print_caa_record(PDNS_RECORD pRecord) {
    printf("CAA: %d %s \"%s\" (TTL: %d)\n",
           pRecord->Data.CAA.bFlags,
           pRecord->Data.CAA.pTag,
           pRecord->Data.CAA.pValue,
           pRecord->dwTtl);
}

// Function to print DNS record based on type
void print_dns_record(PDNS_RECORD pRecord) {
    switch(pRecord->wType) {
        case DNS_TYPE_A:
            print_a_record(pRecord);
            break;
        case DNS_TYPE_AAAA:
            print_aaaa_record(pRecord);
            break;
        case DNS_TYPE_CNAME:
            print_cname_record(pRecord);
            break;
        case DNS_TYPE_NS:
            print_ns_record(pRecord);
            break;
        case DNS_TYPE_MX:
            print_mx_record(pRecord);
            break;
        case DNS_TYPE_TXT:
            print_txt_record(pRecord);
            break;
        case DNS_TYPE_PTR:
            print_ptr_record(pRecord);
            break;
        case DNS_TYPE_SOA:
            print_soa_record(pRecord);
            break;
        case DNS_TYPE_SRV:
            print_srv_record(pRecord);
            break;
        case DNS_TYPE_CAA:
            print_caa_record(pRecord);
            break;
        default:
            printf("%s: [Unsupported record type] (TTL: %d)\n", 
                   get_record_type_name(pRecord->wType), pRecord->dwTtl);
            break;
    }
}

// Function to perform DNS query using DnsQuery_A (ANSI version)
int dns_query_a(const char* hostname, WORD query_type) {
    PDNS_RECORD pDnsRecord = NULL;
    DNS_STATUS status;
    
    printf("\n=== Using DnsQuery_A (ANSI) ===\n");
    printf("Querying: %s\n", hostname);
    printf("Record type: %s\n", get_record_type_name(query_type));
    
    status = DnsQuery_A(
        hostname,           // Domain name to query
        query_type,         // DNS record type
        DNS_QUERY_STANDARD, // Query options
        NULL,              // Extra DNS servers (NULL for default)
        &pDnsRecord,       // Query results
        NULL               // Reserved
    );
    
    if (status != 0) {
        printf("DnsQuery_A failed with error: %d (0x%08X)\n", status, status);
        
        // Print common error meanings
        switch(status) {
            case DNS_ERROR_RCODE_NAME_ERROR:
                printf("Error: Domain name does not exist\n");
                break;
            case DNS_ERROR_RCODE_SERVER_FAILURE:
                printf("Error: DNS server failure\n");
                break;
            case DNS_INFO_NO_RECORDS:
                printf("Error: No records found for this query\n");
                break;
            case ERROR_TIMEOUT:
                printf("Error: Query timeout\n");
                break;
            default:
                printf("Error: Unknown DNS error\n");
                break;
        }
        return -1;
    }
    
    if (pDnsRecord == NULL) {
        printf("No records found\n");
        return 0;
    }
    
    printf("Query successful! Found records:\n\n");
    
    PDNS_RECORD pCurrent = pDnsRecord;
    int record_count = 0;
    
    while (pCurrent) {
        record_count++;
        printf("Record %d:\n", record_count);
        printf("  Name: %s\n", pCurrent->pName);
        printf("  Type: %s (%d)\n", get_record_type_name(pCurrent->wType), pCurrent->wType);
        printf("  ");
        print_dns_record(pCurrent);
        printf("\n");
        
        pCurrent = pCurrent->pNext;
    }
    
    printf("Total records found: %d\n", record_count);
    
    // Free the memory allocated by DnsQuery
    DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
    
    return 0;
}

// Function to perform DNS query using DnsQuery_W (Wide/Unicode version)
int dns_query_w(const char* hostname, WORD query_type) {
    PDNS_RECORD pDnsRecord = NULL;
    DNS_STATUS status;
    WCHAR wide_hostname[256];
    
    // Convert ANSI to Wide character
    MultiByteToWideChar(CP_ACP, 0, hostname, -1, wide_hostname, 256);
    
    printf("\n=== Using DnsQuery_W (Unicode) ===\n");
    printf("Querying: %s\n", hostname);
    printf("Record type: %s\n", get_record_type_name(query_type));
    
    status = DnsQuery_W(
        wide_hostname,      // Domain name to query (wide string)
        query_type,         // DNS record type
        DNS_QUERY_STANDARD, // Query options
        NULL,              // Extra DNS servers (NULL for default)
        &pDnsRecord,       // Query results
        NULL               // Reserved
    );
    
    if (status != 0) {
        printf("DnsQuery_W failed with error: %d (0x%08X)\n", status, status);
        return -1;
    }
    
    if (pDnsRecord == NULL) {
        printf("No records found\n");
        return 0;
    }
    
    printf("Query successful! Found records:\n\n");
    
    PDNS_RECORD pCurrent = pDnsRecord;
    int record_count = 0;
    
    while (pCurrent) {
        record_count++;
        printf("Record %d:\n", record_count);
        
        // Convert wide string name back to ANSI for display
        char ansi_name[256];
        WideCharToMultiByte(CP_ACP, 0, pCurrent->pName, -1, ansi_name, 256, NULL, NULL);
        printf("  Name: %s\n", ansi_name);
        printf("  Type: %s (%d)\n", get_record_type_name(pCurrent->wType), pCurrent->wType);
        printf("  ");
        print_dns_record(pCurrent);
        printf("\n");
        
        pCurrent = pCurrent->pNext;
    }
    
    printf("Total records found: %d\n", record_count);
    
    // Free the memory allocated by DnsQuery
    DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
    
    return 0;
}

// Function to perform DNS query using DnsQuery_UTF8 (if available)
int dns_query_utf8(const char* hostname, WORD query_type) {
    PDNS_RECORD pDnsRecord = NULL;
    DNS_STATUS status;
    
    printf("\n=== Using DnsQuery_UTF8 ===\n");
    printf("Querying: %s\n", hostname);
    printf("Record type: %s\n", get_record_type_name(query_type));
    
    // Note: DnsQuery_UTF8 might not be available on all Windows versions
    // We'll use a function pointer to check if it exists
    typedef DNS_STATUS (WINAPI *DNSQUERY_UTF8_FUNC)(PCSTR, WORD, DWORD, PVOID, PDNS_RECORD*, PVOID*);
    
    HMODULE hDnsApi = LoadLibraryA("dnsapi.dll");
    if (hDnsApi == NULL) {
        printf("Failed to load dnsapi.dll\n");
        return -1;
    }
    
    DNSQUERY_UTF8_FUNC DnsQuery_UTF8_Func = (DNSQUERY_UTF8_FUNC)GetProcAddress(hDnsApi, "DnsQuery_UTF8");
    
    if (DnsQuery_UTF8_Func == NULL) {
        printf("DnsQuery_UTF8 is not available on this Windows version\n");
        printf("This function requires Windows 8 or later\n");
        FreeLibrary(hDnsApi);
        return -1;
    }
    
    status = DnsQuery_UTF8_Func(
        hostname,           // Domain name to query (UTF-8)
        query_type,         // DNS record type
        DNS_QUERY_STANDARD, // Query options
        NULL,              // Extra DNS servers (NULL for default)
        &pDnsRecord,       // Query results
        NULL               // Reserved
    );
    
    FreeLibrary(hDnsApi);
    
    if (status != 0) {
        printf("DnsQuery_UTF8 failed with error: %d (0x%08X)\n", status, status);
        return -1;
    }
    
    if (pDnsRecord == NULL) {
        printf("No records found\n");
        return 0;
    }
    
    printf("Query successful! Found records:\n\n");
    
    PDNS_RECORD pCurrent = pDnsRecord;
    int record_count = 0;
    
    while (pCurrent) {
        record_count++;
        printf("Record %d:\n", record_count);
        printf("  Name: %s\n", pCurrent->pName);
        printf("  Type: %s (%d)\n", get_record_type_name(pCurrent->wType), pCurrent->wType);
        printf("  ");
        print_dns_record(pCurrent);
        printf("\n");
        
        pCurrent = pCurrent->pNext;
    }
    
    printf("Total records found: %d\n", record_count);
    
    // Free the memory allocated by DnsQuery
    DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
    
    return 0;
}

// Function to query all supported record types
void query_all_records(const char* hostname) {
    WORD record_types[] = {
        DNS_TYPE_A,
        DNS_TYPE_AAAA,
        DNS_TYPE_CNAME,
        DNS_TYPE_MX,
        DNS_TYPE_TXT,
        DNS_TYPE_NS,
        DNS_TYPE_SOA,
        DNS_TYPE_SRV,
        DNS_TYPE_CAA
    };
    
    int num_types = sizeof(record_types) / sizeof(record_types[0]);
    
    printf("\n=== Querying All Record Types for %s ===\n", hostname);
    
    for (int i = 0; i < num_types; i++) {
        printf("\n--- %s Records ---\n", get_record_type_name(record_types[i]));
        dns_query_a(hostname, record_types[i]);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("=== Windows DNS Query Tool ===\n");
        printf("Uses Windows DNS API functions: DnsQuery_A, DnsQuery_W, and DnsQuery_UTF8\n\n");
        printf("Usage: %s <domain> [record_type] [method]\n", argv[0]);
        printf("\nExamples:\n");
        printf("  %s example.com\n", argv[0]);
        printf("  %s example.com A\n", argv[0]);
        printf("  %s example.com TXT\n", argv[0]);
        printf("  %s example.com A all\n", argv[0]);
        printf("  %s example.com MX ansi\n", argv[0]);
        printf("  %s example.com A unicode\n", argv[0]);
        printf("  %s example.com TXT utf8\n", argv[0]);
        printf("\nSupported record types: A, AAAA, NS, CNAME, SOA, PTR, MX, TXT, SRV, CAA\n");
        printf("Methods: ansi (default), unicode, utf8, all\n");
        return 1;
    }
    
    const char* hostname = argv[1];
    WORD query_type = DNS_TYPE_A; // Default to A record
    const char* method = "ansi";   // Default method
    
    if (argc >= 3) {
        query_type = get_record_type(argv[2]);
        if (query_type == 0) {
            printf("Error: Unsupported record type '%s'\n", argv[2]);
            printf("Supported types: A, AAAA, NS, CNAME, SOA, PTR, MX, TXT, SRV, CAA\n");
            return 1;
        }
    }
    
    if (argc >= 4) {
        method = argv[3];
    }
    
    // Initialize Winsock for IP address conversion functions
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    printf("=== Windows DNS Query Tool ===\n");
    printf("Target: %s\n", hostname);
    printf("Record Type: %s\n", get_record_type_name(query_type));
    printf("Method: %s\n", method);
    printf("==============================\n");
    
    int result = 0;
    
    if (_stricmp(method, "all") == 0) {
        // Test all three methods
        result |= dns_query_a(hostname, query_type);
        result |= dns_query_w(hostname, query_type);
        result |= dns_query_utf8(hostname, query_type);
    } else if (_stricmp(method, "unicode") == 0) {
        result = dns_query_w(hostname, query_type);
    } else if (_stricmp(method, "utf8") == 0) {
        result = dns_query_utf8(hostname, query_type);
    } else if (_stricmp(method, "ansi") == 0) {
        result = dns_query_a(hostname, query_type);
    } else {
        printf("Unknown method '%s'. Using ANSI method.\n", method);
        result = dns_query_a(hostname, query_type);
    }
    
    WSACleanup();
    
    if (result != 0) {
        printf("\nDNS query failed!\n");
        return 1;
    }
    
    printf("\nDNS query completed successfully!\n");
    return 0;
}