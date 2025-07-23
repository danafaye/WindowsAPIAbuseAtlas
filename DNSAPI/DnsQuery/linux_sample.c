#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>

// DNS record types
#define T_A     1   // IPv4 address
#define T_NS    2   // Name server
#define T_CNAME 5   // Canonical name
#define T_SOA   6   // Start of authority
#define T_PTR   12  // Domain name pointer
#define T_MX    15  // Mail exchange
#define T_TXT   16  // Text
#define T_AAAA  28  // IPv6 address
#define T_SRV   33  // Service record

// DNS header structure
struct dns_header {
    unsigned short id;      // identification number
    unsigned char rd :1;    // recursion desired
    unsigned char tc :1;    // truncated message
    unsigned char aa :1;    // authoritative answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1;    // query/response flag
    unsigned char rcode :4; // response code
    unsigned char z :3;     // its z! reserved
    unsigned char ra :1;    // recursion available
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

// DNS question structure
struct dns_question {
    unsigned short qtype;
    unsigned short qclass;
};

// DNS resource record structure
#pragma pack(push, 1)
struct dns_rr {
    unsigned short type;
    unsigned short class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)

// Function to convert domain name format
void change_to_dns_format(unsigned char* dns, unsigned char* host) {
    int lock = 0, i;
    strcat((char*)host, ".");
    
    for(i = 0; i < strlen((char*)host); i++) {
        if(host[i] == '.') {
            *dns++ = i - lock;
            for(; lock < i; lock++) {
                *dns++ = host[lock];
            }
            lock++;
        }
    }
    *dns++ = '\0';
}

// Function to convert DNS name format back to normal
int read_name(unsigned char* reader, unsigned char* buffer, int* count) {
    unsigned char *name;
    unsigned int p = 0, jumped = 0, offset;
    int i, j;
    
    *count = 1;
    name = (unsigned char*)malloc(256);
    name[0] = '\0';
    
    while(*reader != 0) {
        if(*reader >= 192) {
            offset = (*reader) * 256 + *(reader + 1) - 49152;
            reader = buffer + offset - 1;
            jumped = 1;
        } else {
            name[p++] = *reader;
        }
        
        reader++;
        
        if(jumped == 0) {
            *count = *count + 1;
        }
    }
    
    name[p] = '\0';
    if(jumped == 1) {
        *count = *count + 1;
    }
    
    // Convert to readable format
    for(i = 0; i < (int)strlen((const char*)name); i++) {
        p = name[i];
        for(j = 0; j < (int)p; j++) {
            name[i] = name[i + 1];
            i++;
        }
        name[i] = '.';
    }
    name[i - 1] = '\0';
    
    strcpy((char*)reader, (char*)name);
    free(name);
    return 0;
}

// Function to get record type name
const char* get_record_type_name(int type) {
    switch(type) {
        case T_A: return "A";
        case T_NS: return "NS";
        case T_CNAME: return "CNAME";
        case T_SOA: return "SOA";
        case T_PTR: return "PTR";
        case T_MX: return "MX";
        case T_TXT: return "TXT";
        case T_AAAA: return "AAAA";
        case T_SRV: return "SRV";
        default: return "UNKNOWN";
    }
}

// Function to print A record
void print_a_record(unsigned char* data) {
    struct in_addr addr;
    memcpy(&addr, data, 4);
    printf("A: %s\n", inet_ntoa(addr));
}

// Function to print AAAA record
void print_aaaa_record(unsigned char* data) {
    char ipv6_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, data, ipv6_str, INET6_ADDRSTRLEN);
    printf("AAAA: %s\n", ipv6_str);
}

// Function to print MX record
void print_mx_record(unsigned char* data, unsigned char* buffer) {
    unsigned short priority;
    unsigned char hostname[256];
    int count;
    
    memcpy(&priority, data, 2);
    priority = ntohs(priority);
    
    read_name(data + 2, buffer, &count);
    strcpy((char*)hostname, (char*)(data + 2));
    
    printf("MX: %d %s\n", priority, hostname);
}

// Function to print TXT record
void print_txt_record(unsigned char* data, int data_len) {
    printf("TXT: \"");
    int i = 0;
    while(i < data_len) {
        int txt_len = data[i];
        i++;
        for(int j = 0; j < txt_len && i < data_len; j++, i++) {
            printf("%c", data[i]);
        }
        if(i < data_len) printf(" ");
    }
    printf("\"\n");
}

// Function to print NS/CNAME/PTR record
void print_name_record(unsigned char* data, unsigned char* buffer, const char* type) {
    unsigned char hostname[256];
    int count;
    
    read_name(data, buffer, &count);
    strcpy((char*)hostname, (char*)data);
    
    printf("%s: %s\n", type, hostname);
}

// Function to print SRV record
void print_srv_record(unsigned char* data, unsigned char* buffer) {
    unsigned short priority, weight, port;
    unsigned char hostname[256];
    int count;
    
    memcpy(&priority, data, 2);
    memcpy(&weight, data + 2, 2);
    memcpy(&port, data + 4, 2);
    
    priority = ntohs(priority);
    weight = ntohs(weight);
    port = ntohs(port);
    
    read_name(data + 6, buffer, &count);
    strcpy((char*)hostname, (char*)(data + 6));
    
    printf("SRV: %d %d %d %s\n", priority, weight, port, hostname);
}

// Main DNS query function
int dns_query(const char* hostname, int query_type) {
    unsigned char buf[65536], *qname, *reader;
    struct dns_header *dns = NULL;
    struct dns_question *qinfo = NULL;
    struct dns_rr *answers;
    
    int i, j, stop, s;
    struct sockaddr_in dest;
    
    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr("8.8.8.8"); // Google DNS
    
    // Set up DNS header
    dns = (struct dns_header *)&buf;
    dns->id = (unsigned short) htons(getpid());
    dns->qr = 0; // Query
    dns->opcode = 0; // Standard query
    dns->aa = 0; // Not Authoritative
    dns->tc = 0; // Not Truncated
    dns->rd = 1; // Recursion Desired
    dns->ra = 0; // Recursion not available
    dns->z = 0;
    dns->rcode = 0;
    dns->q_count = htons(1); // We have only 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;
    
    // Point to the query portion
    qname = (unsigned char*)&buf[sizeof(struct dns_header)];
    
    change_to_dns_format(qname, (unsigned char*)hostname);
    qinfo = (struct dns_question*)&buf[sizeof(struct dns_header) + (strlen((const char*)qname) + 1)];
    
    qinfo->qtype = htons(query_type);
    qinfo->qclass = htons(1); // Internet class
    
    printf("Sending DNS query for %s (%s record)...\n", hostname, get_record_type_name(query_type));
    
    if(sendto(s, (char*)buf, sizeof(struct dns_header) + (strlen((const char*)qname) + 1) + sizeof(struct dns_question), 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        perror("sendto failed");
        return -1;
    }
    
    printf("Waiting for response...\n");
    
    // Receive the answer
    i = sizeof(dest);
    if(recvfrom(s, (char*)buf, 65536, 0, (struct sockaddr*)&dest, (socklen_t*)&i) < 0) {
        perror("recvfrom failed");
        return -1;
    }
    
    dns = (struct dns_header*) buf;
    
    // Move to the query section
    reader = &buf[sizeof(struct dns_header) + (strlen((const char*)qname) + 1) + sizeof(struct dns_question)];
    
    printf("\nResponse received:\n");
    printf("Answer count: %d\n", ntohs(dns->ans_count));
    
    // Start reading answers
    stop = 0;
    
    for(i = 0; i < ntohs(dns->ans_count); i++) {
        answers = (struct dns_rr*)(reader);
        
        if(*reader >= 192) {
            reader = reader + 2;
        } else {
            while(*reader != 0) {
                reader++;
            }
            reader++;
        }
        
        answers = (struct dns_rr*)reader;
        reader = reader + sizeof(struct dns_rr);
        
        int type = ntohs(answers->type);
        int data_len = ntohs(answers->data_len);
        
        printf("\nRecord %d:\n", i + 1);
        printf("Type: %s (%d)\n", get_record_type_name(type), type);
        printf("TTL: %u seconds\n", ntohl(answers->ttl));
        printf("Data length: %d bytes\n", data_len);
        
        // Parse different record types
        switch(type) {
            case T_A:
                print_a_record(reader);
                break;
            case T_AAAA:
                print_aaaa_record(reader);
                break;
            case T_NS:
                print_name_record(reader, buf, "NS");
                break;
            case T_CNAME:
                print_name_record(reader, buf, "CNAME");
                break;
            case T_PTR:
                print_name_record(reader, buf, "PTR");
                break;
            case T_MX:
                print_mx_record(reader, buf);
                break;
            case T_TXT:
                print_txt_record(reader, data_len);
                break;
            case T_SRV:
                print_srv_record(reader, buf);
                break;
            default:
                printf("Data: ");
                for(j = 0; j < data_len; j++) {
                    printf("%02x ", reader[j]);
                }
                printf("\n");
                break;
        }
        
        reader = reader + data_len;
    }
    
    close(s);
    return 0;
}

// Function to get record type from string
int get_record_type(const char* type_str) {
    if(strcasecmp(type_str, "A") == 0) return T_A;
    if(strcasecmp(type_str, "NS") == 0) return T_NS;
    if(strcasecmp(type_str, "CNAME") == 0) return T_CNAME;
    if(strcasecmp(type_str, "SOA") == 0) return T_SOA;
    if(strcasecmp(type_str, "PTR") == 0) return T_PTR;
    if(strcasecmp(type_str, "MX") == 0) return T_MX;
    if(strcasecmp(type_str, "TXT") == 0) return T_TXT;
    if(strcasecmp(type_str, "AAAA") == 0) return T_AAAA;
    if(strcasecmp(type_str, "SRV") == 0) return T_SRV;
    return -1;
}

int main(int argc, char *argv[]) {
    if(argc < 2) {
        printf("Usage: %s <domain> [record_type]\n", argv[0]);
        printf("Examples:\n");
        printf("  %s example.com\n", argv[0]);
        printf("  %s example.com A\n", argv[0]);
        printf("  %s example.com TXT\n", argv[0]);
        printf("\nSupported record types: A, AAAA, NS, CNAME, SOA, PTR, MX, TXT, SRV\n");
        return 1;
    }
    
    const char* hostname = argv[1];
    int query_type = T_A; // Default to A record
    
    if(argc >= 3) {
        query_type = get_record_type(argv[2]);
        if(query_type == -1) {
            printf("Error: Unsupported record type '%s'\n", argv[2]);
            printf("Supported types: A, AAAA, NS, CNAME, SOA, PTR, MX, TXT, SRV\n");
            return 1;
        }
    }
    
    printf("=== DNS Query Tool ===\n");
    printf("Querying: %s\n", hostname);
    printf("Record type: %s\n", get_record_type_name(query_type));
    printf("DNS Server: 8.8.8.8\n");
    printf("========================\n\n");
    
    int result = dns_query(hostname, query_type);
    
    if(result != 0) {
        printf("DNS query failed!\n");
        return 1;
    }
    
    return 0;
}