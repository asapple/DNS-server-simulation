#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#include <WS2tcpip.h>
#endif
#ifdef __linux__
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

#include "dns_types.h"
#include "dns_parse.h"

//创建一个DNS解析报文数据包

dns_packet* create_dns_packet() {
    dns_packet* packet = (dns_packet*) malloc(sizeof(dns_packet));
	if (packet == NULL) {
		perror("[dns packet]malloc error");
		return NULL;
	}
    memset(packet->raw_data, 0, sizeof(packet->raw_data));
    packet->raw_len = 0;
	memset(&packet->header, 0, sizeof(packet->header));
	packet->queries = (dns_query*)calloc(1, sizeof(dns_query));
	packet->authorities = (dns_rr*)calloc(1, sizeof(dns_rr));
	packet->answers = (dns_rr*)calloc(1, sizeof(dns_rr));
	packet->additionals = (dns_rr*)calloc(1, sizeof(dns_rr));

    return packet;
}

/* 将DNS报文数据转化为解析后的DNS结构 */
void dns_raw_to_dns_packet(char* raw, dns_packet* packet, int size)
{
	for (int i = 0; i < size; ++i) {
		packet->raw_data[i] = raw[i];
	}
    packet->raw_len = size;
    raw_header_to_packet_header(raw, &packet->header, 0);
    int query_len = raw_query_to_packet_query(raw, DNS_HEADERS_LEN, packet->queries, packet->header.qd_cnt);
    int answer_len = raw_rr_to_packet_rr(raw, DNS_HEADERS_LEN + query_len, packet->answers, packet->header.an_cnt);
    int authority_len = raw_rr_to_packet_rr(raw, DNS_HEADERS_LEN + query_len + answer_len, packet->authorities, packet->header.ns_cnt);
    int additional_len = raw_rr_to_packet_rr(raw, DNS_HEADERS_LEN + query_len + answer_len + authority_len, packet->additionals, packet->header.ar_cnt);
}

int raw_header_to_packet_header(char* raw, dns_header* header, int offset)
{
    header->id = *(uint16_t*)(raw);

    header->qr = (raw[2] & 0x80) >> 7;
    header->opcode = (raw[2] & 0x78) >> 3;
    header->aa = (raw[2] & 0x04) >> 2;
    header->tc = (raw[2] & 0x02) >> 1;
    header->rd = raw[2] & 0x01;
    header->ra = (raw[3] & 0x80) >> 7;
    header->rcode = raw[3] & 0x0f;

    header->qd_cnt = ntohs(*(uint16_t*)(raw+4));
    header->an_cnt = ntohs(*(uint16_t*)(raw+6));
    header->ns_cnt = ntohs(*(uint16_t*)(raw+8));
    header->ar_cnt = ntohs(*(uint16_t*)(raw+10));

    return DNS_HEADERS_LEN;
}

int raw_query_to_packet_query(char* raw, int offset, dns_query* queries, int cnt)
{
    int begin_offset = offset;
    dns_query* cur_query = queries;
    for (int i = 0; i < cnt; ++i) {
        cur_query->next = (dns_query*) malloc(sizeof(dns_query));
        cur_query = cur_query->next;
        cur_query->next = NULL;
        //读取qname
        offset += raw_name_to_packet_name(raw, &cur_query->qname, offset);
        cur_query->qtype = ntohs(*(uint16_t*)(raw + offset));
        offset += 2;
        cur_query->qclass = ntohs(*(uint16_t*)(raw + offset));
        offset += 2;
    }
    return offset - begin_offset;
}

int raw_name_to_packet_name(char* raw, dns_name* name, int offset)
{
    int begin_offset = offset;
    name->label_cnt = 0;
    char label_bufs[MAX_NAME_LEN][MAX_LABEL_LEN] = {'\0'};
        
    int flag = 0; //flag表明当前是否使用压缩方式
    int ptr = offset;
    while (1) {
        if (raw[ptr] == 0) {
            ++ptr;
            if (!flag) {
                offset = ptr;
            }
            break;
        } else if ((raw[ptr] & 0xc0) == 0xc0) {
            ptr = htons(*(uint16_t *)(raw + ptr));
            ptr = ptr & 0x3fff;

			if (flag != 1) offset += 2;
            flag = 1;
        } else if ((raw[ptr] & 0xc0) == 0x00) {
            memcpy(label_bufs[name->label_cnt], raw+ptr+1, raw[ptr]);
            ptr += raw[ptr] + 1;
            if (!flag) {
                offset = ptr;
            }
            (name->label_cnt)++;
        }
    }
    name->labels = (char**) malloc(sizeof(char*)*(name->label_cnt));
    name->label_len = (uint16_t*) malloc((name->label_cnt)*sizeof(uint16_t));
    for (int k = 0;k < name->label_cnt; ++k) {
        uint16_t len = strlen(label_bufs[k]);
        name->labels[k] = (char*) malloc(sizeof(char)*(len+1));
        memcpy(name->labels[k], label_bufs[k], len);
        name->label_len[k] = len;
        name->labels[k][len] = '\0';
    }
    return offset - begin_offset;
}

void dns_name_cpy(dns_name* des, dns_name* src)
{
	if (des == NULL || src == NULL) {
		perror("[dns parse]dns name cpy error");
		return;
	}
	des->label_cnt = src->label_cnt;
	if (des->labels != NULL) {
		for (int i = 0; i < des->label_cnt; ++i) {
			free(des->labels[i]);
			des->labels[i] = NULL;
		}
		free(des->labels);
		des->labels = NULL;
		free(des->label_len);
		des->label_len = NULL;
	}
	des->labels = (char**)malloc(src->label_cnt * sizeof(char*));
	des->label_len = (uint16_t*)malloc(src->label_cnt * sizeof(uint16_t));
	for (int i = 0; i < des->label_cnt; ++i) {
		des->label_len[i] = src->label_len[i];
		des->labels[i] = (char*)malloc((src->label_len[i]+1) * sizeof(char));
		strcpy_s(des->labels[i], des->label_len[i] ,src->labels[i]);
	}
}

int dns_labels_to_domain_name(dns_name name, char* domain_name)
{
	int len = 0;
	for (int i = 0; i < name.label_cnt; ++i) {
		for (int j = 0; j < name.label_len[i]; ++j) {
			domain_name[len++] = name.labels[i][j];
		}
		domain_name[len++] = '.';
	}
	domain_name[len - 1] = '\0';
	return len;
}
int raw_rr_to_packet_rr(char* raw, int offset, dns_rr* rr, int cnt)
{
    int begin_offset = offset;
    dns_rr* cur_rr = rr;
    for (int i = 0; i < cnt; ++i) {
        cur_rr->next = (dns_rr*) malloc(sizeof(dns_rr));
        cur_rr = cur_rr->next;
        cur_rr->next = NULL;
        offset += raw_name_to_packet_name(raw, &cur_rr->name, offset);
        cur_rr->rrtype = ntohs(*(uint16_t*)(raw + offset));
        offset += 2;
        cur_rr->rrclass = ntohs(*(uint16_t*)(raw + offset));
        offset += 2;
        cur_rr->ttl = ntohl(*(uint32_t*)(raw + offset));
        offset += 4;
        cur_rr->len = ntohs(*(uint32_t*)(raw + offset));
        offset += 2;
        cur_rr->data = (uint8_t*) malloc(cur_rr->len*sizeof(char));
		memcpy(cur_rr->data, raw + offset, cur_rr->len);
        offset += cur_rr->len;
    }
    return offset - begin_offset;

}

//将DNS结构转化为DNS报文数据
int dns_packet_to_dns_raw(dns_packet* packet, char* raw)
{
    int offset = 0;
    offset = packet_header_to_raw_header(packet->header, raw, offset);
    offset = packet_query_to_raw_query(packet->queries, raw, offset);
    offset = packet_rr_to_raw_rr(packet->answers,raw,offset);
    offset = packet_rr_to_raw_rr(packet->authorities,raw,offset);
    offset = packet_rr_to_raw_rr(packet->additionals,raw,offset);
    return offset;
}

int packet_header_to_raw_header(dns_header header, char* raw, int offset)
{
    *(uint16_t*)raw = header.id;
    raw[2] |= header.qr << 7;
    raw[2] |= header.opcode << 3;
    raw[2] |= header.aa << 2;
    raw[2] |= header.tc << 1;
    raw[2] |= header.rd;
    raw[3] |= header.ra << 7;
    raw[3] |= header.rcode;
    *(uint16_t*)(raw + 4) = htons(header.qd_cnt);
    *(uint16_t*)(raw + 6) = htons(header.an_cnt);
    *(uint16_t*)(raw + 8) = htons(header.ns_cnt);
    *(uint16_t*)(raw + 10) = htons(header.ar_cnt);
    return DNS_HEADERS_LEN;
}

int packet_query_to_raw_query(dns_query* queries, char* raw, int offset)
{
    dns_query* cur_query = queries->next;
    while (cur_query != NULL) {
        dns_name name = cur_query->qname;
        for (int i=0;i<name.label_cnt;++i) {
            raw[offset] = name.label_len[i];
            ++offset;
            memcpy(raw+offset, name.labels[i] ,name.label_len[i]);
            offset += name.label_len[i];
        }
        raw[offset] = '\0';
        ++offset;
        *(uint16_t*)(raw + offset) = htons(cur_query->qtype);
        offset += 2;
        *(uint16_t*)(raw + offset) = htons(cur_query->qclass);
        offset += 2;
        cur_query = cur_query->next;
    }
    return offset;
}

int packet_rr_to_raw_rr(dns_rr* rr, char* raw, int offset)
{
    dns_rr* cur_rr = rr->next;
    while (cur_rr != NULL) {
        dns_name name = cur_rr->name;
        for (int i=0;i<name.label_cnt;++i) {
            raw[offset] = name.label_len[i];
            ++offset;
            memcpy(raw+offset, name.labels[i] ,name.label_len[i]);
            offset += name.label_len[i];
        }
        raw[offset] = '\0';
        ++offset;
        *(uint16_t*)(raw + offset) = htons(cur_rr->rrclass);
        offset += 2;
        *(uint16_t*)(raw + offset) = htons(cur_rr->rrtype);
        offset += 2;
        *(uint32_t*)(raw + offset) = htonl(cur_rr->ttl);
        offset += 4;
        *(uint32_t*)(raw + offset) = htons(cur_rr->len);
        offset += 2;
        memcpy(raw+offset, cur_rr->data, cur_rr->len);
        offset += cur_rr->len;
        cur_rr = cur_rr->next;
    }
    return offset;
}

//销毁dns_packet
void destroy_dns_rr(dns_rr* rr) 
{
    while (rr) {
        dns_rr* temp = rr->next;
		destroy_dns_name(&rr->name);
        if (rr->data != NULL) {
            free(rr->data);
			rr->data = NULL;
        }
        free(rr);
        rr = temp;
    }
}

void destroy_dns_name(dns_name* name)
{
	if (name->label_cnt != 0) {
		for (int i = 0; i < name->label_cnt; ++i) {
			free(name->labels[i]);
			name->labels[i] = NULL;
		}
		free(name->labels);
		name->labels = NULL;
		free(name->label_len);
		name->label_len = NULL;
	}
}

void destroy_dns_query(dns_query* query)
{
    while (query) {
        dns_query* temp = query->next;
		destroy_dns_name(&query->qname);
        free(query);
        query = temp;
    }
	query = NULL;
}

void destroy_dns_packet(dns_packet* packet)
{
    destroy_dns_query(packet->queries);
    destroy_dns_rr(packet->answers);
    destroy_dns_rr(packet->authorities);
    destroy_dns_rr(packet->additionals);

    if (packet != NULL) free(packet);
	packet = NULL;
}

//输出dns信息
void print_dns_packet(FILE* file, dns_packet* packet)
{
	char printbuf[MAX_DNS_INFO_SIZE] = { '\0' };
	int offset = 0;
    offset += sprintf_s(printbuf+offset, MAX_DNS_INFO_SIZE-offset,"\n[DNS message]\n");
	offset += sprintf_s(printbuf+offset, MAX_DNS_INFO_SIZE-offset, "<Raw data>: \n");
	for (int i = 0; i < packet->raw_len; ++i) {
		offset += sprintf_s(printbuf+offset, MAX_DNS_INFO_SIZE - offset, "%02x ", (unsigned char)(packet->raw_data[i]));
		if ((i + 1) % 8 == 0 || i == packet->raw_len - 1) {
			offset += sprintf_s(printbuf+offset, MAX_DNS_INFO_SIZE - offset, "\n");
		}
	}
	offset = print_dns_header(printbuf, offset, packet->header);
    offset = print_dns_query(printbuf, offset, packet->queries);
    offset = print_dns_answer(printbuf, offset, packet->answers);
	offset += sprintf_s(printbuf + offset, MAX_DNS_INFO_SIZE - offset, "\n");
	fprintf(file, printbuf);
}

int print_dns_header(char* buf, int offset,dns_header header)
{
    offset += sprintf_s(buf + offset, MAX_DNS_INFO_SIZE-offset,"<DNS Header>\n");
	offset += sprintf_s(buf + offset, MAX_DNS_INFO_SIZE-offset,"Transaction ID: %04x\n", htons(header.id));
	offset += sprintf_s(buf + offset, MAX_DNS_INFO_SIZE - offset, "Flags: ");
    if (header.qr == DNS_QUERY) {
		offset += sprintf_s(buf + offset, MAX_DNS_INFO_SIZE - offset, "query\n");
    } else if (header.qr == DNS_RESPONSE) {
		offset += sprintf_s(buf + offset, MAX_DNS_INFO_SIZE - offset, "response\n");
    }
    if (header.rcode == 3) {
		offset += sprintf_s(buf + offset, MAX_DNS_INFO_SIZE - offset, "domain not found\n");
    }
	offset += sprintf_s(buf + offset, MAX_DNS_INFO_SIZE - offset, "ra=%d, rd=%d, tc=%d, rcode=%d\n", header.ra, header.rd, header.tc, header.rcode);
	offset += sprintf_s(buf + offset, MAX_DNS_INFO_SIZE - offset, "qd_cnt=%d, an_cnt=%d, ns_cnt=%d, ar_cnt=%d\n", header.qd_cnt, header.an_cnt, header.ns_cnt, header.ar_cnt);
	return offset;
}

int print_dns_query(char* buf, int offset, dns_query* queries)
{
	offset += sprintf_s(buf + offset, MAX_DNS_INFO_SIZE - offset, "<DNS Querries>\n");
    dns_query* cur_query = queries->next;
    while(cur_query) {
		offset += sprintf_s(buf + offset, MAX_DNS_INFO_SIZE - offset, "query:");
        for (int i=0; i<cur_query->qname.label_cnt; ++i) {
			offset += sprintf_s(buf + offset, MAX_DNS_INFO_SIZE - offset, "%s.", cur_query->qname.labels[i]);
        }
		offset += sprintf_s(buf + offset, MAX_DNS_INFO_SIZE - offset, "\n");
        cur_query = cur_query->next;
    }
	return offset;
}

int print_dns_answer(char* buf, int offset, dns_rr* answers)
{
	offset += sprintf_s(buf + offset, MAX_DNS_INFO_SIZE - offset, "<DNS answer>\n");
    dns_rr* cur_rr = answers->next;
    while(cur_rr) {
		offset += sprintf_s(buf + offset, MAX_DNS_INFO_SIZE - offset, "query:");
        for (int i=0; i<cur_rr->name.label_cnt; ++i) {
			offset += sprintf_s(buf + offset, MAX_DNS_INFO_SIZE - offset, "%s.", cur_rr->name.labels[i]);
        }
		offset += sprintf_s(buf + offset, MAX_DNS_INFO_SIZE - offset, "\n");
		if (cur_rr->rrtype == DNS_TYPE_A) {
			char str[30] = { '\0' };
			inet_ntop(AF_INET, (struct in_addr*)cur_rr->data, str, sizeof(str));
			offset += sprintf_s(buf + offset, MAX_DNS_INFO_SIZE - offset, "addr: %s\n", str);
		}
		else if (cur_rr->rrtype == DNS_TYPE_CNAME) {
			offset += sprintf_s(buf + offset, MAX_DNS_INFO_SIZE - offset, "cname\n");
		}
        cur_rr = cur_rr->next;
    }
	return offset;
}