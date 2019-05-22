#include "dhcp.h"

#include <arpa/inet.h>
#include <string.h>

/*
** bootp relay code
*/

extern PPPoEConnection *Connection;
extern struct in_addr peerIP;
extern struct in_addr gatewayIP;
extern struct in_addr netmaskIP;

uint16_t ip_checksum(void* vdata,size_t length) {
    // Cast the data pointer to one that can be indexed.
    char* data=(char*)vdata;

    // Initialise the accumulator.
    uint32_t acc=0xffff;

    // Handle complete 16-bit blocks.
    for (size_t i=0;i+1<length;i+=2) {
        uint16_t word;
        memcpy(&word,data+i,2);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Handle any partial block at the end of the data.
    if (length&1) {
        uint16_t word=0;
        memcpy(&word,data+length-1,1);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}

int
isdhcp(EthPacket *ethpacket, int len)
{
    struct bootp_pkt *bootpreq;

    bootpreq = (struct bootp_pkt *) ethpacket->payload;

    /* Verify once more that it's IPv4 */
    if (bootpreq->iph.version != 4) {
	// fprintf(stderr, "IP4 check failed: %d\n", bootpreq->iph.version);
	return(0);
    }

    /* Is it a fragment that's not at the beginning of the packet? */
    if (bootpreq->iph.frag_off) {
	/* Yup, don't touch! */
	// fprintf(stderr, "Frag check failed: %d\n", bootpreq->iph.frag_off);
	return(0);
    }

    /* Is it UDP? */
    if (bootpreq->iph.protocol != 0x11) {
	// fprintf(stderr, "protocol check failed: %d\n", bootpreq->iph.protocol);
	return(0);
    }

    if (bootpreq->udph.source != htons(68) || bootpreq->udph.dest != htons(67)) {
	// fprintf(stderr, "port check failed: src %d - dest %d\n", ntohs(bootpreq->udph.source), ntohs(bootpreq->udph.dest));
	return(0);
    }

// Do more tests here
    return(1);
}

#define MAXOPT 256
struct dhcp_option dhcpoptlist[MAXOPT];

int unpackDHCPOptions(unsigned char *options, int maxlen)
{
	int n;
	int len=0;
	int count=0;
	unsigned char *p;

	/*
	fprintf(stderr, "Options:-\n");
	dumpHex(stderr, options, maxlen);
	*/
	memset(dhcpoptlist, 0, sizeof(struct dhcp_option) * 256);
	p=options;
	for (n=0; n<255 && len<maxlen; n++) {
		if (*p>0) {
			dhcpoptlist[n].code=*p;
			if (*p == 255) {
				break;
			}
			dhcpoptlist[n].length=*(p+1);
			dhcpoptlist[n].value=p+2;
			//fprintf(stderr, "dhcp option: %d len=%d\n", dhcpoptlist[n].code, dhcpoptlist[n].length);
			//dumpHex(stderr, dhcpoptlist[n].value, dhcpoptlist[n].length);
			//fprintf(stderr, "\n");
			//fflush(stderr);
			len += dhcpoptlist[n].length+2;
			p+=dhcpoptlist[n].length+2;
			count++;
		} else {
			len++;
			p++;
		}
	}
	return(count);
}

struct dhcp_option *
findDHCPOption(int code)
{
	int n;
	for (n=0; n<MAXOPT && dhcpoptlist[n].code != code && dhcpoptlist[n].code != 255; n++);
	return(dhcpoptlist[n].code == code ? dhcpoptlist+n : NULL);
}

void
addDHCPOption(unsigned char **p, unsigned char code, unsigned char *value, unsigned char len)
{
	**p=code; (*p)++;
	**p=len; (*p)++;
	memcpy(*p, value, len);
	(*p)+=len;
	if (len & 0x01) {
		// Align on word boundary
		**p=0; (*p)++;
		len++;
	}
	**p=255; // Put terminator on the end
}

#define MYNAME "modem"

void
handleDHCPRequest(PPPoEConnection *conn, int sock, EthPacket *ethpacket, int len, PPPoEConnection *pppoeconn, PPPoEPacket *pppoepacket)
{
    struct bootp_pkt *bootpreq;
    EthPacket ethreply;
    struct bootp_pkt *bootpreply;
    unsigned char *optptr;
    struct dhcp_option *op;
    int dhcp_message_type;
    unsigned char buf[100];
    int req_opt_len;
    int tmpval;
    int udpreplylen;
    // int n;

    bootpreq = (struct bootp_pkt *) ethpacket->payload;
    bootpreply = (struct bootp_pkt *) ethreply.payload;

    // set relay IP
//    inet_pton(AF_INET, "10.10.10.2", &(bootpreq->relay_ip));
//    inet_pton(AF_INET, "10.10.10.2", &(bootpreq->iph.saddr));
//    inet_pton(AF_INET, "10.10.10.1", &(bootpreq->iph.daddr));
//    pppoepacket->payload[0]=0x00;
//    pppoepacket->payload[1]=0x21;
//    memcpy(pppoepacket->payload+2, ethpacket->payload, len);
//    sendSessionPacket(pppoeconn, pppoepacket, len+2);

	// Calculate length of options section (incl DHCP Cookie)
	req_opt_len=ntohs(bootpreq->udph.uh_ulen) -
		((unsigned char *) (&bootpreply->exten) - (unsigned char *) (&bootpreply->udph));

	unpackDHCPOptions(bootpreq->exten+4, sizeof(bootpreq->exten)-4);
	op=findDHCPOption(DHO_DHCP_MESSAGE_TYPE);
	dhcp_message_type=op->value[0];

	if (dhcp_message_type == DHCP_DISCOVER || dhcp_message_type == DHCP_REQUEST || dhcp_message_type == DHCP_FORCE_RENEW) {
		memcpy(bootpreply, bootpreq, sizeof(struct bootp_pkt));
		// Save the source hwaddr
		memcpy(conn->peerEth, ethpacket->ethHdr.h_source, ETH_ALEN);



		// Construct the reply
		bootpreply->op=BOOT_REPLY;
		bootpreply->htype=1;
		bootpreply->hlen=ETH_ALEN;
		bootpreply->hops=0;
		memcpy(&(bootpreply->xid), &(bootpreq->xid), 4);
		bootpreply->flags=bootpreq->flags;
		memset(&(bootpreply->client_ip), 0, 4);
		memcpy(&(bootpreply->your_ip), &peerIP, sizeof(peerIP));
		memcpy(&(bootpreply->server_ip), &gatewayIP, sizeof(gatewayIP));
		memset(&(bootpreply->relay_ip), 0, 4);
		memcpy(bootpreply->hw_addr, ethpacket->ethHdr.h_source, ETH_ALEN);
		memset(bootpreply->serv_name, 0, sizeof(bootpreply->serv_name));
		memcpy(bootpreply->serv_name, MYNAME, strlen(MYNAME));
		memset(bootpreply->boot_file, 0, sizeof(bootpreply->boot_file));
		bootpreply->exten[0]=0x63;
		bootpreply->exten[1]=0x82;
		bootpreply->exten[2]=0x53;
		bootpreply->exten[3]=0x63;

		optptr=bootpreply->exten+4;
		
		if (dhcp_message_type == DHCP_DISCOVER) {
			buf[0]=DHCP_OFFER;
			addDHCPOption(&optptr, DHO_DHCP_MESSAGE_TYPE, buf, 1);
		} else if (dhcp_message_type == DHCP_REQUEST || dhcp_message_type == DHCP_FORCE_RENEW) {
			buf[0]=DHCP_ACK;
			addDHCPOption(&optptr, DHO_DHCP_MESSAGE_TYPE, buf, 1);
		}

		addDHCPOption(&optptr, DHO_DHCP_SERVER_IDENTIFIER, (unsigned char *) &gatewayIP, 4);

		tmpval=htonl(5*60);
		addDHCPOption(&optptr, DHO_DHCP_LEASE_TIME, (unsigned char *) &tmpval, 4);

		addDHCPOption(&optptr, DHO_SUBNET, (unsigned char *) &netmaskIP, 4);

		addDHCPOption(&optptr, DHO_ROUTERS, (unsigned char *) &gatewayIP, 4);

		inet_pton(AF_INET, "8.8.8.8", buf);
		addDHCPOption(&optptr, DHO_DOMAIN_NAME_SERVERS, buf, 4);

		// Add padding to bring the packet up to the same size as the original
		optptr++;
		int padding=req_opt_len - ((unsigned char *) optptr - (unsigned char *) (&bootpreply->exten));
		memset(optptr, 0, padding);
		optptr += padding;

		// Put the udp header length in
		udpreplylen=((unsigned char *) (&bootpreply->exten) - (unsigned char *) (&bootpreply->udph)) + 
			((unsigned char *) optptr - (unsigned char *) (&bootpreply->exten));
		bootpreply->udph.uh_ulen=htons(udpreplylen);

		// Set the IP Header
		bootpreply->iph.version = 4;
		bootpreply->iph.ihl = sizeof(bootpreply->iph)/4;
		bootpreply->iph.tos = 0;
		bootpreply->iph.check = 0;
		bootpreply->iph.tot_len = htons(udpreplylen + sizeof(bootpreply->iph));
		memcpy(&(bootpreply->iph.daddr), &peerIP, sizeof(bootpreply->iph.daddr));
		memcpy(&(bootpreply->iph.saddr), &gatewayIP, sizeof(bootpreply->iph.saddr));
		bootpreply->iph.check = ip_checksum(&bootpreply->iph, sizeof(bootpreply->iph));
		

		// Set the UDP Header
		bootpreply->udph.uh_sum=0;
		bootpreply->udph.source=htons(67);
		bootpreply->udph.dest=htons(68);

		// Set the ethernet header
		memcpy(ethreply.ethHdr.h_source, conn->myEth, ETH_ALEN);
		if (bootpreq->flags & 0x80) {
			memset(ethreply.ethHdr.h_dest, 0xff, ETH_ALEN);
		} else {
			memcpy(ethreply.ethHdr.h_dest, conn->peerEth, ETH_ALEN);
		}
		ethreply.ethHdr.h_proto = htons(ETH_P_IP);

		sendIPPacket(conn, sock, &ethreply, udpreplylen + sizeof(bootpreply->iph) + sizeof(ethreply.ethHdr));
	}
}
