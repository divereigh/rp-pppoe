#ifndef _DHCP_H_
#define _DHCP_H_
#include "config.h" 
#include "pppoe.h"

// #ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
// #endif

// #ifdef HAVE_NETINET_UDP_H
#include <netinet/udp.h>
// #endif

typedef unsigned char u8;

struct bootp_pkt {		/* BOOTP packet format */
	struct iphdr iph;	/* IP header */
	struct udphdr udph;	/* UDP header */
	u8 op;			/* 1=request, 2=reply */
	u8 htype;		/* HW address type */
	u8 hlen;		/* HW address length */
	u8 hops;		/* Used only by gateways */
	__be32 xid;		/* Transaction ID */
	__be16 secs;		/* Seconds since we started */
	__be16 flags;		/* Just what it says */
	__be32 client_ip;		/* Client's IP address if known */
	__be32 your_ip;		/* Assigned IP address */
	__be32 server_ip;		/* (Next, e.g. NFS) Server's IP address */
	__be32 relay_ip;		/* IP address of BOOTP relay */
	u8 hw_addr[16];		/* Client's HW address */
	u8 serv_name[64];	/* Server host name */
	u8 boot_file[128];	/* Name of boot file */
	u8 exten[312];		/* DHCP options / BOOTP vendor extensions */
};

struct dhcp_option
{
    u8 code;
    u8 length;
    u8 *value;
};

/** DHCP BOOTP CODES **/
#define BOOT_REQUEST	1
#define BOOT_REPLY		2

/** DHCP HTYPE CODE **/
#define HTYPE_ETHER		1
#define HTYPE_IEEE802	6
#define HTYPE_FDDI		8
#define HTYPE_IEEE1394	24

/** DHCP MESSAGE CODES **/
#define DHCP_DISCOVER			1
#define DHCP_OFFER				2
#define DHCP_REQUEST			3
#define DHCP_DECLINE			4
#define DHCP_ACK				5
#define DHCP_NAK				6
#define DHCP_RELEASE			7
#define DHCP_INFORM				8
#define DHCP_FORCE_RENEW		9
#define DHCP_LEASE_QUERY		10
#define DHCP_LEASE_UNASSIGNED	11
#define DHCP_LEASE_UNKNOWN		12
#define DHCP_LEASE_ACTIVE		13

/**	DHCP OPTIONS CODE **/
#define DHO_PAD								0
#define DHO_SUBNET							1
#define DHO_TIME_OFFSET						2
#define DHO_ROUTERS							3
#define DHO_TIME_SERVERS					4
#define DHO_NAME_SERVERS					5
#define DHO_DOMAIN_NAME_SERVERS				6
#define DHO_LOG_SERVER						7
#define DHO_COOKIE_SERVERS					8
#define DHO_LPR_SERVERS						9
#define DHO_IMPRESS_SERVER					10
#define DHO_RESOURCE_LOCATION_SERVERS		11
#define DHO_HOST_NAME						12
#define DHO_BOOT_SIZE                      	13
#define DHO_MERIT_DUMP                     	14
#define DHO_DOMAIN_NAME                    	15
#define DHO_SWAP_SERVER                    	16
#define DHO_ROOT_PATH                      	17
#define DHO_EXTENSIONS_PATH                	18
#define DHO_IP_FORWARDING                  	19
#define DHO_NON_LOCAL_SOURCE_ROUTING       	20
#define DHO_POLICY_FILTER                  	21
#define DHO_MAX_DGRAM_REASSEMBLY           	22
#define DHO_DEFAULT_IP_TTL                 	23
#define DHO_PATH_MTU_AGING_TIMEOUT         	24
#define DHO_PATH_MTU_PLATEAU_TABLE         	25
#define DHO_INTERFACE_MTU                  	26
#define DHO_ALL_SUBNETS_LOCAL              	27
#define DHO_BROADCAST_ADDRESS              	28
#define DHO_PERFORM_MASK_DISCOVERY         	29
#define DHO_MASK_SUPPLIER                  	30
#define DHO_ROUTER_DISCOVERY               	31
#define DHO_ROUTER_SOLICITATION_ADDRESS    	32
#define DHO_STATIC_ROUTES                  	33
#define DHO_TRAILER_ENCAPSULATION          	34
#define DHO_ARP_CACHE_TIMEOUT              	35
#define DHO_IEEE802_3_ENCAPSULATION        	36
#define DHO_DEFAULT_TCP_TTL                	37
#define DHO_TCP_KEEPALIVE_INTERVAL         	38
#define DHO_TCP_KEEPALIVE_GARBAGE          	39
#define DHO_NIS_SERVERS                    	41
#define DHO_NTP_SERVERS                    	42
#define DHO_VENDOR_ENCAPSULATED_OPTIONS    	43
#define DHO_NETBIOS_NAME_SERVERS           	44
#define DHO_NETBIOS_DD_SERVER              	45
#define DHO_NETBIOS_NODE_TYPE              	46
#define DHO_NETBIOS_SCOPE                  	47
#define DHO_FONT_SERVERS                   	48
#define DHO_X_DISPLAY_MANAGER              	49
#define DHO_DHCP_REQUESTED_ADDRESS         	50
#define DHO_DHCP_LEASE_TIME                	51
#define DHO_DHCP_OPTION_OVERLOAD           	52
#define DHO_DHCP_MESSAGE_TYPE              	53
#define DHO_DHCP_SERVER_IDENTIFIER         	54
#define DHO_DHCP_PARAMETER_REQUEST_LIST    	55
#define DHO_DHCP_MESSAGE                   	56
#define DHO_DHCP_MAX_MESSAGE_SIZE          	57
#define DHO_DHCP_RENEWAL_TIME              	58
#define DHO_DHCP_REBINDING_TIME            	59
#define DHO_VENDOR_CLASS_IDENTIFIER        	60
#define DHO_DHCP_CLIENT_IDENTIFIER         	61
#define DHO_NWIP_DOMAIN_NAME               	62
#define DHO_NWIP_SUBOPTIONS                	63
#define DHO_NISPLUS_DOMAIN                 	64
#define DHO_NISPLUS_SERVER                 	65
#define DHO_TFTP_SERVER                    	66
#define DHO_BOOTFILE                       	67
#define DHO_MOBILE_IP_HOME_AGENT           	68
#define DHO_SMTP_SERVER                    	69
#define DHO_POP3_SERVER                    	70
#define DHO_NNTP_SERVER                    	71
#define DHO_WWW_SERVER                     	72
#define DHO_FINGER_SERVER                  	73
#define DHO_IRC_SERVER                     	74
#define DHO_STREETTALK_SERVER              	75
#define DHO_STDA_SERVER                    	76
#define DHO_USER_CLASS                     	77
#define DHO_FQDN                           	81
#define DHO_DHCP_AGENT_OPTIONS             	82
#define DHO_NDS_SERVERS                    	85
#define DHO_NDS_TREE_NAME                  	86
#define DHO_NDS_CONTEXT					   	87
#define DHO_CLIENT_LAST_TRANSACTION_TIME   	91
#define DHO_ASSOCIATED_IP				   	92
#define DHO_USER_AUTHENTICATION_PROTOCOL   	98
#define DHO_AUTO_CONFIGURE                	116
#define DHO_NAME_SERVICE_SEARCH           	117
#define DHO_SUBNET_SELECTION              	118
#define DHO_DOMAIN_SEARCH	              	119
#define DHO_CLASSLESS_ROUTE				  	121
#define DHO_END                            	-1 

/** DHCP PACKET LENGTH **/
#define BOOTP_ABSOLUTE_MIN_LEN	236
#define DHCP_VEND_SIZE		64
#define DHCP_MAX_MTU		1500

int isdhcp(EthPacket *ethpacket, int len);
void handleDHCPRequest(IPoEConnection *conn, int sock, EthPacket *ethpacket, int len, PPPoEConnection *pppoeconn, PPPoEPacket *pppoepacket);
void handleARPRequest(IPoEConnection *conn, int sock, EthPacket *packet);
void handleIPv4Packet(IPoEConnection *conn, int sock, EthPacket *ethpacket, int len, PPPoEConnection *pppoeconn, PPPoEPacket *pppoepacket);
void readIPFromEth(IPoEConnection *ipoeconn, int sock, PPPoEConnection *pppoeconn, PPPoEPacket *packet);
#endif
