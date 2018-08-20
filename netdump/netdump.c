/*
	Esteban Serna Jr 
	Cpre 530. 
	Homworks 2 & 3
	
*/



#define RETSIGTYPE void
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// OUTSIDE .h files added.
#include <ctype.h>


//Personal .h file. 
//netdump.h file to simplify things.
#include "netdump.h"

#ifndef setsignal_h
#define setsignal_h

RETSIGTYPE (*setsignal(int, RETSIGTYPE (*)(int)))(int);
#endif

char cpre580f98[] = "netdump";

void raw_print(u_char *user, const struct pcap_pkthdr *h, const u_char *p);
/*
	Packet counters
*/
int num_ip_packets,num_apr_packets,
ICMP_Count, Broad_count,Tcp_count,Smtp_count, Pop_count, Imap_count,
Udp_count, Http_count;

/*
	E_Type made as a global Var.
*/
uint16_t e_type ;

int packettype;

char *program_name;

/* Externs */
extern void bpf_dump(const struct bpf_program *, int);

extern char *copy_argv(char **);

/* Forwards */
 void program_ending(int);

/* Length of saved portion of packet. */
int snaplen = 1500;;

static pcap_t *pd;

extern int optind;
extern int opterr;
extern char *optarg;
int pflag = 0, aflag = 0;

int
main(int argc, char **argv)
{
	int cnt, op, i, done = 0;
	bpf_u_int32 localnet, netmask;
	char *cp, *cmdbuf, *device;
	struct bpf_program fcode;
	 void (*oldhandler)(int);
	u_char *pcap_userdata;
	char ebuf[PCAP_ERRBUF_SIZE];

	cnt = -1;
	device = NULL;

	if ((cp = strrchr(argv[0], '/')) != NULL)
		program_name = cp + 1;
	else
		program_name = argv[0];

	opterr = 0;
	while ((i = getopt(argc, argv, "pa")) != -1)
	{
		switch (i)
		{
		case 'p':
			pflag = 1;
		break;
		case 'a':
			aflag = 1;
		break;
		case '?':
		default:
			done = 1;
		break;
		}
		if (done) break;
	}
	if (argc > (optind)) cmdbuf = copy_argv(&argv[optind]);
		else cmdbuf = "";

	if (device == NULL) {
		device = pcap_lookupdev(ebuf);
		if (device == NULL)
			error("%s", ebuf);
	}
	pd = pcap_open_live(device, snaplen,  1, 1000, ebuf);
	if (pd == NULL)
		error("%s", ebuf);
	i = pcap_snapshot(pd);
	if (snaplen < i) {
		warning("snaplen raised from %d to %d", snaplen, i);
		snaplen = i;
	}
	if (pcap_lookupnet(device, &localnet, &netmask, ebuf) < 0) {
		localnet = 0;
		netmask = 0;
		warning("%s", ebuf);
	}
	/*
	 * Let user own process after socket has been opened.
	 */
	setuid(getuid());

	if (pcap_compile(pd, &fcode, cmdbuf, 1, netmask) < 0)
		error("%s", pcap_geterr(pd));

	(void)setsignal(SIGTERM, program_ending);
	(void)setsignal(SIGINT, program_ending);
	/* Cooperate with nohup(1) */
	if ((oldhandler = setsignal(SIGHUP, program_ending)) != SIG_DFL)
		(void)setsignal(SIGHUP, oldhandler);

	if (pcap_setfilter(pd, &fcode) < 0)
		error("%s", pcap_geterr(pd));
	pcap_userdata = 0;
	(void)fprintf(stderr, "%s: listening on %s\n", program_name, device);
	if (pcap_loop(pd, cnt, raw_print, pcap_userdata) < 0) {
		(void)fprintf(stderr, "%s: pcap_loop: %s\n",
		    program_name, pcap_geterr(pd));
		exit(1);
	}
	pcap_close(pd);
	exit(0);
}

/* routine is executed on exit */
void program_ending(int signo)
{
	struct pcap_stat stat;

	if (pd != NULL && pcap_file(pd) == NULL) {
		(void)fflush(stdout);
		putc('\n', stderr);
		if (pcap_stats(pd, &stat) < 0)
			(void)fprintf(stderr, "pcap_stats: %s\n",
			    pcap_geterr(pd));
		else {
// packet counts go here.
			(void)fprintf(stderr, "%d packets received by filter\n",
			    stat.ps_recv);
			(void)fprintf(stderr, "%d packets dropped by kernel\n",
			    stat.ps_drop);
			(void)fprintf(stderr, "%d Total IP packets sent and recived \n",
				num_ip_packets);
			(void)fprintf(stderr, "%d Totoal APR packets send and received\n",
				num_apr_packets);
			(void)fprintf(stderr,"%d Total Number of ICMP protocol packets transmited  \n",
			 	ICMP_Count);
			(void)fprintf(stderr,"%d Total Number of TCP protocol packets transmited\n", 
				Tcp_count);
			(void)fprintf(stderr,"%d Total Number of UDP protocol packets transmited \n",
			 	Udp_count);
			(void)fprintf(stderr,"%d  Total IMAP packets send and received \n", 
				Imap_count); 
			(void)fprintf(stderr,"%d  Total Broadcast packets send and received \n", 
				num_ip_packets);
			(void)fprintf(stderr,"%d  Total POP packets send and received \n",
				 Pop_count);
			(void)fprintf(stderr,"%d  Total SMTP packets send and received \n",
				 Smtp_count);
			(void)fprintf(stderr,"%d  Total HTTP packets send and received \n", 
				Http_count);      
 
		}
	}

	exit(0);
}

/* Like default_print() but data need not be aligned */
void
default_print_unaligned(register const u_char *cp, register u_int length)
{
	register u_int i, s;
	register int nshorts;

	nshorts = (u_int) length / sizeof(u_short);
	i = 0;
	while (--nshorts >= 0) {
		if ((i++ % 8) == 0)
			(void)printf("\n\t\t\t");
		s = *cp++;
		(void)printf(" %02x%02x", s, *cp++);
	}
	if (length & 1) {
		if ((i % 8) == 0)
			(void)printf("\n\t\t\t");
		(void)printf(" %02x", *cp);
	}
}

/*
 * By default, print the packet out in hex.
 */
void
default_print(register const u_char *bp, register u_int length)
{
	register const u_short *sp;
	register u_int i;
	register int nshorts;

	if ((long)bp & 1) {
		default_print_unaligned(bp, length);
		return;
	}
	sp = (u_short *)bp;
	nshorts = (u_int) length / sizeof(u_short);
	i = 0;
	while (--nshorts >= 0) {
		if ((i++ % 8) == 0)
			(void)printf("\n\t");
		(void)printf(" %04x", ntohs(*sp++));
	}
	if (length & 1) {
		if ((i % 8) == 0)
			(void)printf("\n\t");
		(void)printf(" %02x", *(u_char *)sp);
	}
}

/*
	Declares the IP and ARP Struct.
*/
void 
Declrations(const u_char *p, u_int caplen){
	struct APR_info *arp = (struct APR_info*)(p + 14 ); 
			if(ntohs(arp->hrdwr_type) == 1 && ntohs(arp->protocol_type) == 0x800)
            Declrations(p,caplen);

	struct IP_info *ip = (struct IP_info*)(p + 14); 	
	
	ARP_data(p,caplen,arp);
	IP_BASE(p,caplen,ip);
}

/*
	ARP DATA
	Handles the out put of the data for ARP Packets
*/
void 
ARP_data(const u_char *p, u_int caplen, struct APR_info *arp){
	int i = 0;
	
 	printf("Operation: ");
    printf("%s\n", ntohs(arp->Oper) == 1 ? " Request" : " Reply");
    printf("Network Protocol Type: Ethernet\n\n");

    
	printf("\t Source / Target:\n");
	printf("-------------------------------------------- \n");

	while( i < 5) {
	printf("%d \n", arp->Shardware_add[i]);
	printf("%02X \n", arp->Target_add[i]);
		i++;
	}
	printf(stderr,"%02X \n", arp->Shardware_add[5]);
	printf(stderr,"%02X \n", arp->Target_add[5]);

	printf("\n IP ADD: \n");
	while(i < 3){
	printf(stderr,"%d  \n", arp->Sprotocol_add[i]);
	printf(stderr,"%d  \n", arp->Target_Proto[i]);
		i++;
		}
	printf("%02X \n", arp->Sprotocol_add[3]);
	printf("%d  \n", arp->Target_Proto[3]);

    printf("\n\n");
}

/*
	
	IP PACKET DATA
	Handles the out put of the data for IP and other IP related Packets
*/
void 
IP_BASE(const u_char *p, u_int caplen, struct IP_info *ip){
	// IP things are here. 
	// use gotoxy
	int i = 0; 
    u_int8_t ip_length = ip->leng*4;
	// edit the format that it prints out in last 
    printf("\t\t\tIP Header: \n");
    printf("\tIP Version: %d\n", ip->ver);
    printf("\tHeader Length: %d\n", ip->leng);
    printf("\tTime To Live: %d hops\n", ip->ttl);
	printf("--------------------------------------------\n");
    printf("SRC IP Address: \tDEST IP Address: ");
	
    while(i < 3) {
        printf("%d.", ip->source_add[i]);
 		printf("%d.", ip->dest_add[i]);
		 i++; 
    }
	printf("%d\n", ip->source_add[3]);
 	printf("%d\n", ip->dest_add[3]);

// ICMP PORTTION: 
	struct ICMP_info *icmp = (struct ICMP_info *)((p + 14) + (ip->leng*4));
    ICMP_Count++;

    printf("ICMP Header Info:\t");
    printf("\tType: %i", icmp->type );
	printf( "\t\t Code: %d\t\t", icmp->c);
	printf( "\tChecksum Offset: %d\n", ntohs(icmp->_check));

// TCP PORTION:
    
    struct TCP_info *tcp = (struct TCP_info *)(p + 14 + ip_length);
	Tcp_count++;

	// this is all needing to be formated.
    printf("\tTCP :\n");
    printf("\t\tSource Port: %u\n", ntohs(tcp->src));
    printf("\t\tDestination Port: %u\n", ntohs(tcp->dest));
    printf("\t\tSequence Number: %u\n", ntohl(tcp->seq_num));
    printf("\t\tAcknowledgement Number: %u\n", ntohl(tcp->ack_num));
    printf("\t\tData Offset: %d\n", (u_int)tcp->_soff);
	printf("--------------------------------------------");
	printf("\n");
    printf("\tFlags:\n");
    printf("\t\tUrgent Pointer (URG): %d\n", (u_int)tcp->ug);
    printf("\t\tAcknowledgement (ACK): %d\n", (u_int)tcp->ack);
    printf("\t\tReset the Connection (RST): %d\n", (u_int)tcp->rs);
	printf("\t\tPush (PSH): %d\n", (u_int)tcp->ps);
    printf("\t\tSynchronize Sequence Numbers (SYN): %d\n", (u_int)tcp->sy);
    printf("\t\tFinish (FIN): %d\n", (u_int)tcp->fn);
	printf("\n");
	printf("--------------------------------------------\n");
    printf("\t\tWindow: %d\n", ntohs(tcp->win));
    printf("\t\tChecksum: %d\n", ntohs(tcp->chksum));
    printf("\t\tUrgent Pointer: %d\n", ntohs(tcp->urp));
	printf("--------------------------------------------\n");


	// ports(p,caplen,tcp);
	int offset = 14 + ip_length + 20;
	int byte_count =0; 
	for(int i = offset; i < caplen; i++){
	   
	
		if(ntohs(tcp->src == 143) || ntohs(tcp->dest) == 143) {
        printf("\n\t		IMAP Payload		\t\n");
		Imap_count++; 
    } else if(ntohs(tcp->src) == 110 || ntohs(tcp->dest) == 110) {
        printf("\n\t		POP Payload		\t\n");
		Pop_count++;
    } else if(ntohs(tcp->src) == 80 || ntohs(tcp->dest) == 80) {
        printf("\n\t		HTTP Payload		\t\n");
		Http_count++;
    } else if(ntohs(tcp->src) == 25 || ntohs(tcp->dest) == 25) {
        printf("\n\t		SMTP Payload		\t\n");
		Smtp_count++;
    }
	 if(byte_count >= 10) {
            printf("\n");
			printf("--------------------------------------------\n");

            byte_count = 0;
        }

    if(isprint(p[i])) { 
            printf("%c ", p[i]);
        } 
        byte_count++;
	}

}

/*
	Handles the printing for the program. 
*/
void 
raw_print(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
        u_int length = h->len;
        u_int caplen = h->caplen;

  // what to do about the Ethernet type... hmm... hmmm
	e_type = p[12]*256 + p[13];

	printf("E_Type = %04X ", e_type);
	if (e_type == 0x800){
		    num_ip_packets++;
			Declrations(p,caplen);
	    	printf(" ->IP \n");

			// IP things here 
	}
	if (e_type == 0x806){
		      num_apr_packets++;
			 Declrations(p,caplen);
	        printf(" ->APR \n");
	}
        printf("DESTINATION Address = %02x:%02X:%02X:%02X:%02X:%02X:\n",
		       	p[0],p[1],p[2],p[3],p[4],p[5]);
        printf("SENDER Address = %02x:%02X:%02X:%02X:%02X:%02X:\n",
		       	p[6],p[7],p[8],p[9],p[10],p[11]);
				   
	if (p[6] == 0xFF && p[7] == 0xFF && p[8] == 0xFF && p[9] == 0xFF && p[10] == 0xFF && p[11] == 0xFF) {
        Broad_count++;
    }
        putchar('\n');
  
}
