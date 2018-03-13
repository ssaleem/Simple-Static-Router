/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));  /*2nd link: 3rd link in sr_arpcache.c*/
    /* Call the below one for hardcoded ARP cache  
    sr_arpcache_init_hardcoded(&(sr->cache));  */    
    
    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);
    /*print_hdrs(packet, len); */

    /* fill in code here */
    int minlength = sizeof(sr_ethernet_hdr_t);
    if (len < minlength) {
        fprintf(stderr, "Packet is of insufficient length\n");
        return;
    }
    struct sr_if* iface = sr_get_interface(sr, interface);
    assert(iface);
    
    struct sr_ethernet_hdr* e_hdr = 0;
    struct sr_arp_hdr*      a_hdr = 0;
    struct sr_ip_hdr*       i_hdr = 0;
    struct sr_icmp_hdr*  icmp_hdr = 0;
 
    /* For newly constructed packets */
    unsigned char *newpacket                = 0;
    struct sr_ethernet_hdr*       new_e_hdr = 0;
    struct sr_icmp_t3_hdr*  new_icmp_t3_hdr = 0;
    struct sr_icmp_t11_hdr*  new_icmp_t11_hdr = 0;
    struct sr_arp_hdr*            new_a_hdr = 0;
    struct sr_ip_hdr*             new_i_hdr = 0;
    unsigned int new_len;
    
    /* Routing Table and ARP Cache look-up results */
    struct sr_rt*       lpm_match = 0;
    struct sr_arpentry* arp_entry = 0;
    struct sr_if*        fwdiface = 0;
    int sent;   
    /* For ARP Cache related affairs*/
    struct sr_arpreq* req = 0;
    
    e_hdr = (struct sr_ethernet_hdr*)packet;
    uint16_t ethtype = ethertype(packet);
    if (ethtype == ethertype_ip) { /* IP */
    
        fprintf(stderr, "====================IP==================\n");
        i_hdr = (struct sr_ip_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
        uint8_t ip_proto = ip_protocol(i_hdr);
        uint32_t destination_ip = i_hdr->ip_dst;
        uint8_t  dest_mac[ETHER_ADDR_LEN];
        memcpy(dest_mac, e_hdr->ether_dhost,ETHER_ADDR_LEN);
        int router_packet = packet_for_me(sr, destination_ip);   /*Defined in sr_if.h, sr_if.c*/
        uint16_t ip_checksum = i_hdr->ip_sum;
        i_hdr->ip_sum = 0x0000;

        if (ip_checksum != cksum (i_hdr, sizeof(sr_ip_hdr_t)))  /*Corrupt Packet */
            fprintf(stderr, "=======Invalid Checksum-Do Nothing==================\n");
        else if(router_packet) {  /*Packet Destined to Router */
            if (ip_proto == ip_protocol_icmp) { /* ICMP */
            
                fprintf(stderr, "================ICMP Packet====================\n");
                icmp_hdr = (struct sr_icmp_hdr*)(packet + sizeof(struct sr_ethernet_hdr)+ sizeof(sr_ip_hdr_t));
                
                if(icmp_hdr->icmp_type == icmp_type_echorequest)   /* Echo Request-> Send Echo Reply */ /*CORRRECT*/  
                    sr_send_echoreply(sr , packet, len , interface, e_hdr, i_hdr, icmp_hdr);      
            }
            else if ((ip_proto == ip_protocol_udp ) || (ip_proto == ip_protocol_tcp ))  /*Traceroute -> Send Port Unreachable*//*CORRECT*/
                sr_send_portunreachable(sr , interface, e_hdr, i_hdr);          
        } 
        else {  /* Packet requires forwarding */
            if (i_hdr->ip_ttl <= 1)  /* Send ICMP Time Exceeded *//* CORRECT*/
                sr_send_icmptimeexceeded(sr , interface, e_hdr, i_hdr, iface);
            else {  /*Forward*//*CORRECT*/
            /* client wget 172.64.3.10*/
                i_hdr->ip_ttl = i_hdr->ip_ttl - 1;
                lpm_match = lpm(sr, i_hdr->ip_dst);
                fwdiface = sr_get_interface(sr, lpm_match->interface);
                i_hdr->ip_sum = cksum (i_hdr, sizeof(sr_ip_hdr_t));
                memcpy(e_hdr->ether_shost, fwdiface->addr,ETHER_ADDR_LEN);
                if(lpm_match){
                    fprintf(stderr, "\n================Matching Routing Entry====================\n");
                    sr_print_routing_entry(lpm_match);
                    arp_entry = sr_arpcache_lookup((&(sr->cache)), (lpm_match->gw).s_addr);
                    if(arp_entry){
                    fprintf(stderr, "================Matching ARP Entry====================\n");
                    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
                    fprintf(stderr, "-----------------------------------------------------------\n");
                    unsigned char *mac = arp_entry->mac;
                    fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(arp_entry->ip), ctime(&(arp_entry->added)), arp_entry->valid);
                    memcpy(e_hdr->ether_dhost, arp_entry->mac,ETHER_ADDR_LEN);
                    /*fprintf(stderr, "================Fwd Packet Begins====================\n");
                    print_hdrs(packet, len); 
                    fprintf(stderr, "================Fwd Packet Ends====================\n"); */
                    /* Forward  */
                    sent = sr_send_packet(sr, packet , len, lpm_match->interface);
                    fprintf(stderr, "Packet Forwarded = %d", sent); 
                    free(arp_entry);
                    }
                    else{
                        req = sr_arpcache_queuereq(&(sr->cache), (lpm_match->gw).s_addr, packet, len, lpm_match->interface);
                        handle_arpreq(sr, req);
                        }
                }
                else {  /* Send Destination Net Unreachable*/ /*CORRECT*/
                    /*fprintf(stderr, "\n================No Matching Routing Entry====================\n");*/
                    sr_send_destnetunreachable(sr , interface, e_hdr, i_hdr, iface);
                }
            }
        } 
    }
    else if (ethtype == ethertype_arp) { /* ARP */
        /*fprintf(stderr, "================ARP================\n");*/
        
        a_hdr = (struct sr_arp_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
           
        if (a_hdr->ar_op == htons(arp_op_request))     /* ARP REQUEST Received */ /*CORRRECT*/ /*Implicitly checked using ping to router*/
            sr_send_arpreply(sr, packet , len, interface);               
        else if (a_hdr->ar_op == htons(arp_op_reply)) { /* ARP REPLY Received */ /*CORRECT*/
            /* server2 ping -c 1 10.0.1.100*/
            /*fprintf(stderr, "================ARP Reply=================\n");*/
            /* Will be received in response to ARP Request...Update ARP Cache*/
            uint32_t reply_ip = a_hdr->ar_sip;
            uint8_t  reply_mac[ETHER_ADDR_LEN];
            memcpy(reply_mac, a_hdr->ar_sha,ETHER_ADDR_LEN);
            req = sr_arpcache_insert(&(sr->cache), reply_mac, reply_ip);
            sr_arpcache_dump(&(sr->cache));
            if(req){
                struct sr_packet* walker = req->packets;
                while(walker){
                    e_hdr = (struct sr_ethernet_hdr*)(walker->buf);
                    memcpy(e_hdr->ether_dhost, reply_mac,ETHER_ADDR_LEN);
                    
                    int sent = sr_send_packet(sr, walker->buf , walker->len, walker->iface);
                    fprintf(stderr, "Packet Forwarded after receiving ARP Reply = %d\n", sent);
                    walker = walker->next;
                    }
                sr_arpreq_destroy(&(sr->cache), req);
            }
            }
    }
  
}/* end sr_ForwardPacket */

/*---------------------------------------------------------------------
 * Method: sr_send_arpreply(struct sr_instance* , uint8_t* , unsigned int , const char*);
 * Scope:  Global
 *
 *---------------------------------------------------------------------*/
void sr_send_arpreply(struct sr_instance* sr , uint8_t* packet , unsigned int len, const char* interface){
    /*fprintf(stderr, "=============Sending ARP Reply=============\n");*/
    struct sr_if* iface = sr_get_interface(sr, interface);
    struct sr_ethernet_hdr* e_hdr = 0;
    struct sr_arp_hdr*      a_hdr = 0; 
    e_hdr = (struct sr_ethernet_hdr*)packet;
    a_hdr = (struct sr_arp_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
            
    uint32_t target_ip = a_hdr->ar_tip;
    /*fprintf(stderr, "\Target IP Address: ");
    print_addr_ip_int(ntohl(target_ip));*/
    /* Changes in ARP Header 
        -opcode
        -Sender MAC
        -Sender IP
        -Target MAC
        -Target IP 
    */
    a_hdr->ar_op = htons(arp_op_reply);
    a_hdr->ar_tip = a_hdr->ar_sip;
    a_hdr->ar_sip = target_ip;
    memcpy(a_hdr->ar_tha, a_hdr->ar_sha, ETHER_ADDR_LEN);
    memcpy(a_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
    /* Changes in ETHERNET Header 
        -Source MAC
    */
    memcpy(e_hdr->ether_shost, iface->addr,ETHER_ADDR_LEN);
    /* fprintf(stderr, "================ARP Reply Begins====================\n");
    print_hdrs(packet, len); 
    fprintf(stderr, "================ARP Reply Ends====================\n"); */
     /* Send reply  */
    int sent = sr_send_packet(sr, packet , len, interface);
    fprintf(stderr, "ARP Reply sent = %d\n", sent);                

}

/*---------------------------------------------------------------------
 * Method: sr_send_echoreply(struct sr_instance* , uint8_t* , unsigned int , const char*, struct sr_ethernet_hdr*, struct sr_ip_hdr*, struct sr_icmp_hdr*);
 * Scope:  Global
 *
 *---------------------------------------------------------------------*/
void sr_send_echoreply(struct sr_instance* sr , uint8_t* packet, unsigned int len , const char* interface, 
                    struct sr_ethernet_hdr* e_hdr, struct sr_ip_hdr* i_hdr, struct sr_icmp_hdr* icmp_hdr){
    /*server2 ping -c 1 172.64.3.1*/
    uint32_t destination_ip = i_hdr->ip_dst;
    uint8_t  dest_mac[ETHER_ADDR_LEN];
    memcpy(dest_mac, e_hdr->ether_dhost,ETHER_ADDR_LEN);
    /* Changes in ICMP Header
        | type | new checksum |
    */
    icmp_hdr->icmp_sum = 0x0000;
    fprintf(stderr, "\tICMP----Calculated Checksum: %d\n", cksum (icmp_hdr, (len-sizeof(sr_ip_hdr_t))-sizeof(sr_ethernet_hdr_t)));
    icmp_hdr->icmp_type = ntohs(icmp_type_echoreply);
    icmp_hdr->icmp_sum = cksum (icmp_hdr, (len-sizeof(sr_ip_hdr_t))-sizeof(sr_ethernet_hdr_t));
    /* Changes in IP Header 
        | Source Ip | Destination Ip | new checksum |
    */ 
    i_hdr->ip_dst = i_hdr->ip_src; 
    i_hdr->ip_src = destination_ip;
    i_hdr->ip_sum = cksum (i_hdr, sizeof(sr_ip_hdr_t));
    /* Changes in Ethernet Header
        | Source MAC | Destination MAC |
    */
    memcpy(e_hdr->ether_dhost, e_hdr->ether_shost,ETHER_ADDR_LEN);
    memcpy(e_hdr->ether_shost, dest_mac,ETHER_ADDR_LEN);
   /* fprintf(stderr, "================Echo Reply Begins====================\n");
    print_hdrs(packet, len); 
    fprintf(stderr, "================Echo Reply Ends====================\n");
    /* Send reply  */
    int sent = sr_send_packet(sr, packet , len, interface);
    fprintf(stderr, "Echo Reply sent = %d", sent);
}

/*---------------------------------------------------------------------
 * Method: sr_send_portunreachable(struct sr_instance* , uint8_t* , unsigned int , const char*, struct sr_ethernet_hdr*, struct sr_ip_hdr*);
 * Scope:  Global
 *
 *---------------------------------------------------------------------*/
void sr_send_portunreachable(struct sr_instance* sr , const char* interface, struct sr_ethernet_hdr* e_hdr, struct sr_ip_hdr* i_hdr){

    /*server2 traceroute -n 172.64.3.1*/
    unsigned char *newpacket                = 0;
    struct sr_ethernet_hdr*       new_e_hdr = 0;
    struct sr_icmp_t3_hdr*  new_icmp_t3_hdr = 0;
    struct sr_ip_hdr*             new_i_hdr = 0;
    unsigned int new_len;
    uint32_t destination_ip = i_hdr->ip_dst;
    uint8_t  dest_mac[ETHER_ADDR_LEN];
    memcpy(dest_mac, e_hdr->ether_dhost,ETHER_ADDR_LEN);
    
    fprintf(stderr, "================Traceroute Received====================\n");
    /* Construct new packet */
    new_len = sizeof(struct sr_ethernet_hdr) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    newpacket = malloc(new_len);
    new_e_hdr = (struct sr_ethernet_hdr *)newpacket;
    new_i_hdr = (struct sr_ip_hdr*)(newpacket + sizeof(struct sr_ethernet_hdr));
    new_icmp_t3_hdr = (struct sr_icmp_t3_hdr*)(newpacket + sizeof(struct sr_ethernet_hdr)+ sizeof(sr_ip_hdr_t));
    /* Changes in ICMP Header
            | type | code | new checksum | unused = 0 | copy IP header and first 8 bytes of data in 'data' field
    */
    new_icmp_t3_hdr->icmp_sum = 0x0000;
    new_icmp_t3_hdr->icmp_type = icmp_type_destunreach;
    new_icmp_t3_hdr->icmp_code = icmp_code_destportunreach;
    new_icmp_t3_hdr->unused = 0x0000;
    memcpy(new_icmp_t3_hdr->data, i_hdr, ICMP_DATA_SIZE);
    new_icmp_t3_hdr->icmp_sum = cksum (new_icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));
    
    /* Changes in IP header */
    new_i_hdr->ip_hl = i_hdr->ip_hl; 
    new_i_hdr->ip_v = i_hdr->ip_v;
    new_i_hdr->ip_tos =  i_hdr->ip_tos;           
    new_i_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    new_i_hdr->ip_off = htons(IP_DF);
    new_i_hdr->ip_id = 0x0000;
    new_i_hdr->ip_p = ip_protocol_icmp;
    new_i_hdr->ip_ttl = 0xFF;
    new_i_hdr->ip_dst = i_hdr->ip_src; 
    new_i_hdr->ip_src = destination_ip;
    new_i_hdr->ip_sum = 0x0000;
    new_i_hdr->ip_sum = cksum (new_i_hdr, sizeof(sr_ip_hdr_t));
    /* Changes in Ethernet header 
        | Source MAC | Destination MAC | ether type
    */
    memcpy(new_e_hdr->ether_dhost, e_hdr->ether_shost,ETHER_ADDR_LEN);
    memcpy(new_e_hdr->ether_shost, dest_mac,ETHER_ADDR_LEN);
    new_e_hdr->ether_type = e_hdr->ether_type;
    /*fprintf(stderr, "================Port Unreachable Begins====================\n");
    print_hdrs(newpacket, new_len); 
    fprintf(stderr, "================Port Unreachable Ends====================\n");
    /* Send and free */
    int sent = sr_send_packet(sr, newpacket , new_len, interface);
    fprintf(stderr, "Port Unreachable sent = %d", sent);
    free(newpacket);
}
/*---------------------------------------------------------------------
 * Method: sr_send_icmptimeexceeded(struct sr_instance* , uint8_t* , unsigned int , const char*, struct sr_ethernet_hdr*, struct sr_ip_hdr*, struct sr_if* );
 * Scope:  Global
 *
 *---------------------------------------------------------------------*/
void sr_send_icmptimeexceeded(struct sr_instance* sr , const char* interface, struct sr_ethernet_hdr* e_hdr, struct sr_ip_hdr* i_hdr, struct sr_if* iface){

    /*mininet> server2 traceroute -n -m 1 10.0.1.100
    traceroute to 10.0.1.100 (10.0.1.100), 1 hops max, 60 byte packets
    1  172.64.3.1  86.040 ms  85.148 ms  87.045 ms  */
    unsigned char *newpacket                = 0;
    struct sr_ethernet_hdr*       new_e_hdr = 0;
    struct sr_icmp_t11_hdr*  new_icmp_t11_hdr = 0;
    struct sr_ip_hdr*             new_i_hdr = 0;
    unsigned int new_len;
    uint8_t  dest_mac[ETHER_ADDR_LEN];
    memcpy(dest_mac, e_hdr->ether_dhost,ETHER_ADDR_LEN);
    fprintf(stderr, "================TTL<=1 Received====================\n");
    /* Construct new packet */
    new_len = sizeof(struct sr_ethernet_hdr) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t);
    newpacket = malloc(new_len);
    new_e_hdr = (struct sr_ethernet_hdr *)newpacket;
    new_i_hdr = (struct sr_ip_hdr*)(newpacket + sizeof(struct sr_ethernet_hdr));
    new_icmp_t11_hdr = (struct sr_icmp_t11_hdr*)(newpacket + sizeof(struct sr_ethernet_hdr)+ sizeof(sr_ip_hdr_t));
    /* Changes in ICMP Header
            | type | code | new checksum | unused = 0 | copy IP header and first 8 bytes of data in 'data' field
    */
    new_icmp_t11_hdr->icmp_sum = 0x0000;
    new_icmp_t11_hdr->icmp_type = icmp_type_timeexceeded;
    new_icmp_t11_hdr->icmp_code = icmp_code_timeexceeded;
    new_icmp_t11_hdr->unused = 0x00000000;
    memcpy(new_icmp_t11_hdr->data, i_hdr, ICMP_DATA_SIZE);
    new_icmp_t11_hdr->icmp_sum = cksum (new_icmp_t11_hdr, sizeof(sr_icmp_t11_hdr_t));
    
    /* Changes in IP header */
    new_i_hdr->ip_hl = i_hdr->ip_hl; 
    new_i_hdr->ip_v = i_hdr->ip_v;
    new_i_hdr->ip_tos =  i_hdr->ip_tos;           
    new_i_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
    new_i_hdr->ip_off = htons(IP_DF);
    new_i_hdr->ip_id = 0x0000;
    new_i_hdr->ip_p = ip_protocol_icmp;
    new_i_hdr->ip_ttl = 0xFF;
    new_i_hdr->ip_dst = i_hdr->ip_src; 
    new_i_hdr->ip_src = iface->ip; /* This should be router interface on which traceroute received*/
    new_i_hdr->ip_sum = 0x0000;
    new_i_hdr->ip_sum = cksum (new_i_hdr, sizeof(sr_ip_hdr_t));
    /* Changes in Ethernet header 
        | Source MAC | Destination MAC | ether type
    */
    memcpy(new_e_hdr->ether_dhost, e_hdr->ether_shost,ETHER_ADDR_LEN);
    memcpy(new_e_hdr->ether_shost, dest_mac,ETHER_ADDR_LEN);
    new_e_hdr->ether_type = e_hdr->ether_type;
    /*fprintf(stderr, "================Time Exceeded Begins====================\n");
    print_hdrs(newpacket, new_len); 
    fprintf(stderr, "================Time Exceeded Ends====================\n");
    /* Send and free */
    int sent = sr_send_packet(sr, newpacket , new_len, interface);
    fprintf(stderr, "Time Exceeded sent = %d", sent);
    free(newpacket);

}

/*---------------------------------------------------------------------
 * Method: sr_send_destnetunreachable(struct sr_instance* , uint8_t* , unsigned int , const char*, struct sr_ethernet_hdr*, struct sr_ip_hdr*);
 * Scope:  Global
 *
 *---------------------------------------------------------------------*/
void sr_send_destnetunreachable(struct sr_instance* sr , const char* interface, struct sr_ethernet_hdr* e_hdr, struct sr_ip_hdr* i_hdr, struct sr_if* iface){

    /* server2 ping -c 1 10.0.1.100*/
    unsigned char *newpacket                = 0;
    struct sr_ethernet_hdr*       new_e_hdr = 0;
    struct sr_icmp_t3_hdr*  new_icmp_t3_hdr = 0;
    struct sr_ip_hdr*             new_i_hdr = 0;
    unsigned int new_len;
    uint8_t  dest_mac[ETHER_ADDR_LEN];
    memcpy(dest_mac, e_hdr->ether_dhost,ETHER_ADDR_LEN);
    
    fprintf(stderr, "================Fwding for unknown IP Received====================\n");
    /* Construct new packet */
    new_len = sizeof(struct sr_ethernet_hdr) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    newpacket = malloc(new_len);
    new_e_hdr = (struct sr_ethernet_hdr *)newpacket;
    new_i_hdr = (struct sr_ip_hdr*)(newpacket + sizeof(struct sr_ethernet_hdr));
    new_icmp_t3_hdr = (struct sr_icmp_t3_hdr*)(newpacket + sizeof(struct sr_ethernet_hdr)+ sizeof(sr_ip_hdr_t));
    /* Changes in ICMP Header
            | type | code | new checksum | unused = 0 | copy IP header and first 8 bytes of data in 'data' field
    */
    new_icmp_t3_hdr->icmp_sum = 0x0000;
    new_icmp_t3_hdr->icmp_type = icmp_type_destunreach;
    new_icmp_t3_hdr->icmp_code = icmp_code_destnetunreach;
    new_icmp_t3_hdr->unused = 0x0000;
    memcpy(new_icmp_t3_hdr->data, i_hdr, ICMP_DATA_SIZE);
    new_icmp_t3_hdr->icmp_sum = cksum (new_icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));
    
    /* Changes in IP header */
    new_i_hdr->ip_hl = i_hdr->ip_hl; 
    new_i_hdr->ip_v = i_hdr->ip_v;
    new_i_hdr->ip_tos =  i_hdr->ip_tos;           
    new_i_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    new_i_hdr->ip_off = htons(IP_DF);
    new_i_hdr->ip_id = 0x0000;
    new_i_hdr->ip_p = ip_protocol_icmp;
    new_i_hdr->ip_ttl = 0xFF;
    new_i_hdr->ip_dst = i_hdr->ip_src; 
    new_i_hdr->ip_src = iface->ip;
    new_i_hdr->ip_sum = 0x0000;
    new_i_hdr->ip_sum = cksum (new_i_hdr, sizeof(sr_ip_hdr_t));
    /* Changes in Ethernet header 
        | Source MAC | Destination MAC | ether type
    */
    memcpy(new_e_hdr->ether_dhost, e_hdr->ether_shost,ETHER_ADDR_LEN);
    memcpy(new_e_hdr->ether_shost, dest_mac,ETHER_ADDR_LEN);
    new_e_hdr->ether_type = e_hdr->ether_type;
    /*fprintf(stderr, "================Destination Network Unreachable Begins====================\n");
    print_hdrs(newpacket, new_len); 
    fprintf(stderr, "================Destination Network Unreachable Ends====================\n");
    /* Send and free */
    int sent = sr_send_packet(sr, newpacket , new_len, interface);
    fprintf(stderr, "Destination Network Unreachable sent = %d", sent);
    free(newpacket);
}
/*---------------------------------------------------------------------
 * Method: sr_send_desthostunreachable(struct sr_instance* , uint8_t* , unsigned int , const char*, struct sr_ethernet_hdr*, struct sr_ip_hdr*);
 * Scope:  Global
 *
 *---------------------------------------------------------------------*/
void sr_send_desthostunreachable(struct sr_instance* sr , const char* interface, struct sr_ethernet_hdr* e_hdr, struct sr_ip_hdr* i_hdr){

    /* server2 ping -c 1 10.0.1.100*/
    unsigned char *newpacket                = 0;
    struct sr_ethernet_hdr*       new_e_hdr = 0;
    struct sr_icmp_t3_hdr*  new_icmp_t3_hdr = 0;
    struct sr_ip_hdr*             new_i_hdr = 0;
    unsigned int new_len;
    
    uint8_t  dest_mac[ETHER_ADDR_LEN];
    memcpy(dest_mac, e_hdr->ether_dhost,ETHER_ADDR_LEN);
    struct sr_if* iface = sr_get_interface(sr,dest_mac );
    
    fprintf(stderr, "================Sending for known IP but no response of ARPs====================\n");
    /* Construct new packet */
    new_len = sizeof(struct sr_ethernet_hdr) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    newpacket = malloc(new_len);
    new_e_hdr = (struct sr_ethernet_hdr *)newpacket;
    new_i_hdr = (struct sr_ip_hdr*)(newpacket + sizeof(struct sr_ethernet_hdr));
    new_icmp_t3_hdr = (struct sr_icmp_t3_hdr*)(newpacket + sizeof(struct sr_ethernet_hdr)+ sizeof(sr_ip_hdr_t));
    /* Changes in ICMP Header
            | type | code | new checksum | unused = 0 | copy IP header and first 8 bytes of data in 'data' field
    */
    new_icmp_t3_hdr->icmp_sum = 0x0000;
    new_icmp_t3_hdr->icmp_type = icmp_type_destunreach;
    new_icmp_t3_hdr->icmp_code = icmp_code_desthostunreach;
    new_icmp_t3_hdr->unused = 0x0000;
    memcpy(new_icmp_t3_hdr->data, i_hdr, ICMP_DATA_SIZE);
    new_icmp_t3_hdr->icmp_sum = cksum (new_icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));
    
    /* Changes in IP header */
    new_i_hdr->ip_hl = i_hdr->ip_hl; 
    new_i_hdr->ip_v = i_hdr->ip_v;
    new_i_hdr->ip_tos =  i_hdr->ip_tos;           
    new_i_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    new_i_hdr->ip_off = htons(IP_DF);
    new_i_hdr->ip_id = 0x0000;
    new_i_hdr->ip_p = ip_protocol_icmp;
    new_i_hdr->ip_ttl = 0xFF;
    new_i_hdr->ip_dst = i_hdr->ip_src; 
    new_i_hdr->ip_src = iface->ip;
    new_i_hdr->ip_sum = 0x0000;
    new_i_hdr->ip_sum = cksum (new_i_hdr, sizeof(sr_ip_hdr_t));
    /* Changes in Ethernet header 
        | Source MAC | Destination MAC | ether type
    */
    memcpy(new_e_hdr->ether_dhost, e_hdr->ether_shost,ETHER_ADDR_LEN);
    memcpy(new_e_hdr->ether_shost, dest_mac,ETHER_ADDR_LEN);
    new_e_hdr->ether_type = e_hdr->ether_type;
    /*fprintf(stderr, "================Destination Host Unreachable Begins====================\n");
    print_hdrs(newpacket, new_len); 
    fprintf(stderr, "================Destination Host Unreachable Ends====================\n");
    /* Send and free */
    int sent = sr_send_packet(sr, newpacket , new_len, interface);
    fprintf(stderr, "Destination Host Unreachable sent = %d", sent);
    free(newpacket);
}
/*---------------------------------------------------------------------
 * Method: sr_send_arprequest(struct sr_instance* sr , const char* interface, uint32_t t_ip);
 * Scope:  Global
 *
 *---------------------------------------------------------------------*/
void sr_send_arprequest(struct sr_instance* sr , const char* interface, uint32_t t_ip){
    unsigned char *newpacket                = 0;
    struct sr_ethernet_hdr*       new_e_hdr = 0;
    struct sr_arp_hdr*            new_a_hdr = 0;
    unsigned int new_len;
    new_len = sizeof(struct sr_ethernet_hdr) + sizeof(sr_arp_hdr_t);
    newpacket = malloc(new_len);
    new_e_hdr = (struct sr_ethernet_hdr *)newpacket;
    new_a_hdr = (struct sr_arp_hdr*)(newpacket + sizeof(struct sr_ethernet_hdr));
    struct sr_if* fwdiface = sr_get_interface(sr, interface);
    
    /* Changes in ARP Header 
        -Hardware Type
        -Protocol Type
        -Hardware Address Length
        -Protocol Address Length
        -opcode
        -Sender MAC
        -Sender IP
        -Target MAC
        -Target IP 
    */
    new_a_hdr->ar_hrd = htons(arp_hrd_ethernet);
    new_a_hdr->ar_pro = htons(ethertype_ip);
    new_a_hdr->ar_hln = arp_hln_ethernet;
    new_a_hdr->ar_pln = arp_pln_ip;
    new_a_hdr->ar_op = htons(arp_op_request);
    new_a_hdr->ar_tip = t_ip;
    new_a_hdr->ar_sip = fwdiface->ip;
    memset(new_a_hdr->ar_tha, 0, ETHER_ADDR_LEN);
    memcpy(new_a_hdr->ar_sha, fwdiface->addr, ETHER_ADDR_LEN);
    /* Changes in ETHERNET Header 
        -Source MAC
        -Destination MAC
        -EtherType
    */
    memcpy(new_e_hdr->ether_shost, fwdiface->addr,ETHER_ADDR_LEN);
    memset(new_e_hdr->ether_dhost, 0xFF,ETHER_ADDR_LEN);
    new_e_hdr->ether_type = htons(ethertype_arp);
    /*fprintf(stderr, "================ARP Request Begins====================\n");
    print_hdrs(newpacket, new_len); 
    fprintf(stderr, "================ARP Request Ends====================\n"); 
     /* Send request  */
    int sent = sr_send_packet(sr, newpacket , new_len, interface);
    fprintf(stderr, "ARP Request sent = %d\n", sent); 
    free(newpacket);
}