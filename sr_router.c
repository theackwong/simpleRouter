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
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/* TODO: Add constant definitions here... */

/* TODO: Add helper functions here... */

 //returns the route using longest prefix matching
struct sr_rt* longest_prefix_matching(struct sr_instance* sr, uint32_t dest){

    struct sr_rt* current = sr->routing_table;
    struct sr_rt* match = NULL;
    unsigned long longest_match = 0;
    struct in_addr dest_addr;
    dest_addr.s_addr = dest;

    while(current != NULL){ //while there are still entries in the routing table
        if (((dest_addr.s_addr & current->mask.s_addr) == (current->dest.s_addr & current->mask.s_addr)) & (longest_match <= current->mask.s_addr)){
            longest_match = current->mask.s_addr;
            match = current;
        }
        current = current->next;
    }
    return match;

}


/* See pseudo-code in sr_arpcache.h */
void handle_arpreq(struct sr_instance* sr, struct sr_arpreq *req){
    time_t currtime = time(NULL);

    if (difftime(currtime, req->sent) > 1.0){
        if (req_times_sent >= 5){
            //send icmp host unreachable to source addr of all pkts waiting on req
            //will use method defined in sr_router.c
            sr_arpreq_destroy(&sr, req);
        }
        else{
            //send arp request

            struct sr_rt* rt_entry = longest_prefix_matching(sr, req->ip);
            struct sr_if* sr_interface = sr_get_interface(sr, req->packets->iface);

            struct sr_arpentry* existing_arp = sr_arpcache_lookup(&sr->cache, rt_entry->gw.s_addr);

            sr_arp_hdr_t* arp_header = (struct sr_arp_hdr*)malloc(sizeof(struct sr_arp_hdr));
            //fill out the arp header
            arp_header->ar_hrd = htons(arp_hdr_ethernet);             /* format of hardware address   */
            arp_header->ar_pro = htons(ethertype_ip);             /* format of protocol address   */
            arp_header->ar_hln = ETHER_ADDR_LEN;             /* length of hardware address   */
            arp_header->ar_pln = sizeof(uint32_t);             /* length of protocol address   */
            arp_header->ar_op = htons(arp_op_request);              /* ARP opcode (command)         */
            arp_header->ar_sha = sr_interface->addr;   /* sender hardware address      */
            arp_header->ar_sip = sr_interface->ip;             /* sender IP address            */
            //arp_header->ar_tha[ETHER_ADDR_LEN];   /* target hardware address *IGNORE FOR ARP      */
            arp_header->ar_tip = req->ip;

            //send the packet
            struct sr_ethernet_hdr ether_header;
            uint8_t* ether_packet = malloc(sizeof(sr_arp_hdr_t) + sizeof(struct sr_ethernet_hdr));

            ether_header.ether_type = htons(ethertype_arp);
            memcpy(ether_packet, &ether_header, sizeof(struct sr_ethernet_hdr));
            memcpy(ether_packet + sizeof(struct sr_ethernet_hdr), arp_header, sizeof(sr_arp_hdr_t));

            if(existing_arp){
               
                ether_header.ether_dhost = existing_arp->mac;
                ether_header.ether_shost = sr_interface->addr; 
                
            }else{
                 
                memset(ether_header.ether_dhost, 255, ETHER_ADDR_LEN);
                memcpy(ether_header.ether_shost, sr_interface->addr, ETHER_ADDR_LEN);
            }

            sr_send_packet(sr, ether_packet, packet_len + sizeof(struct sr_ethernet_hdr), rt_entry->interface);
            free(ether_packet);

            req->sent = currtime;
            req->times_sent++;
        }
    }

}
  

void sr_send_packet(struct sr_instance* sr, )


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
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* TODO: (opt) Add initialization code here */

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
 * by sr_vns_comm.c that means do NOT free either (signified by "lent" comment).  
 * Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */){

  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d\n",len);

  /* TODO: Add forwarding logic here */
 
  

}/* -- sr_handlepacket -- */

