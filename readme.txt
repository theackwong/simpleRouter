Group Members: names and usernames of each member
JUNDA LI(username:jundal)
ANDREW WONG(username: acw16)


---------------------------------------------------------------------------------------
Work Division: who implemented/tested which part
JUNDA implement the IP Forwarding and tested
	- IP sending
ANDREW implemented/tested:
	- ARP sending/receiving
	- ICMP sending

---------------------------------------------------------------------------------------
Known Bugs/Issues: all bugs or issues that you know of in your code



---------------------------------------------------------------------------------------
Code Design: Briefly describe the design of your code and the data structures implemented.
we are implemented the router is based on the packet header structure is encapsulate on Ethernet -> ip -> icmp.

In regards to sending of packets, one main helper method, direct_and_send was used to properly wrap the ethernet headers for any packet being sent out
as well as sending out ARP request/replies. If a packet was to be sent out, first the direct_and_send method would check the ARP cache for a matching IP->MAC address. If one was found, that address would be used in the header for that ethernet frame and then sent out from there. If there was no existing item in the ARP cache with a matching IP->MAC, then a arp request object would be created and placed in the arp queue. Then, the handle_arpreq method would be used to send out the ARP requests. The actual sending out of the ARP request is done again through the direct_and_send method.

Once a ARP reply is received, the ARP queue is checked for any requests matching the recieved MAC address. If a match occurs, then any packets that were placed in the queue that are waiting on that reply will be fulfilled and then the corresponding packets would be loaded with this MAC address and then sent out. 