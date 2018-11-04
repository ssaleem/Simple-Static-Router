# Static Network Router
This project is a network router application programmed in C and configured with a static routing table. Upon receiving raw Ethernet frames, the router processes the packets just like a real router and then forward them to the correct outgoing interface. Following standard ARP and IP protocols and longest prefix match, the router handles ARP packets and forwards IP packets.
Some of the operations supported by the router are
- _ping_ to and through the router.
- _traceroute_ to and through the router. 
- Downloading files from HTTP servers using `wget/curl`.

## Implemented Protocols 
Following protocols are implemented for correct functionality of router
- Ethernet
- ARP
- IP
- ICMP

## Installation
- Download/clone the project on your machine and go to the project folder.
- To install type `make` in the terminal.
- To run type `./sr` in the terminal.

## Topology
To test router functionality, [Mininet](http://mininet.org/) is used. Mininet, a software package developed at Stanford, allows to emulate a topology on a single machine. It provides the isolation between the emulated nodes so that router node can process and forward real Ethernet frames between the hosts like a real router. Following topology is emulated on Mininet for this project.
```
-------------                ------------
| server1   |                | server2  |
-------------                ------------
     |                            |
     |                            |
      ------------     -----------
                  |   |
               ------------                  
               | router   |                  
               ------------
                    |
               ------------                  
               | client   |                  
               ------------
```