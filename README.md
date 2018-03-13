# Simple Static Router
This project is a simple router configured with a static routing table. The router handles ARP and forwards IP packets. Some of the supported operations involve ping, traceroute and downloading files from http server.

## Installation
- To install `make`
- To run `./sr`

## Topology
To test router functionality, [Mininet](http://mininet.org/) is used. Mininet allows to emulate a topology on a single machine. It provides the isolation between the emulated nodes so that router node can process and forward real Ethernet frames between the hosts like a real router. Following topology is emulated on Mininet.
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