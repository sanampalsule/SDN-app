SDN - Software defined networking: 


This project aims to present the design and implementation of a software-defined networking (SDN) application that combines layer-3 shortest path routing with distributed load balancing.


Two primary applications : 


1. Shortest Path Routing
2. LoadBalancing




* The ShortestPathSwitching module computes and installs shortest path routes between hosts using Dijkstra's algorithm
* The LoadBalancer module distributes incoming TCP connections across a set of backend hosts. The two modules work together to provide efficient routing and load balancing in an SDN environment.