# Bare-metal  Cluster Deployer
## Objective

To create multiple bare metal clusters based on GCP VMs in the same network or different networks. Enable Routing to make ingress reachable across different clusters.

## Summary
As for the BM cluster built on GCP VM all nodes and Load-balancer in the cluster should be in the same L2 network. Vxlan is used to build a virtual L2 overlay on top of GCE VMs.
In each BM cluster there is a bootstrap VM, control nodes and work nodes. To build connectivity to allow all nodes to access load-balancer in a different cluster a gateway VM is introduced which has a Vxlan interface for each cluster. 

## Implementation

There are multiple load-balance schemes for Bare-Metal Cluster. Here we use a hybrid Load-balancer scheme bundled in Control Nodes in cluster.

### Multi-cluster in same network

   1.1 Build multiple BM clusters
   
   1.2 Adding fwd entries in all nodes to allow L2 connectivity among all nodes in all cluster

### Multi-cluster in different networks

   2.1 Build multiple BM clusters
  
   2.2 Build gateway VM which has Vxlan interface per cluster
  
   2.3 On all control nodes add routers to L2 subnet in the other cluster
  
   2.3 On all nodes add routers to load-balancer in the other cluster
   
       *Bootstrap can be used as the gateway too ideally. 
       
### Usage
./mbmc-deployer.sh [cluster_index] [differnet_network [1|0]] [Number of clusters]

      Cluster_index: integer from 0 to 255. By default it is 1.
      Same or diff network: 1 is to use different network. By default, it is 1.
      Number of clusters: integer from 1 to 16. By default it is 2.
      
      Please download all files to the same directory before running this tool.
      



