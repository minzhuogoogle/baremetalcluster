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

./mbmc-deployer.sh [Version] [Number of clusters] [differnet_network [1|0]]

 * Version: Anthos BareMetal Release"
 * Number of clusters: integer from 1 to 8. By default it is 2.
 * Same or diff network: 1 is to use different network. By default, it is 1.

#### Sample 1: create one BM cluster
./mbmc-deployer.sh 1.6.1 1 

#### Sample 2: create 2 BM clusters in different networks
./mbmc-deployer.sh 1.6.1 2 

#### Sample 3: create 2 BM clusters in the same network
./mbmc-deployer.sh 1.6.1 2 0

#### Sample 4: create 8 BM clusters in the same network
./mbmc-deployer.sh 1.6.1 8 0

### Note

* By default, region is set to \"us-central1\", zone is set to \"us-central1-c\".

* Please notice not all regions allows to deploy vm using machine type \"Intel Haswel\".

* The script, by default, uses GCP project set in the env where you run the script.

* Run gcloud config get-value projectid to check your current project id.

* Run gcloud config set project [projectid] to set to a new project.

* After VM rebooting all routing table will be lost.  Connection between 2 clusters in different network will not work after rebooting.





