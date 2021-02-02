# baremetalcluster
Objective:
To create multiple bare metal clusters based on GCP VMs in the same network or different networks. Enable Routing to make ingress reachable across different clusters.

Summary:
As for the BM cluster built on GCP VM all nodes and Load-balancer in the cluster should be in the same L2 network. Vxlan is used to build a virtual L2 overlay on top of GCE VMs.
In each BM cluster there is a bootstrap VM, control nodes and work nodes. To build connectivity to allow all nodes to access load-balancer in a different cluster a gateway VM is introduced which has a Vxlan interface for each cluster. 
