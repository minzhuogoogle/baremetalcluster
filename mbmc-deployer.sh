#!/usr/bin/env bash

setup_gcp_env() {
  gcloud config set project $PROJECT_ID
  service_account=baremetal-sa-$grandomid
  sa_key=sa-bmc-key-$zone-$region-$grandomid.json

  gcloud iam service-accounts create $service_account
  gcloud iam service-accounts keys create $sa_key \
   --iam-account=$service_account@${PROJECT_ID}.iam.gserviceaccount.com

  gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:$service_account@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/gkehub.connect"

  gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:$service_account@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/gkehub.admin"

  gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:$service_account@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/logging.logWriter"

  gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:$service_account@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/monitoring.metricWriter"

  gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:$service_account@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/monitoring.dashboardEditor"

  gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:$service_account@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/stackdriver.resourceMetadata.writer"
}

setup_global_variable() {
  VPC_PREFIX=bmvpc
  VPC=$VPC_PREFIX-$grandomid
  MACHINE_TYPE=n1-standard-4
  VM_PREFIX=bmvm
  VM_WS=$VM_PREFIX-admin-bmc-$zone-$grandomid
  VM_GW=$VM_PREFIX-gateway-bmc-$zone-$grandomid
  FIREWALL_NAME=bm-fw-$VPC-$grandomid
  GVM+=("$VM_WS")
  GVM+=("$VM_GW")
}

setup_local_variable() {
clustername=bmc-gce-$cluster_index-$region-$zone-$PROJECT_ID-$grandomid
VM_CP0=$VM_PREFIX-c0-bmc-$cluster_index-$zone-$grandomid
VM_CP1=$VM_PREFIX-c1-bmc-$cluster_index-$zone-$grandomid
VM_W0=$VM_PREFIX-w0-bmc-$cluster_index-$zone-$grandomid
VM_W1=$VM_PREFIX-w1-bmc-$cluster_index-$zone-$grandomid
VM_W2=$VM_PREFIX-w2-bmc-$cluster_index-$zone-$grandomid

declare -a VMs=("$VM_WS" "$VM_CP0" "$VM_W0" "$VM_W1" "$VM_W2" "$VM_GW")
declare -a IPs=()
GVM+=("$VM_CP0")
GVM+=("$VM_W0")
GVM+=("$VM_W1")
GVM+=("$VM_W2")
}

create_vpc() {
  gcloud compute networks create $VPC
  gcloud compute firewall-rules create $FIREWALL_NAME --network $VPC --allow all
}


create_vm() {
  declare -a IPs=()
  if [ $loop -gt 0 ]; then
     declare -a VMs=("$VM_CP0" "$VM_W0" "$VM_W1" "$VM_W2")
  else
     declare -a VMs=("$VM_WS" "$VM_CP0" "$VM_W0" "$VM_W1" "$VM_W2" "$VM_GW")
  fi
  for vm in ${VMs[@]}
  do
    gcloud compute instances create $vm \
              --image-family=ubuntu-2004-lts --image-project=ubuntu-os-cloud \
              --boot-disk-size 200G \
              --boot-disk-type pd-ssd \
              --can-ip-forward \
              --network $VPC \
              --zone $zone \
              --tags http-server,https-server,cluster-$cluster_index \
              --min-cpu-platform "Intel Haswell" \
              --scopes cloud-platform \
              --machine-type $MACHINE_TYPE
    IP=$(gcloud compute instances describe $vm --zone $zone  \
         --format='get(networkInterfaces[0].networkIP)')
    IPs+=("$IP")
    GIPs+=("$IP")
  done
}

install_standard_pkt() {
  declare -a VMs=("$VM_WS" "$VM_CP0" "$VM_W0" "$VM_W1" "$VM_W2" "$VM_GW")
  for vm in "${VMs[@]}"
  do
    gcloud compute ssh root@$vm --zone $zone "${EXTRA_SSH_ARGS[@]}" << EOF
    apt-get -qq update > /dev/null
    apt-get -qq install -y jq > /dev/null
    apt install net-tools > /dev/null
    systemctl stop apparmor.service #anthos on BM does not support apparmor
    systemctl disable apparmor.service
EOF
  done
}

create_vxlan() {
 declare -a VMs=("$VM_WS" "$VM_CP0" "$VM_W0" "$VM_W1" "$VM_W2" "$VM_GW") 
 if [ $mnetworkflag -eq 1 ]; then
    vlan_index=$cluster_index
 else
    vlan_index=$ip1
 fi
 interface=vxlan$vlan_index

 #### The maximum number of cluster in the same network is 8
 ip0=$(((cluster_index-1)*32+2))   # We start from 10.201.$cluster_index.1/27
 for vm in "${VMs[@]}"; do
   ipvxlan=10.201.$ip1.$ip0
   gcloud compute ssh root@$vm --zone $zone "${EXTRA_SSH_ARGS[@]}" << EOF
   set -x
   ip link add $interface type vxlan id $vlan_index dev ens4 dstport \
   $vlan_index
   current_ip=\$(gcloud compute instances describe $vm --zone $zone  \
         --format='get(networkInterfaces[0].networkIP)')
   for ip in ${GIPs[@]}; do
     if [ "\$ip" != "\$current_ip" ]; then
        bridge fdb append to 00:00:00:00:00:00 dst \$ip dev $interface
     fi
   done
   if [ $mnetworkflag -eq 1 ]; then
      ip addr add $ipvxlan/27 dev $interface
   else
      ip addr add $ipvxlan/24 dev $interface
   fi
   ip link set up dev $interface
EOF
    case ${vm} in
          $VM_CP0)
              CP0IP=$ipvxlan
              ;;
          $VM_CP1)
              CP1IP=$ipvxlan
              ;;
          $VM_W0)
              W0IP=$ipvxlan
              ;;
          $VM_W1)
              W1IP=$ipvxlan
              ;;
          $VM_W2)
              W2IP=$ipvxlan
              ;;
          $VM_WS)
              WSIP=$ipvxlan
              ;;
          $VM_GW)
              GWIP=$ipvxlan
              ;;
    esac
    ip0=$((ip0+1))
  done

  IP4Control=10.201.$ip1.$ip0
  ip0=$((ip0+1))
  IP4Ingress=10.201.$ip1.$ip0
  ip0=$((ip0+1))
  IP4Lber1=10.201.$ip1.$ip0
  ip0=$((ip0+1))
  IP4Lber2=10.201.$ip1.$ip0
  ip0=$((ip0+1))
  IP4Lber3=10.201.$ip1.$ip0
  ip0=$((ip0+1))
  IP4Lber4=10.201.$ip1.$ip0
  ip0=$((ip0+1))
  IP4Lber5=10.201.$ip1.$ip0
  ip0=$((ip0+1))
  IP4Lber6=10.201.$ip1.$ip0
}

prepare_admin_ws() {
   gcloud compute scp $sa_key root@$VM_WS:/root/$sa_key --zone $zone
   gcloud compute scp nginx.yaml root@$VM_WS:/root/$nginx.yaml --zone $zone
   gcloud compute ssh root@$VM_WS --zone $zone "${EXTRA_SSH_ARGS[@]}" << EOF
   curl -LO "https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl"
   chmod +x kubectl
   mv kubectl /usr/local/sbin/
   mkdir baremetal && cd baremetal
   gsutil cp gs://anthos-baremetal-release/bmctl/1.6.0/linux-amd64/bmctl .
   chmod a+x bmctl
   mv bmctl /usr/local/sbin/
   cd ~
   echo "Installing docker"
   curl -fsSL https://get.docker.com -o get-docker.sh
   sh get-docker.sh
   curl -L https://istio.io/downloadIstio | sh -
EOF
}

enable_ip_forwarding() {
   gcloud compute ssh root@$VM_GW --zone $zone "${EXTRA_SSH_ARGS[@]}" << EOF
   sudo bash -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
EOF
   gcloud compute ssh root@$VM_WS --zone $zone "${EXTRA_SSH_ARGS[@]}" << EOF
   sudo bash -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
EOF
}


populate_routing_table(){
  local vm=$1
  local zone=$2
  local cluster_index=$3
  ip0=$(((cluster_index-1)*32+7))
  destip=10.201.$ip1.$ip0
  mask=$(((cluster_index-1)*32))
  vxlan_index=$cluster_index
  vlaninterface=vxlan$vxlan_index
}

prepare_ssh_key() {
  gcloud compute ssh root@$VM_WS --zone $zone "${EXTRA_SSH_ARGS[@]}" << EOF
      set -x
      ssh-keygen -t rsa -N "" -f ~/.ssh/id_rsa
      sed 's/ssh-rsa/root:ssh-rsa/' ~/.ssh/id_rsa.pub > ssh-metadata
EOF
  gcloud compute scp root@$VM_WS:/root/ssh-metadata ssh-metadata --zone $zone
}

copy_ssh_key_to_vms() {
  declare -a VMs=("$VM_WS" "$VM_CP0" "$VM_W0" "$VM_W1" "$VM_W2" "$VM_GW")
  for vm in ${VMs[@]}; do
    gcloud compute instances add-metadata $vm --zone $zone --metadata-from-file ssh-keys=ssh-metadata
  done
}

prepare_bmc_config() {
gcloud compute ssh root@$VM_WS --zone $zone "${EXTRA_SSH_ARGS[@]}" << EOF
set -x
export PROJECT_ID=$(gcloud config get-value project)
export clustername=$clustername
export sa_key=$sa_key
export CP0IP=$CP0IP
export W0IP=$W0IP
export W1IP=$W1IP
export W2IP=$W2IP
export IP4Control=$IP4Control
export IP4Ingress=$IP4Ingress
export LASTIP=$LASTIP
export IP4Lber1=$IP4Lber1
export IP4Lber2=$IP4Lber2
export IP4Lber3=$IP4Lber3
export IP4Lber4=$IP4Lber4
export IP4Lber5=$IP4Lber5
export IP4Lber6=$IP4Lber6

export region=$region


bmctl create config -c \$clustername
cat > bmctl-workspace/\$clustername/\$clustername.yaml << EOB
---
gcrKeyPath: /root/\$sa_key
sshPrivateKeyPath: /root/.ssh/id_rsa
gkeConnectAgentServiceAccountKeyPath: /root/\$sa_key
gkeConnectRegisterServiceAccountKeyPath: /root/\$sa_key
cloudOperationsServiceAccountKeyPath: /root/\$sa_key
---
apiVersion: v1
kind: Namespace
metadata:
  name: cluster-\$clustername
---
apiVersion: baremetal.cluster.gke.io/v1
kind: Cluster
metadata:
  name: \$clustername
  namespace: cluster-\$clustername
spec:
  type: hybrid
  anthosBareMetalVersion: 1.6.0
  gkeConnect:
    projectID: \$PROJECT_ID
  controlPlane:
    nodePoolSpec:
      clusterName: \$clustername
      nodes:
      - address: \$CP0IP
  clusterNetwork:
    pods:
      cidrBlocks:
      - 192.168.0.0/16
    services:
      cidrBlocks:
      - 172.26.232.0/24
  loadBalancer:
    mode: bundled
    ports:
      controlPlaneLBPort: 443
    vips:
      controlPlaneVIP: \$IP4Control
      ingressVIP: \$IP4Ingress
    addressPools:
    - name: pool1
      addresses:
      - \$IP4Ingress/32
      - \$IP4Lber1/32
      - \$IP4Lber2/32
      - \$IP4Lber3/32
      - \$IP4Lber4/32
      - \$IP4Lber5/32
      - \$IP4Lber6/32
  clusterOperations:
    location: \$region
    projectID: \$PROJECT_ID
  storage:
    lvpNodeMounts:
      path: /mnt/localpv-disk
      storageClassName: node-disk
    lvpShare:
      numPVUnderSharedPath: 5
      path: /mnt/localpv-share
      storageClassName: standard
---
apiVersion: baremetal.cluster.gke.io/v1
kind: NodePool
metadata:
  name: node-pool-1
  namespace: cluster-\$clustername
spec:
  clusterName: \$clustername
  nodes:
  - address: \$W0IP
  - address: \$W1IP
  - address: \$W2IP
EOB
bmctl create cluster -c \$clustername
EOF
}

create_bmc() {
  export clustername=$clustername
  gcloud compute ssh root@$VM_WS --zone $zone "${EXTRA_SSH_ARGS[@]}" << EOF
  set -x
  bmctl create cluster -c \$clustername
EOF
}

install_asm() {
gcloud compute ssh root@$VM_WS --zone $zone "${EXTRA_SSH_ARGS[@]}" << EOF
export clustername=$clustername
set -x
cd istio-1.8.2
export PATH=$PWD/bin:$PATH
export KUBECONFIG=/root/bmctl-workspace/$clustername/$clustername-kubeconfig
/root/istio-1.8.2/bin/istioctl install --set profile=demo -y
kubectl label namespace default istio-injection=enabled
kubectl apply -f samples/bookinfo/platform/kube/bookinfo.yaml
kubectl apply -f samples/bookinfo/networking/bookinfo-gateway.yaml
/root/istio-1.8.2/bin/istioctl analyze
EOF
}

deploy_nginx() {
gcloud compute ssh root@$VM_WS --zone $zone "${EXTRA_SSH_ARGS[@]}" << EOF
export clustername=$clustername
set -x
export KUBECONFIG=/root/bmctl-workspace/$clustername/$clustername-kubeconfig
kubectl apply -f nginx.yaml
EOF
}

enable_routing_node() {
  declare -a VMs=("$VM_W0" "$VM_W1" "$VM_W2")
  for vm in ${VMs[@]}; do
    echo "Updating routers in $vm"
    gcloud compute scp populate_routing_table.data root@$vm:/root/nodes.sh --zone $zone
    gcloud compute ssh root@$VM_WS --zone $zone "${EXTRA_SSH_ARGS[@]}" << EOF
    set -x
    chmod +x /root/nodes.sh
    /root/nodes.sh
EOF
  done
}


enable_routing_lber() {
  for vm in {$VM_CP0}; do
    echo "Updating routers in $vm"
    gcloud compute scp populate_routing_table_cp.data root@$vm:/root/cps.sh --zone $zone
    gcloud compute ssh root@$vm --zone $zone "${EXTRA_SSH_ARGS[@]}" << EOF
    set -x
    chmod +x /root/cps.sh
    /root/cps.sh
EOF
  done
}
#############################################################
# This script is to create multiple bare metal clusters     #
# in the same network                                       #
# or different networks                                     #
# ###########################################################
#
#
# By default the current project in your env is used.
# If you need to change prroject, pls do it before running the script.
# A new VPC with random identifier will be created.
PROJECT_ID=$(gcloud config get-value project)

echo
echo
echo "==============================================================================="
echo "Warning:"
echo "==============================================================================="
echo "./mbmc-deployer.sh [cluster_index] [differnet_network?] [Region] [Zone]"
echo "by default, cluster_index is set to 1"
echo "clusters are created in different networks. if same network is desired, pls run:"
echo "./mbmc-deployer.sh [cluster_index] 0"
echo "By default, region is set to us-west1, zone is set to us-west1-c."
echo "Please notice not all regions can deploy vm using  machine type Intel Haswel."

# By default cluster index is set to 1
if [ -z "$1" ]
then
    cluster_index=1
    region=us-west1
    zone=us-west1-c
    mnetworkflag=1
else
    cluster_index=$1
    if [ -z "$2" ]
    then
      mnetworkflag=1
      region=us-west1
      zone=us-west1-c
    else
      mnetworkflag=$2
      if [ -z "$3" ]
      then
          region=us-west1
          zone=us-west1-c
      else
          region=$3
          if [ -z "$4" ]
          then
             zone=$region-c
          else
             zone=$4
          fi
      fi
    fi
fi

# By default the first cluster used vlan index same as cluster index
vlan_index=$((cluster_index-1))
ip1=$cluster_index
grandomid=$(( $RANDOM % 99999 ));
echo "The script is going to build  14 VMs in $PROJECT_ID, $region, $zone."
echo "3 Bare Metal clusters are to be provisioned over 14 VMs."
if [ $mnetworkflag -eq 0 ]; then
  echo "All clusters are in the same network."
else
  echo "All clusters are in the different networks."
fi
echo "You have 30 seconds to stop it.........."

#sleep 30
declare -ga GIPs=()
declare -ga GVMs=()

loop=0
totalclusters=2
setup_gcp_env
setup_global_variable
create_vpc
until [ $loop -gt $totalclusters ]; do
  setup_local_variable
  create_vm
  enable_ip_forwarding
  enable_routing_node
  enable_routing_lber
  install_standard_pkt
  create_vxlan
  if [ $loop -eq 0 ]; then
     prepare_admin_ws
     prepare_ssh_key
  fi
  copy_ssh_key_to_vms
  prepare_bmc_config
  install_asm
  deploy_nginx
  cluster_index=$((cluster_index+1))
  loop=$((loop+1))
done

echo "Finishing all clusters creation!"

