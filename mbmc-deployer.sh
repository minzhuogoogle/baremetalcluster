#!/usr/bin/env bash


delete_vm() {
    name=$1
    echo $name
    for i in `gcloud compute instances list --project $project --filter="zone:$zone name:$name"  | grep -v NAME |  cut -d ' ' -f1`;
    do
        echo "vm to be deleted: $i, $project, $zone"
        gcloud compute instances delete $i --project $project --zone $zone -q;
        retval=$?
        if [ $retval -ne 0 ]; then
            return -1
        fi
    done
    return 0
}

delete_address() {
    name=$1
    region=$2
    echo "delete_address $name $region"
    #echo "cmd: gcloud compute addresses list --project $project --filter=$region | grep $name |  cut -d ' ' -f1"
    for i in `gcloud compute addresses list --filter=$region | grep $name |  cut -d ' ' -f1`;
    do
         echo "addess to be deleted: $i, $project, $region"
         gcloud compute addresses delete $i --project $project --region $region -q;
         retval=$?
         if [ $retval -ne 0 ]; then
             return -1
         fi
    done
}

delete_subnet() {
     name=$1
     region=$2
     echo "delete_subnet $name $region"
     #echo "cmd: gcloud compute  networks subnets  list --project $project   --filter=$region | grep $name  | cut -d ' ' -f1"
     for i in `gcloud compute  networks subnets  list  --filter=$region | grep $name  | cut -d ' ' -f1`;
     do
         echo "subnet to be deleted: $i, $project, $region"
         gcloud compute  networks subnets delete $i --project $project --region $region -q;
         retval=$?
         if [ $retval -ne 0 ]; then
             echo "delete vm $name fails."
             return -1
         fi
     done
}

delete_route() {
    name=$1
    region=$2
    echo "delete_route $name $region"
    #echo "cmd: gcloud compute routes list --project $project  --filter=$region | grep $name  | cut -d ' ' -f1"
    for i in `gcloud compute routes list   --filter=$region | grep $name  | cut -d ' ' -f1`;
    do
        echo "route to be deleted: $i, $project, $region"
        gcloud compute  routes delete $i --project $project -q;
        retval=$?
        if [ $retval -ne 0 ]; then
	    echo "delete route $name fails."
            return -1
        fi
     done
}

delete_network() {
    name=$1
    region=$2
    echo "delete_network $name $region"
    #echo "cmd: gcloud compute  networks subnets  list --project $project   --filter=$region | grep $name  | cut -d ' ' -f1"
    for i in `gcloud compute networks list --project $project  --filter=$region | grep $name | cut -d ' ' -f1`;
    do
        echo "network to be deleted: $i, $project, $region"
        gcloud compute networks  delete $i --project $project -q;
        retval=$?
        if [ $retval -ne 0 ]; then
	    echo "delete network $name fails."
            return -1
        fi
     done
}

delete_firewall() {
    name=$1
    region=$2
    echo "delete_firewall $name $region"
    #echo "cmd: gcloud compute firewall-rules list --project $project  --filter="NAME:$name"  --format="table(NAME)" | grep -v NAME |  cut -d ' ' -f1"
    for i in `gcloud compute firewall-rules list  --filter="NAME:$name"  --format="table(NAME)" | grep -v NAME |  cut -d ' ' -f1`;
    do
        echo "firewall to be deleted: $i, $project, $region"
        gcloud compute firewall-rules delete $i --project $project -q;
        retval=$?
        if [ $retval -ne 0 ]; then
	    echo "delete firewall $name fails."
            return -1
        fi
     done
}

cleanup_test() {
    name=$1
    delete_vm $name
    for i in `gcloud compute regions list  | cut -d ' ' -f1`
    do
        echo $i
        if [[ $zone =~ $i ]]; then
           echo "zone $zone in region $i "
           delete_address $name $i
           delete_subnet $name $i
           delete_route $name $i
           delete_network $name $i
	   continue
	fi   
    done
    delete_firewall $name
}

purge_all_resources() {
  randomid=$1
  if [ $randomid -eq 0 ]; then
    vmname="bm-vm-"
    vpcname="bm-vpc-"
  else
    vmname=$zone-$grandomid
    vpcname="bm-vpc-$grandomid"
  fi
#  purge_all_vms $vnname
#  purge_all_vpc $vpcname
}

setup_gcp_env() {
  service_account=bmc-sa-$PROJECT_ID-$grandomid
  service_account=$(sed 's/\(.\{30\}\).*/\1/' <<< "$service_account")
  #### If you have SA and key ready,
  ### you can set them here to skip SA and key creation.
  #service_account=mzhuo-bare-metal
  sa_key=bmc-sakey-$PROJECT_ID-$grandomid.json
  if  [[  -f "$sa_key" ]]; then
     echo "INFO: will re-user SA $service_account@$PROJECT_ID.iam.gserviceaccount.com and SA Key $sa_key"
     return
  fi
  gcloud services enable \
    anthos.googleapis.com \
    anthosgke.googleapis.com \
    cloudresourcemanager.googleapis.com \
    container.googleapis.com \
    gkeconnect.googleapis.com \
    gkehub.googleapis.com \
    serviceusage.googleapis.com \
    stackdriver.googleapis.com \
    monitoring.googleapis.com \
    logging.googleapis.com

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
  --role="roles/monitoring.admin"


  gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:$service_account@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/monitoring.dashboardEditor"

  gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:$service_account@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/stackdriver.admin"

  gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:$service_account@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/stackdriver.resourceMetadata.writer"

  gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:$service_account@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/compute.admin"

  gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:$service_account@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/compute.StorageAdmin"
}

setup_global_variable() {
  EXTRA_SSH_ARGS=()
  if command -v corp-ssh-helper &> /dev/null
  then
    EXTRA_SSH_ARGS=(-- -o ProxyCommand='corp-ssh-helper %h %p' -ServerAliveInterval=30 -o ConnectTimeout=30)
  fi
  VPC_PREFIX=bm-vpc
  VPC=$VPC_PREFIX-$grandomid
  MACHINE_TYPE=n1-standard-8
  VM_PREFIX=bm-vm
  VM_WS=$VM_PREFIX-admin-bmc-$zone-$grandomid
  VM_GW=$VM_PREFIX-gateway-bmc-$zone-$grandomid
  FIREWALL_NAME=bm-fw-$VPC-$grandomid
  GVMs+=("$VM_WS")
  GVMs+=("$VM_GW")
  gip=2
  until [ $gip -gt $totalnumofvm ]; do
      tip=10.0.2.$gip
      GIPs+=("$tip")
      gip=$((gip+1))
  done
  tip=10.0.2.$gip
  GIPs+=("$tip")
  unset $tip
  unset $gip
}

setup_local_variable() {
  clustername=bmc-gce-$cluster_index-$zone-$grandomid
  if [ ${#clustername} -gt 64 ]; then
    echo "Clustername $clustername is too long, chopping it to the short one"
    clustername=$(sed 's/\(.\{63\}\).*/\1/' <<< "$clustername")
  fi
  VM_CP0=$VM_PREFIX-c0-bmc-c$cluster_index-$zone-$grandomid
  VM_CP1=$VM_PREFIX-c1-bmc-c$cluster_index-$zone-$grandomid
  VM_W0=$VM_PREFIX-w0-bmc-c$cluster_index-$zone-$grandomid
  VM_W1=$VM_PREFIX-w1-bmc-c$cluster_index-$zone-$grandomid
  VM_W2=$VM_PREFIX-w2-bmc-c$cluster_index-$zone-$grandomid

  declare -a VMs=("$VM_WS" "$VM_CP0" "$VM_W0" "$VM_W1" "$VM_W2" "$VM_GW")
  GVMs+=("$VM_CP0")
  GVMs+=("$VM_W0")
  GVMs+=("$VM_W1")
  GVMs+=("$VM_W2")
}

create_vpc() {
  gcloud compute networks create $VPC --subnet-mode=custom  --bgp-routing-mode=regional
  retcode=$?
  if [ $retcode -ne 0 ] ; then
    if [ ! "$VPC" = "default" ]; then
        echo "Fail to create VPC $VPC, check quota in case there is no quota."
        exit 1
    fi
  fi
  gcloud compute networks subnets create bm-cluster-$grandomid --range=10.0.2.0/24 --network=$VPC --region=$region
  gcloud compute firewall-rules create $FIREWALL_NAME --network $VPC --allow all
  gcloud compute project-info add-metadata --metadata enable-oslogin=FALSE
}

populate_route_table_worknode() {
  vm=$1
  vlaninterface=$2
  echo "Ppopulate routing table for worknode $vm for cluster $((vlaninterface+1))"
  gatewayip0=$((loop*32+7))
  ncluster=0
  until [ $ncluster -eq  $totalclusters ]; do
    if [ $((ncluster+1)) -ne $vlaninterface ]; then
      for lbindex in {0..3}; do
        gcloud compute ssh root@$vm --zone $zone "${EXTRA_SSH_ARGS[@]}" << EOF
          set -x
          ip route add 10.201.1.$((ncluster*32+lbindex+10))/32 via 10.201.1.$gatewayip0 dev vxlan$vlaninterface
EOF
      done
    fi
    ncluster=$((ncluster+1))
  done
}

populate_route_table_controlnode() {
  vm=$1
  vlaninterface=$2
  echo "Populate_route_table_for control node,  $vm for cluster $((vlaninterface+1))"
  gatewayip0=$((loop*32+7))
  subnet=0
  until [ $subnet -eq $totalclusters ]; do
     if [ $subnet -ne $loop ]; then
       gcloud compute ssh root@$vm --zone $zone "${EXTRA_SSH_ARGS[@]}" << EOF
       set -x
       ip route add 10.201.1.$((subnet*32))/27 via 10.201.1.$gatewayip0 dev vxlan$vlaninterface
EOF
     fi
     subnet=$((subnet+1))
  done
}

add_fwd_entry_all_nodes() {
  vm=$1
  vlanint=$2
  localip=$(gcloud compute instances describe $vm --zone $zone  \
         --format='get(networkInterfaces[0].networkIP)')
  if [ $mnetworkflag -eq 0 ];then
    gcloud compute ssh root@$vm --zone $zone "${EXTRA_SSH_ARGS[@]}" << EOF
      set -x
      for vxlanip0 in {2..$totalnumofvm}; do
        ip=10.0.2.$vxlanip0
        if [ "$ip" != "$local_ip" ]; then
          bridge fdb append to 00:00:00:00:00:00 dst $ip dev vxlan$vlanint
        fi
      done
EOF
  else
    gcloud compute ssh root@$vm --zone $zone "${EXTRA_SSH_ARGS[@]}" << EOF
      set -x
      for vxlanip0 in {1..$totalclusters}; do
        for vmnumbers in {1..4}; do
          temp0=$((loop*32+1+vmnumbers))
          ip=10.0.2.$temp0
          if [ "$ip" != "$localip" ]; then
             bridge fdb append to 00:00:00:00:00:00 dst $ip dev vxlan$vlanint
          fi
        done
      done
EOF
  fi
}

create_vm() {
  if [ $loop -gt 0 ]; then
     declare -a VMs=("$VM_CP0" "$VM_W0" "$VM_W1" "$VM_W2")
     declare -a IPs=("10.0.2.2" "10.0.2.7")
  else
     declare -a VMs=("$VM_WS" "$VM_CP0" "$VM_W0" "$VM_W1" "$VM_W2" "$VM_GW")
     declare -a IPs=()
  fi
  for vm in ${VMs[@]}
  do
    IP=10.0.2.$vmip0
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
              --machine-type $MACHINE_TYPE \
              --private-network-ip $IP \
              --subnet bm-cluster-$grandomid \
              --service-account $service_account@$PROJECT_ID.iam.gserviceaccount.com
    retcode=$?
    if [ $retcode -ne 0 ]; then
       echo "Fail to create VM $vm"
       exit 1
    fi

    IPs+=("$IP")
    vmip0=$((vmip0+1))
    vm_index=$((vm_index+1))
  done
  if [ ${#IPs[@]} -ne 6 ]; then
      echo "IP table building failure, exit"
      exit 1
  fi
}

wait_for_ssh() {
  if [ $loop -gt 0 ]; then
     declare -a VMs=("$VM_CP0" "$VM_W0" "$VM_W1" "$VM_W2")
  else
     declare -a VMs=("$VM_WS" "$VM_CP0" "$VM_W0" "$VM_W1" "$VM_W2" "$VM_GW")
  fi
  retry_count=0
  for vm in "${VMs[@]}"
  do
    while ! gcloud compute ssh root@$vm --zone $zone --command "echo SSH to $vm succeeded" "${EXTRA_SSH_ARGS[@]}"
    do
        echo "Trying to SSH into $vm failed. Sleeping for 10 seconds. zzzZZzzZZ"
        sleep  10
        retry_count=$((retry_count+1))
        if [ $retry_count -gt 6 ]; then
           echo "Fail to ssh to $vm"
           exit 1
        fi
    done
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
    retcode=$?
    if [ $retcode -ne 0 ]; then
       echo "Fail to install pkges on $vm"
       exit 1
    fi
  done
}

build_connectivity() {
  declare -a VMs=("$VM_CP0" "$VM_W0"  "$VM_W1" "$VM_W2")
  for vm in "${VMs[@]}"; do
    case ${vm} in
          #bm-vm-c0-bmc*|)
	  bm-vm-c*|bm-vm-w*)
            if [  $mnetworkflag -eq 1 ]; then
                populate_route_table_controlnode $vm $cluster_index
            fi
            ;;
          bm-vm-w0-bmc*|bm-vm-w1-bmc*|bm-vm-w2-bmc*)
	    echo "skip"
            #populate_route_table_worknode $vm $cluster_index
            ;;
    esac
  done
}

create_vxlan() {
 declare -a VMs=("$VM_WS" "$VM_CP0" "$VM_W0" "$VM_W1" "$VM_W2" "$VM_GW")
 if [ $mnetworkflag -eq 1 ]; then
    vxlan_index=$cluster_index
 else
    vxlan_index=1
 fi
 interface=vxlan$vxlan_index
 for vm in "${VMs[@]}"; do
   ipvxlan=10.201.1.$vxip0
   gcloud compute ssh root@$vm --zone $zone "${EXTRA_SSH_ARGS[@]}" << EOF
   set -x
   ip link add $interface type vxlan id $vxlan_index dev ens4 dstport $vxlan_index
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
    vxip0=$((vxip0+1))
  done

  IP4Control=10.201.1.$vxip0
  vxip0=$((vxip0+1))
  IP4Ingress=10.201.1.$vxip0
  vxip0=$((vxip0+1))
  IP4Lber1=10.201.1.$vxip0
  vxip0=$((vxip0+1))
  IP4Lber2=10.201.1.$vxip0
  vxip0=$((vxip0+1))
  IP4Lber3=10.201.1.$vxip0
  vxip0=$((vxip0+1))
  IP4Lber4=10.201.1.$vxip0
  vxip0=$((vxip0+1))
  IP4Lber5=10.201.1.$vxip0
  vxip0=$((vxip0+1))
  IP4Lber6=10.201.1.$vxip0
}

prepare_admin_ws() {
   gcloud compute scp $sa_key root@$VM_WS:/root/$sa_key --zone $zone
   retcode=$?
   if [ $retcode -ne 0 ]; then
       echo "Fail to copy sa keys to $VM_WS"
       exit 1
   fi
   gcloud compute scp nginx.yaml root@$VM_WS:/root/nginx.yaml --zone $zone
   gcloud compute ssh root@$VM_WS --zone $zone "${EXTRA_SSH_ARGS[@]}" << EOF
   curl -LO "https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl"
   chmod +x kubectl
   mv kubectl /usr/local/sbin/kubectl

   mkdir baremetal && cd baremetal
   ##### If you want to use image from other source, you can change it here.
   #### Bare Metal Prod image is : gs://anthos-baremetal-release
   #### Bare Metal Staging image is : gs://anthos-baremetal-staging
   #### To use Staging image please talk to Bare Metal Team.
   gsutil cp gs://anthos-baremetal-release/bmctl/$version/linux-amd64/bmctl bmctl
   chmod a+x bmctl
   mv bmctl /usr/local/sbin/
   cd ~
   echo "Installing docker"
   curl -fsSL https://get.docker.com -o get-docker.sh
   sh get-docker.sh
   curl -L https://istio.io/downloadIstio | sh -
EOF
   if [ $retcode -ne 0 ]; then
       echo "Fail to prepare $VM_WS"
       exit 1
   fi
}

enable_ip_forwarding() {
   gcloud compute ssh root@$VM_GW --zone $zone "${EXTRA_SSH_ARGS[@]}" << EOF
   sudo bash -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
EOF
   gcloud compute ssh root@$VM_WS --zone $zone "${EXTRA_SSH_ARGS[@]}" << EOF
   sudo bash -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
EOF
}

prepare_ssh_key() {
  gcloud compute ssh root@$VM_WS --zone $zone "${EXTRA_SSH_ARGS[@]}" << EOF
      set -x
      rm -rf ssh-metadata
      ssh-keygen -t rsa -N "" -f ~/.ssh/id_rsa
      sed 's/ssh-rsa/root:ssh-rsa/' ~/.ssh/id_rsa.pub > ssh-metadata
EOF
  gcloud compute scp root@$VM_WS:/root/ssh-metadata ssh-metadata-$grandomid --zone $zone
  retcode=$?
  if [ $retcode -ne 0 ]; then
       echo "Fail to copy metadata from $VM_WS to local machine."
       exit 1
  fi
}

copy_ssh_key_to_vms() {
  declare -a VMs=("$VM_CP0" "$VM_W0" "$VM_W1" "$VM_W2" "$VM_GW")
  for vm in ${VMs[@]}; do
    gcloud compute instances add-metadata $vm --zone $zone --metadata-from-file ssh-keys=ssh-metadata-$grandomid
    retcode=$?
    if [ $retcode -ne 0 ]; then
       echo "Fail to set metadata for \$vm."
       exit 1
    fi
  done
}

prepare_bmc_config() {
  gcloud compute ssh root@$VM_WS --zone $zone "${EXTRA_SSH_ARGS[@]}" << EOF
  set -x
  export PROJECT_ID=$PROJECT_ID
  export clustername=$clustername
  export sa_key=$sa_key
  export CP0IP=$CP0IP
  export W0IP=$W0IP
  export W1IP=$W1IP
  export W2IP=$W2IP
  export IP4Control=$IP4Control
  export IP4Ingress=$IP4Ingress
  export IP4Lber1=$IP4Lber1
  export IP4Lber2=$IP4Lber2
  export IP4Lber3=$IP4Lber3
  export IP4Lber4=$IP4Lber4
  export IP4Lber5=$IP4Lber5
  export IP4Lber6=$IP4Lber6
  export region=$region
  export version=$version

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
  name: \$clustername
---
apiVersion: baremetal.cluster.gke.io/v1
kind: Cluster
metadata:
  name: \$clustername
  namespace: \$clustername
spec:
  type: hybrid
  anthosBareMetalVersion: \$version
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
  namespace: \$clustername
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

install_asm() {
  gcloud compute ssh root@$VM_WS --zone $zone "${EXTRA_SSH_ARGS[@]}" << EOF
  export clustername=$clustername
  set -x
  cd istio-1.8.2
  export PATH=$PWD/bin:$PATH
  export KUBECONFIG=/root/bmctl-workspace/$clustername/$clustername-kubeconfig
  /root/istio-1.8.2/bin/istioctl install --set profile=demo -y
  kubectl create namespace bookstore
  kubectl label namespace bookstore istio-injection=enabled
  kubectl apply -f samples/bookinfo/platform/kube/bookinfo.yaml -n bookstore
  kubectl apply -f samples/bookinfo/networking/bookinfo-gateway.yaml -n bookstore
  /root/istio-1.8.2/bin/istioctl analyze
EOF
}

deploy_nginx() {
  gcloud compute ssh root@$VM_WS --zone $zone "${EXTRA_SSH_ARGS[@]}" << EOF
  export clustername=$clustername
  set -x
  export KUBECONFIG=/root/bmctl-workspace/$clustername/$clustername-kubeconfig
  kubectl create namespace nginx
  kubectl apply -f nginx.yaml -n nginx
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
# in the same network or different networks.                #
# ###########################################################
#
# By default the current project in your env is used.
# If you need to change project, pls do it before running the script.
# A new VPC with random identifier will be created.
#

PROJECT_ID=$(gcloud config get-value project)
echo
echo
echo "=================================================================================="
echo "Syntax:"
echo "=================================================================================="
echo "./mbmc-deployer.sh [Version] [Number of clusters] [differnet_network [1|0]]"
echo
echo "      Version: Anthos BareMetal Release"
echo "      Number of clusters: integer from 1 to 8. By default it is 2."
echo "      Same or diff network: 1 is to use different network. By default, it is 1."
echo
echo "Note:"
echo "    By default, region is set to \"us-central1\" or \"us-east1\""
echo "    zone is set to \"us-central1-c\" or \"us-east1-c\"".
echo "    Please notice not all regions allows to deploy vm using machine type \"Intel Haswel\"."
echo
echo "    The script, by default, uses GCP project set in the env where you run the script."
echo "    Run gcloud config get-value projectid to check your current project id."
echo "    Run gcloud config set project [projectid] to set to a new project."
echo
echo
echo "    WARNING: you need to have the correct GCP project set and make sure you have IAM admin role."

#################################
# These are hard-coded variables.
region=us-central1
zone=us-central1-c
cluster_index=1
vmip0=2
#################################

if [ -z "$1" ]
then
    version=1.6.1
    mnetworkflag=1
    totalclusters=2
else
    version=$1
    if [ -z "$2" ]
    then
      totalclusters=2
      mnetworkflag=1
    else
      totalclusters=$2
      if [ -z "$3" ]
      then
        mnetworkflag=1
      else
        mnetworkflag=$3
      fi
    fi
fi

### TODO: hiddlen cmd to delete all resource links to grandomid.
if [ "$version" == "delete" ]; then
  # purge_all_resources $2
  echo "Under Constrution"
fi

if [ $mnetworkflag -eq 1 ]; then
  region=us-central1
  zone=us-central1-c
else
  region=us-east1
  zone=us-east1-c
fi

if [ $totalclusters -gt 8 ]; then
  echo "Total number of clusters should  be less than or equal to 16."
  exit 1
fi


totalnumofvm=$((totalclusters*4+2))
# By default the first cluster used vlan index same as cluster index
grandomid=$(( $RANDOM % 9999999999 ))
echo "The script is going to build $totalnumofvm VMs in $PROJECT_ID."
echo "    Region: $region"
echo "    Zone: $zone"
echo "$totalclusters Bare Metal clusters are to be provisioned over $totalnumofvm VMs."
if [ $mnetworkflag -eq 0 ]; then
  echo "All clusters are in the same network."
else
  echo "All clusters are in the different networks."
fi
echo "You have 30 seconds to stop it.........."
sleep 30

declare -a GIPs=()
declare -a GVMs=()

loop=0
vm_index=1

setup_gcp_env
setup_global_variable
create_vpc
until [ $loop -eq $totalclusters ]; do
  vxip0=$((loop*32+2))
  setup_local_variable
  create_vm
  wait_for_ssh
  if [ $loop -eq 0 ]; then
     prepare_admin_ws
     prepare_ssh_key
  fi
  create_vxlan
  if [ $mnetworkflag -eq 1 ]; then
    enable_ip_forwarding
    build_connectivity
  fi
  install_standard_pkt
  copy_ssh_key_to_vms
  prepare_bmc_config
  install_asm
  deploy_nginx
  cluster_index=$((cluster_index+1))
  loop=$((loop+1))
  GVMs+=("$VM_CP0")
  GVMs+=("$VM_W0")
  GVMs+=("$VM_W1")
  GVMs+=("$VM_W2")
done

echo "Finishing all clusters creation!"
echo
echo
echo "If everything is fine, you can access istio demo app bookinfo at: "
echo "  10.201.1.x/productpage, x=10,42,74,106,138,170"
echo "  For example, to access bookinfo in the 1st cluster,"
echo "  curl http://10.201.1.9/productpage"
echo "Nginx is able to be accessed at:"
echo "  10.201.1.y, y=11, 43, 75, 106, 139, 170"
echo "  For example, to access nginx in the 1st cluster,"
echo "  curl http://10.201.1.10/productpage"
echo "Additional 4 load-balancer VIPs are available in the pool."
echo "Cross-cluster Ingress communication is built for the first 3 Ingress VIPs."

echo "Summary Report:"
echo "==========================================================="
echo "List of VMs created in project $PROJECT_ID, zone: $zone:"
for vm in ${GVMs[@]}
do
     echo $vm
done
echo "You can ssh to bootstrap VM $VM_WS to access Bare Metal Clusters."
echo "Please delete all resouces if no longer needed."
echo "============================================================"
