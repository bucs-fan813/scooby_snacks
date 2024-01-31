#!/usr/bin/env bash
# Script Name: Packer Flush
#
# Author: bucs-fan813@users.noreply.github.com
# Date : 01/10/2024
#
# Description: Packer Flush removes all straggling resources created by packer (ec2 instances, AMIs, snapshots, security groups, key pairs). AWS free-tier
#               
#
# Run Information: ./packer_flush/run.sh

# Set globals
ACCOUNT_ID="${1:-self}"

# ACCOUNT_ID must be a 12 digit AWS account ID or "self" (default)
if ! [[ "${ACCOUNT_ID}" =~ ^[0-9]{12}$ || "${ACCOUNT_ID}" == "self" ]]; then
    echo "Invalid AWS account ID"
    exit 1
fi

echo -e "AWS Account ID: \e[1m\e[33m${ACCOUNT_ID}\e[0m"

# Flush VPCs
vpc_ids=$(aws ec2 describe-vpcs --query 'Vpcs[].VpcId' --output text)
vpcs=$(echo $vpc_ids | wc -w)
printf "VPCs (including default): "
echo -e "\e[1m\e[33mFound ${vpcs}\e[0m"

# Flush instances
printf "EC2s: "
instance_ids=$(aws ec2 describe-instances --query 'Reservations[].Instances[?State.Name!=`terminated`].InstanceId' --output text)
instances=$(echo $instance_ids | wc -w)
echo -e "\e[1m\e[33mFound ${instances}\e[0m"

if [ $instances -gt 0 ]; then
    echo "Deleting {${instances}} EC2 instances"
    aws ec2 terminate-instances --instance-ids ${instance_ids[@]}
fi

# Flush AMIs
printf "AMIs: "
ami_ids=$(aws ec2 describe-images --owner "${ACCOUNT_ID}" --query 'Images[].ImageId' --output text)
amis=$(echo $ami_ids | wc -w)
echo -e "\e[1m\e[33mFound ${amis}\e[0m"

if [ $amis -gt 0 ]; then
    echo "De-registering {${amis}} AMIs"
    for ami_id in ${ami_ids[@]}; do aws ec2 deregister-image --image-id $ami_id; done
fi

# Flush snapshots
printf "Snapshots: "
snapshot_ids=$(aws ec2 describe-snapshots --owner "${ACCOUNT_ID}" --query 'Snapshots[].SnapshotId' --output text)
snapshots=$(echo $snapshot_ids | wc -w)
echo -e "\e[1m\e[33mFound ${snapshots}\e[0m"

if [ $snapshots -gt 0 ]; then
    echo "Deleting {${snapshots}} snapshots"
    for snapshot_id in ${snapshot_ids[@]}; do aws ec2 delete-snapshot --snapshot-id $snapshot_id; done
fi

# Flush security groups
printf "Security Groups (exluding default): "
sg_ids=$(aws ec2 get-security-groups-for-vpc --vpc-id ${vpc_ids} --query 'SecurityGroupForVpcs[?GroupName!=`default`].GroupId' --output text)
sgs=$(echo $sg_ids | wc -w)
echo -e "\e[1m\e[33mFound ${sgs}\e[0m"

# TODO: add deadman switch
drain_count=$(aws ec2 describe-instance-status --query 'length(InstanceStatuses[].InstanceState[?Name!=`terminated`])')
while [ $drain_count -gt 0 ]; do
  echo "Waiting 10 seconds for (${drain_count}) instances to terminate..."
  sleep 10
  drain_count=$(aws ec2 describe-instance-status --query 'length(InstanceStatuses[].InstanceState[?Name!=`terminated`])')
done

if [ $sgs -gt 0 ]; then
    echo "Deleting security {${sgs}} groups"
    for sg_id in ${sg_ids[@]}; do aws ec2 delete-security-group --group-id $sg_id; done
fi

# Flush key pairs
printf "Key Pairs: "
keypair_ids=$(aws ec2 describe-key-pairs --query 'KeyPairs[].KeyPairId' --output text)
keypairs=$(echo $keypair_ids | wc -w)
echo -e "\e[1m\e[33mFound ${keypairs}\e[0m"

if [ $keypairs -gt 0 ]; then
    echo "Deleting key pairs"
    for keypair_id in ${keypair_ids[@]}; do aws ec2 delete-key-pair --key-pair-id $keypair_id; done
fi

# TODO: port to python
# TODO: Dependency checker for awscli and locales-all (so we get pretty numbers)
# TODO: make args for --all (default), --ec2, --snapshots, --vpcs
# TODO: handle non-default VPCs
# TODO: usage()
