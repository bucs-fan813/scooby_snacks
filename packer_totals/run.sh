#!/usr/bin/env bash
# Script Name: Packer Totals
#
# Author: john@pocdigital.org
# Date : 01/10/2024
#
# Description: Packer Total estimates  (ec2 instances, AMIs, snapshots, security groups, key pairs). AWS free-tier
#               
#
# Run Information: root:/# ./run.sh

# Set globals
ACCOUNT_ID="${1:-self}"
export LC_NUMERIC="en_US.UTF-8" # NOTE: Requires `apt install locales-all`

# ACCOUNT_ID must be a 12 digit AWS account ID or "self" (default)
if ! [[ "${ACCOUNT_ID}" =~ ^[0-9]{12}$ || "${ACCOUNT_ID}" == "self" ]]; then
    echo "Invalid AWS account ID"
    exit 1
fi

# Get snapshots created by packer (use describe-images first instead of describe-snapshots)
snapshots=$(aws ec2 describe-images --owner "${ACCOUNT_ID}" --query 'Images[].BlockDeviceMappings[].Ebs.SnapshotId' --output text)

# Format snapshots array for use in --snapshot-ids
IFS=" " read -r -a snapshot_ids <<< "$snapshots"

# Exit if the snapshots array is empty
if [ ${#snapshot_ids[@]} -eq 0 ]; then
    echo "Uhh ohh, this account doesn't have any snapshots!"
    exit 1
fi

# Get the size (in GB) of each snapshot_id and sum up the results
let snapshot_total_size=0
snapshot_sizes=$(aws ec2 describe-snapshots --owner "${ACCOUNT_ID}" --snapshot-ids ${snapshot_ids} --query 'Snapshots[].VolumeSize' --output text)
for snapshot_size in ${snapshot_sizes[@]}; do ((snapshot_total_size+=$snapshot_size)); done

# Calculate the monthly and annual costs for snapshots
# We have to do a lot of massaging to get bash to deal with floats... use python instead!
aws_standard_monthly=$(awk -v snapshot_total_size="$snapshot_total_size" 'BEGIN{aws_standard_monthly=snapshot_total_size * 0.05; printf "%0.02f",aws_standard_monthly}')
aws_standard_annual=$(awk -v aws_standard_monthly="$aws_standard_monthly" 'BEGIN{aws_standard_annual=aws_standard_monthly * 12; printf "%0.02f",aws_standard_annual}')
aws_archive_monthly=$(awk -v snapshot_total_size="$snapshot_total_size" 'BEGIN{aws_archive_monthly=snapshot_total_size * 0.0125; printf "%0.02f",aws_archive_monthly}')
aws_archive_annual=$(awk -v aws_archive_monthly="$aws_archive_monthly" 'BEGIN{aws_archive_annual=aws_archive_monthly * 12; printf "%0.02f",aws_archive_annual}')
aws_savings=$(echo "$aws_standard_annual $aws_archive_annual" | awk '{print $1 - $2}')

# Print the report
echo "Total size of snapshots: $(printf "%'d\n" $snapshot_total_size) GB"
echo "================================================"
echo -e "Standard tier monthly cost for snapshots: \e[33m$(printf "$%'.2f" $aws_standard_monthly)\e[0m"
echo -e "Standard tier annual cost for snapshots: \e[33m$(printf "$%'.2f" $aws_standard_annual)\e[0m"
echo -e "\e[1mArchive tier monthly cost for snapshots: \e[32m$(printf "$%'.2f" $aws_archive_monthly)\e[0m"
echo -e "\e[1mArchive tier annual cost for snapshots: \e[32m$(printf "$%'.2f" $aws_archive_annual)\e[0m"
echo "================================================"
echo -e "\e[1mAnnual savings per environment: \e[32m$(printf "$%'.2f" $aws_savings)\e[0m"

# TODO: Port to python
# TODO: Depemdency checker for awscli and locales-all (so we get pretty numbers)
# TODO: Handle snapshot_total_size as bytes shown in GB, TB and/or PB
# TODO: Adjust to only calculate X of Y snapshots to convert to archive tier. ie: AMIs snapshots older than 90 days or latest 5 AMI snapshots
# TODO: usage()
# TODO: Extra reporting for # of snapshots, # of AMIs, all snapshots (using flexible-snapshot-proxy)

### Scratchpad ###
# aws ec2 describe-snapshots --filters "Name=owner-id,Values=${ACCOUNT_ID}"
# aws ec2 describe-snapshots --filters "Name=owner-id,Values=${ACCOUNT_ID}" --query 'Snapshots[].[SnapshotId,VolumeSize]' --output text