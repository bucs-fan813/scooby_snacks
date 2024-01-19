#!/usr/bin/env bash
# Script Name: Packer Totals
#
# Author: bucs-fan813@users.noreply.github.com
# Date : 01/10/2024
#
# Description: Packer Total estimates the monthly cost for resources created by packer and compares Standard tier vs Archive tier for snapshots
#
#
# Run Information: ./packer_totals/run.sh

#### Set globals ####
export LC_NUMERIC="en_US.UTF-8" # NOTE: Requires `apt install locales-all`
ACCOUNT_ID="${1:-self}"
let volume_total_size=0
let snapshot_total_bytes=0
#####################

#### Define functions ####
# Get the size (in bytes) of each snapshot_id using flexible-snapshot-proxy (https://github.com/awslabs/flexible-snapshot-proxy)
function get_snapshot_bytes() {
    snapshot_id="${1}"
    echo "$(python3 flexible-snapshot-proxy-main/src/main.py list $snapshot_id | grep -oE ' [0-9]+ ' | tr -d [:blank:] | tail -n1)"
}

# Define the function to process each chunk of snapshot_ids
function process_chunk() {
    # $@ contains the chunk of snapshots
    chunk=("$@")
    let counter=0
    let length=${#chunk[@]}
    for snapshot_id in "${chunk[@]}"; do
        # Process each snapshot as needed
        counter=$((counter + 1))
        # NOTE: Use printf to appear "more" interactive output
        printf "Processing ($counter of $length): \e[1m\e[37m$snapshot_id => "
        snapshot_bytes=$(get_snapshot_bytes $snapshot_id)
        if [ $snapshot_bytes == false ]; then
            echo -e "\e[31mskipped\e[0m"
        else
            echo -e "$snapshot_bytes bytes\e[0m"
            ((snapshot_total_bytes+=snapshot_bytes))
        fi
    done
}
##########################

#### Start Here ####

# Start dependency checks
FLEXIBLE_SNAPSHOT_PROXY=$(ls **/*/main.py 2> /dev/null)
if ! [[ ! -z $FLEXIBLE_SNAPSHOT_PROXY && "$FLEXIBLE_SNAPSHOT_PROXY" =~ .*flexible-snapshot-proxy.* ]]; then
    echo "Downloading flexible-snapshot-proxy from https://github.com/awslabs/flexible-snapshot-proxy/archive/refs/heads/main.zip"
    curl -o flexible-snapshot-proxy.zip
    unzip flexible-snapshot-proxy.zip
    FLEXIBLE_SNAPSHOT_PROXY=$(ls **/*/main.py 2> /dev/null)
fi

# ACCOUNT_ID must be a 12 digit AWS account ID or "self" (default)
if ! [[ "${ACCOUNT_ID}" =~ ^[0-9]{12}$ || "${ACCOUNT_ID}" == "self" ]]; then
    echo "Invalid AWS account ID"
    exit 1
fi

### DEBUG ###
if [[ $ACCOUNT_ID == "self" ]]; then
    echo -e "ACCOUNT_ID: \e[1m\e[37m$ACCOUNT_ID\e[0m ($(aws sts get-caller-identity --query 'Account' --output text))"
else
    echo -e "ACCOUNT_ID: \e[1m\e[37m$ACCOUNT_ID\e[0m"
fi
echo -e "REGION: \e[1m\e[37m$(aws configure get region)\e[0m"

# Get all snapshots in the account
all_snapshots=$(aws ec2 describe-snapshots --owner-ids "${ACCOUNT_ID}" --query 'Snapshots[].SnapshotId' --output text)
all_snapshots_total=$(echo $all_snapshots | wc -w)

# Get snapshots created by packer (use describe-images first instead of describe-snapshots)
ami_snapshots=$(aws ec2 describe-images --owners "${ACCOUNT_ID}" --query 'Images[].BlockDeviceMappings[].Ebs.SnapshotId' --output text)
ami_snapshots_total=$(echo $ami_snapshots | wc -w)

# Format snapshots array for use in --snapshot-ids
IFS=" " read -r -a snapshot_ids <<< "$ami_snapshots"
# Exit if the snapshots array is empty
if [ ${#snapshot_ids[@]} -eq 0 ]; then
    echo "Uhh ohh, this account doesn't have any snapshots or your credentials have expired!"
    exit 1
fi

### DEBUG ###
echo -e "Total Snapshots: \e[1m\e[37m$all_snapshots_total\e[0m"
echo -e "AMI Snapshots: \e[1m\e[37m$ami_snapshots_total\e[0m"

# FIXME: Split the list of snapshots into chunks of 1000 to avoid `InvalidSnapshot.NotFound` errors?
# If `MaxResults` parameter is not used, then the request returns all snapshots.
# https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSnapshots.html
if [ $ami_snapshots_total -le 1000 ]; then
    volume_sizes=$(aws ec2 describe-snapshots --owner-ids "${ACCOUNT_ID}" --snapshot-ids ${snapshot_ids[@]} --query 'Snapshots[].VolumeSize' --output text)
    for volume_size in ${volume_sizes[@]}; do ((volume_total_size+=$volume_size)); done
    process_chunk ${snapshot_ids[@]}
else
    # Initialize an array to store chunks
    chunks=()
    let chunks_size=0
    let chunks_batch=1
    for snapshot_id in "${snapshot_ids[@]}"; do
        chunks+=("$snapshot_id")
        chunks_size=$((chunks_size + 1))
        echo $snapshot_id
        # If the chunk size reaches 1000, process the chunk
        if [ "${chunks_size}" -eq 1000 ]; then
            echo "Processing batch #${chunks_batch}..."
            volume_sizes=$(aws ec2 describe-snapshots --owner-ids "${ACCOUNT_ID}" --snapshot-ids "${chunks[@]}" --query 'Snapshots[].VolumeSize' --output text)
            for volume_size in ${volume_sizes[@]}; do ((volume_total_size+=$volume_size)); done
            process_chunk ${chunks[@]}

            # Clear the chunk and reset the size
            chunks=()
            chunks_size=0
            chunks_batch=$((chunks_batch + 1))
        fi
    done
fi

# volume_total_size = The sum (in GB) of all volumes
# snapshot_total_bytes = The sum (in bytes) of all snapshots
# snapshot_total_size = The sum (in GB) of all snapshots
snapshot_total_size=$((snapshot_total_bytes / 1024 / 1024 / 1024))

# Calculate the monthly and annual costs for snapshots
# We have to do a lot of massaging to get bash to deal with floats... use python instead!
aws_standard_monthly=$(awk -v snapshot_total_size="$snapshot_total_size" 'BEGIN{aws_standard_monthly=snapshot_total_size * 0.05; printf "%0.02f",aws_standard_monthly}')
aws_standard_annual=$(awk -v aws_standard_monthly="$aws_standard_monthly" 'BEGIN{aws_standard_annual=aws_standard_monthly * 12; printf "%0.02f",aws_standard_annual}')
aws_archive_monthly=$(awk -v snapshot_total_size="$snapshot_total_size" 'BEGIN{aws_archive_monthly=snapshot_total_size * 0.0125; printf "%0.02f",aws_archive_monthly}')
aws_archive_annual=$(awk -v aws_archive_monthly="$aws_archive_monthly" 'BEGIN{aws_archive_annual=aws_archive_monthly * 12; printf "%0.02f",aws_archive_annual}')
aws_savings=$(echo "$aws_standard_annual $aws_archive_annual" | awk '{print $1 - $2}')

# Print the report
echo "================================================"
echo "Total size of volumes: $(printf "%'d\n" $volume_total_size) GB"
echo -e "\e[1mTotal size of snapshots: \e[37m$(printf "%'d\n" $snapshot_total_size) GB\e[0m"

echo "================================================"
echo -e "Standard tier monthly cost for snapshots: \e[33m$(printf "$%'.2f" $aws_standard_monthly)\e[0m"
echo -e "Standard tier annual cost for snapshots: \e[33m$(printf "$%'.2f" $aws_standard_annual)\e[0m"
echo -e "\e[1mArchive tier monthly cost for snapshots: \e[32m$(printf "$%'.2f" $aws_archive_monthly)\e[0m"
echo -e "\e[1mArchive tier annual cost for snapshots: \e[32m$(printf "$%'.2f" $aws_archive_annual)\e[0m"
echo "================================================"
echo -e "\e[1mAnnual savings per environment: \e[32m$(printf "$%'.2f" $aws_savings)\e[0m"

# TODO: Port to python
# TODO: Depemdency checker for awscli, flexible-snapshot-proxy, locales-all (so we get pretty numbers)
# TODO: Handle volume_total_size as bytes shown in GB, TB and/or PB
# TODO: Adjust to only calculate X of Y snapshots to convert to archive tier. ie: AMIs snapshots older than 90 days or latest 5 AMI snapshots?
# TODO: usage()
# TODO: Extra reporting for # of snapshots, # of AMIs, all snapshots (using flexible-snapshot-proxy)
# TODO: add arg from aws profile

### Scratchpad ###
# aws ec2 describe-snapshots --filters "Name=owner-id,Values=${ACCOUNT_ID}"
# aws ec2 describe-snapshots --filters "Name=owner-id,Values=${ACCOUNT_ID}" --query 'Snapshots[].[SnapshotId,VolumeSize]' --output text