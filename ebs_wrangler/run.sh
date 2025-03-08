#!/usr/bin/env bash
# Script Name: EBS Wrangler
#
# Author: bucs-fan813@users.noreply.github.com
# Date : 03/06/2025
#
# Description: Find unattached EBS volumes across multiple accounts
#               
#
# Run Information: ./ebs_wrangler/run.sh

# Declare globals
declare -r ASSUME_ROLE_NAME=SERVADMIN
declare -A HAYSTACK
declare -i TOTAL_COUNT TOTAL_SIZE TOTAL_COST
declare hasResults=false

# isAuthenticated Checks to see if valid AWS credentials are available
function isAuthenticated {
    aws sts get-caller-identity > /dev/null 2>&1 && echo true || echo false
}

# hasCluster Checks to see if kubectl is configured for a cluster
function hasCluster {
    kubectl cluster-info > /dev/null 2>&1 && echo true || echo false
}

spinner() {
    [[ $hasResults == true ]] && return
	i=$1
	sp="-\|/"
    # NOTE: https://unix.stackexchange.com/questions/225179/display-spinner-while-waiting-for-some-process-to-finish
	printf "\b${sp:i++%${#sp}:1}"
    # sleep 0.1
}

# fetchPods Gets the list of namespaces and pod names
function fetchPods {
    printf '\e[?25l'
    CLUSTER_ARN=$(kubectl config current-context)
    CLUSTER_NAME=$(sed -E 's#.*\W(\w*)#\1#' <<< "${CLUSTER_ARN}")
    echo -e "Fetching pods from: \e[34m${CLUSTER_NAME} (${CLUSTER_ARN})\e[0m..."

    let i=0
    # Get the list of namespaces and pod names
    while read -r NAMESPACE POD; do
        # Ensure both namespace and pod values are non-empty
        if [[ -n "$NAMESPACE" && -n "$POD" ]]; then
            # Retrieve environment variables from the pod
            ENVS=$(kubectl exec -n "$NAMESPACE" "$POD" -- printenv 2>/dev/null)

            # Check if `printenv` succeeded
            if [[ -z "$ENVS" ]]; then
                # echo "Skipping pod $POD in namespace $NAMESPACE (failed to retrieve env vars)"
                spinner $i
                continue
            fi
            # Extract ACCOUNT from either `ACCOUNT` or `AWS_ROLE_ARN`
            AWS_ACCOUNT=$(echo "$ENVS" | grep -E '^ACCOUNT=' | cut -d= -f2)

            if [[ -z "$AWS_ACCOUNT" ]]; then
                AWS_ROLE_ARN=$(echo "$ENVS" | grep -E '^AWS_ROLE_ARN=' | cut -d= -f2)
                if [[ -n "$AWS_ROLE_ARN" ]]; then
                    AWS_ACCOUNT=$(echo "$AWS_ROLE_ARN" | sed -E 's/.*:([0-9]{12}):.*/\1/')
                else
                    spinner $i
                    continue
                fi
            fi

            # Validate ACCOUNT format
            if ! [[ "$AWS_ACCOUNT" =~ ^[0-9]{12}$ ]]; then
                echo -e "Invalid: \e[31m$AWS_ACCOUNT\e[0m, Namespace: $NAMESPACE, Pod: $POD"
                continue
            # Check for duplicates
            elif [[ -n "${HAYSTACK[$AWS_ACCOUNT]}" ]]; then
                echo -e "Duplicate: \e[33m$AWS_ACCOUNT\e[0m, Namespace: $NAMESPACE, Pod: $POD"
                continue
            fi

            # Store valid accounts (and add a new line from the spinner!)
            [[ $hasResults == false ]] && { hasResults=true; echo ""; }
            HAYSTACK["$AWS_ACCOUNT"]="$POD"
            echo -e "Added: \e[32m$AWS_ACCOUNT\e[0m, Namespace: $NAMESPACE, Pod: $POD"
        fi
    # NOTE: Don't use piping or subshells with while loop
    done < <(kubectl get pods -A --no-headers -o custom-columns="Namespace:metadata.namespace,Pod:metadata.name")
    printf "%*s\n" "$COLUMNS" "" | tr " " "="
    echo -e "${#HAYSTACK[@]} AWS Accounts found: [${!HAYSTACK[@]}]"
    printf "%*s\n" "$COLUMNS" "" | tr " " "="
    printf '\e[?25h'
}

# fetchEbsVolumes gets the EBS volume data for the account
function fetchEbsVolumes {
    local ACCOUNT=$1
    # Fetch unused EBS Volumes in JSON format
    # json_data=$(aws ec2 describe-volumes --query 'sort_by(Volumes[?State==`available`],&CreateTime)[].[VolumeId,State,VolumeType,AvailabilityZone,CreateTime,Size]' --output json)
    json_data=$(aws ec2 describe-volumes --filters "Name=status,Values=available" --query 'sort_by(Volumes[?!not_null(Tags[?Key==`ebs.csi.aws.com/cluster`].Value)],&CreateTime)[].[VolumeId,State,VolumeType,AvailabilityZone,CreateTime,Size]' --output json)

    # Check if JSON data is empty
    if [[ -z "$json_data" || "$json_data" == "[]" ]]; then
        echo "No available volumes found or failed to retrieve data."
        return
    fi

    # Get the count of volumes
    count=$(echo "$json_data" | jq 'length')

    # Print table headers
    echo -e "Volume ID\tState\t\tType\t\tAvailability Zone\tCreate Time\t\tSize (GB)"
    echo "-----------------------------------------------------------------------------------------------"

    # Initialize total size
    let total_size=0

    # Parse JSON and format output
    while IFS=$'\t' read -r volume_id state volume_type az create_time size; do
        printf "%-12s %-12s %-12s %-20s %-20s %-8s\n" "$volume_id" "$state" "$volume_type" "$az" "$create_time" "$size"
        ((total_size += size))
    done < <(echo "$json_data" | jq -r '.[] | @tsv')

    # Print summation row
    TOTAL_COUNT+=$count
    TOTAL_SIZE+=$total_size
    cost=$(awk "BEGIN {print $total_size * 0.1"})
    TOTAL_COST+=$cost
    echo "-----------------------------------------------------------------------------------------------"
    printf "Sub-total: %-8s volumes\t\t\t\t\t\t %d GB\t\tCost: \$%d/month\n" "$count" "$total_size" "$cost"
}

function main {
    [[ $(isAuthenticated) == true ]] && echo -en "\e[32mCredentials found!\e[0m Connecting to cluster..." || { echo -e "\e[31mNo valid credentials!\e[0m"; exit 1; }
    [[ $(hasCluster) == true ]] && echo -e "\e[32mConnected!\e[0m" || { echo -e "\e[31mFailed!\e[0m"; exit 1; }

    fetchPods

    for NEEDLE in "${!HAYSTACK[@]}"; do
        echo -n "Assuming ${ASSUME_ROLE_NAME} for AWS Account: ${NEEDLE}... "
        
        CREDENTIALS=$(aws sts assume-role \
            --role-arn "arn:aws-us-gov:iam::$NEEDLE:role/$ASSUME_ROLE_NAME" \
            --role-session-name "VOL_CHECKUP" 2>/dev/null)
        
        if [[ -z "$CREDENTIALS" ]]; then
            # echo -e "\e[31mFailed to assume role for account $NEEDLE\e[0m"
            echo -e "\e[31mFailed!\e[0m"
            unset HAYSTACK["$NEEDLE"]
            continue
        fi
        
        export AWS_ACCESS_KEY_ID=$(echo "$CREDENTIALS" | jq -r '.Credentials.AccessKeyId')
        export AWS_SECRET_ACCESS_KEY=$(echo "$CREDENTIALS" | jq -r '.Credentials.SecretAccessKey')
        export AWS_SESSION_TOKEN=$(echo "$CREDENTIALS" | jq -r '.Credentials.SessionToken')
        
        ACCOUNT_ALIAS=$(aws iam list-account-aliases --query 'AccountAliases[0]' --output text 2>/dev/null | awk '{print toupper($0)}')
        
        if [[ -z "$ACCOUNT_ALIAS" || "$ACCOUNT_ALIAS" == "None" ]]; then
            ACCOUNT_ALIAS="UNKNOWN"
        fi
        
        # FIXME: HAYSTACK["$NEEDLE"] will be the pod name I overwrite it. Do I need to check to see if the pod name matches the alias?
        HAYSTACK["$NEEDLE"]="$ACCOUNT_ALIAS"
        echo -e "\e[32mSuccess\e[0m, Account Alias: ${ACCOUNT_ALIAS}"
        
        fetchEbsVolumes "$NEEDLE"
        
        # Clear AWS credentials to avoid contamination
        unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
    done

    printf "%*s\n" "$COLUMNS" "" | tr " " "="
    printf "Number of Accounts: %d\t\t\t Number of EBS Volumes: %d \t\t\t Total Size: %d GB \t\t\t Total Cost: \$%d/month\n" "${#HAYSTACK[@]}" "$TOTAL_COUNT" "$TOTAL_SIZE" "$TOTAL_COST"
}

# Entry Point
main
