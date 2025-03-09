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
# set -x
# Declare globals
declare -r ASSUME_ROLE_NAME=SERVADMIN
declare -A HAYSTACK
declare -i TOTAL_COUNT TOTAL_SIZE TOTAL_COST
declare hasResults=false

# Magic Spells
CURSOR_OFF='\e[?25l'
CURSOR_ON='\e[?25h'
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
NC='\e[0m'

# isAuthenticated Checks to see if valid AWS credentials are available
function isAuthenticated {
    aws sts get-caller-identity > /dev/null 2>&1 && echo true || echo false
}

# hasCluster Checks to see if K8S cluster is available
function hasCluster {
    kubectl cluster-info > /dev/null 2>&1 && echo true || echo false
}

# hasKubeconfig Checks to see if kubectl is configured
function hasKubeconfig {
    kubectl config view > /dev/null 2>&1 && echo true || echo false
}

# hasSSHConnection Checks to see if there is an SSH connnection ESTABLISHED
function hasSSHConnection {
    if [ ! -x "$(command -v netstat 2>/dev/null)" ]; then
        # Retrieve `/etc/os-release` information for OS using `source`
        [[ -f /etc/os-release ]] && source /etc/os-release
        if [ "${ID_LIKE}" == "fedora" ]; then
            yum install -yq net-tools
        elif [ "${ID_LIKE}" == "debian" ]; then
            apt install -yqqq netstat-nat
        else
            echo "Uhh ohh, netstat is broken! Exiting!!"
            exit 1
        fi
    fi
    local LOCAL_ADDRESS=$(ip addr | awk '/inet / {print $2}' | grep '^10\.' | cut -d'/' -f1 | tail -n 1)
    local NETSTAT=$(netstat -tnp4 | grep $LOCAL_ADDRESS)
    local PROTO=$(awk '{ print $1 }' <<< $NETSTAT)
    local SSH_SERVER_ADDRESS=$(awk '{ print $5 }' <<< $NETSTAT | cut -d ":" -f1)
    local SSH_SERVER_PORT=$(awk '{ print $5 }' <<< $NETSTAT | cut -d ":" -f2)
    local STATUS=$(awk '{ print $6 }' <<< $NETSTAT)
    local PROCESS=$(awk '{ print $7 }' <<< $NETSTAT)
    [[ ! -n $NETSTAT ]] && { echo false; exit 1; }
    local SSH_SERVER_FQDN=$(getent hosts $SSH_SERVER_ADDRESS | tr -s ' ' | cut -d " " -f2) 
    echo "SSH connection ${STATUS} to ${SSH_SERVER_ADDRESS} (${SSH_SERVER_FQDN}) on ${PROTO}/${SSH_SERVER_PORT}" > /dev/null 2>&1
    echo true
}

# hasSSHTunnel Checks to see if there is an SSH connnection LISTENing
# TODO: Is there a way to correlate the listening and established connections to make sure we have the correct tunnel?
function hasSSHTunnel {
    local NETSTAT=$(netstat -tlnp4 | grep -E '.*ssh\s*$')
    local PROTO=$(awk '{ print $1 }' <<< $NETSTAT)
    local SSH_TUNNEL_ADDRESS=$(awk '{ print $4 }' <<< $NETSTAT | cut -d ":" -f1)
    local SSH_TUNNEL_PORT=$(awk '{ print $4 }' <<< $NETSTAT | cut -d ":" -f2)
    local STATUS=$(awk '{ print $6 }' <<< $NETSTAT)
    local PROCESS=$(awk '{ print $7 }' <<< $NETSTAT)
    [[ ! -n $NETSTAT ]] && { echo false; exit 1; }
    echo "SSH connection ${STATUS} to ${SSH_SERVER_ADDRESS} on ${PROTO}/${SSH_SERVER_PORT}" > /dev/null 2>&1
    echo true
}

# hasVPNConnection Checks to see if there is connectivity to the ingress point (should work w/ or w/o a VPN connection)
function hasVPNConnection {
    local HOST_NAME=${1:-'ingress-live-black-aec2dda42feecce6.elb.us-gov-west-1.amazonaws.com'}
    local HOST_PORT=${2:-'22'}
    timeout 0.5s bash -c "echo -n 2>/dev/null < /dev/tcp/${HOST_NAME}/${HOST_PORT}" && echo true || echo false
}

# Cause why not!?!
spinner() {
    [[ $hasResults == true ]] && return
	i=$1
	sp="◐◓◑◒"
    # NOTE: https://unix.stackexchange.com/questions/225179/display-spinner-while-waiting-for-some-process-to-finish
	printf "\b${sp:i++%${#sp}:1}"
    # sleep 0.1
}

# fetchPods Gets the list of namespaces and pod names
function fetchPods {
    printf $CURSOR_OFF
    CLUSTER_ARN=$(kubectl config current-context)
    CLUSTER_NAME=$(sed -E 's#.*\W(\w*)#\1#' <<< "${CLUSTER_ARN}")
    echo -e "Fetching pods from: ${BLUE}${CLUSTER_NAME} (${CLUSTER_ARN})${NC}..."

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
                echo -e "Invalid: ${RED}$AWS_ACCOUNT${NC}, Namespace: $NAMESPACE, Pod: $POD"
                continue
            # Check for duplicates
            elif [[ -n "${HAYSTACK[$AWS_ACCOUNT]}" ]]; then
                echo -e "Duplicate: ${YELLOW}$AWS_ACCOUNT${NC}, Namespace: $NAMESPACE, Pod: $POD"
                continue
            fi

            # Store valid accounts (and add a new line from the spinner!)
            [[ $hasResults == false ]] && { hasResults=true; echo ""; }
            HAYSTACK["$AWS_ACCOUNT"]="$POD"
            echo -e "Added: ${GREEN}$AWS_ACCOUNT${NC}, Namespace: $NAMESPACE, Pod: $POD"
        fi
    # NOTE: Don't use piping or subshells with while loop
    done < <(kubectl get pods -A --no-headers -o custom-columns="Namespace:metadata.namespace,Pod:metadata.name")
    printf "%*s\n" "$COLUMNS" "" | tr " " "="
    echo -e "${#HAYSTACK[@]} AWS Accounts found: [${!HAYSTACK[@]}]"
    printf "%*s\n" "$COLUMNS" "" | tr " " "="
    printf $CURSOR_ON
}

# fetchEbsVolumes gets the EBS volume data for the account
function fetchEbsVolumes {
    local ACCOUNT=$1
    # Fetch unused EBS Volumes in JSON format
    json_data=$(aws ec2 describe-volumes --query 'sort_by(Volumes[?State==`available`],&CreateTime)[].[VolumeId,State,VolumeType,AvailabilityZone,CreateTime,Size]' --output json)
    # json_data=$(aws ec2 describe-volumes --filters "Name=status,Values=available" --query 'sort_by(Volumes[?!not_null(Tags[?Key==`ebs.csi.aws.com/cluster`].Value)],&CreateTime)[].[VolumeId,State,VolumeType,AvailabilityZone,CreateTime,Size]' --output json)

    # Check if JSON data is empty
    if [[ -z "$json_data" || "$json_data" == "[]" ]]; then
        echo "No available volumes found or failed to retrieve data."
        return
    fi

    # Get the count of volumes
    count=$(jq 'length' <<< "$json_data")

    # Print table headers
    echo -e "Volume ID\tState\t\tType\t\tAvailability Zone\tCreate Time\t\tSize (GB)"
    echo "-----------------------------------------------------------------------------------------------"

    # Initialize total size
    let account_size=0
    let account_cost=0

    # Parse JSON and format output
    while IFS=$'\t' read -r volume_id state volume_type az create_time size; do
        printf "%-12s %-12s %-12s %-20s %-20s %-8s\n" "$volume_id" "$state" "$volume_type" "$az" "$create_time" "$size"
        ((account_size += size))
    done < <(echo "$json_data" | jq -r '.[] | @tsv')

    # Print summation row
    account_cost=$(awk 'BEGIN { print int(ARGV[1] * 0.1) }' "$account_size")
    TOTAL_COUNT+=$count
    TOTAL_SIZE+=$account_size
    TOTAL_COST+=$account_cost
    echo "-----------------------------------------------------------------------------------------------"
    printf "Sub-total: %-8s volumes\t\t\t\t\t\t %d GB\t\tCost: \$%d/month\n" "$count" "$account_size" "$account_cost"
}

function main {
    [[ $(isAuthenticated) == true ]] && echo -e "${GREEN}AWS credentials found!${NC}" || { echo -e "${RED}No valid AWS credentials!${NC} (Check ~/.aws/credentials)"; exit 1; }
    [[ $(hasKubeconfig) == true ]] && echo -e "${GREEN}Kubeconfig found!${NC}" || { echo -e "${RED}Kubeconfig Failed!${NC} Check ~/.kube/config"; exit 1; }
    [[ $(hasVPNConnection) == true ]] && echo -e "${GREEN}VPN connection established! (or bypassed)${NC}" || { echo -e "${RED}No VPN connection detected!${NC}"; }
    [[ $(hasSSHConnection) == true ]] && echo -e "${GREEN}SSH Jumbbox connection established!${NC}" || { echo -e "${RED}No SSH Jumbox detected!${NC}"; exit 1; }
    [[ $(hasSSHTunnel) == true ]] && echo -e "${GREEN}SSH Tunnel found!${NC}" || { echo -e "${RED}No tunnel detected!${NC}"; }
    [[ $(hasCluster) == true ]] && echo -e "${GREEN}Connected!${NC}" || { echo -e "${RED}Failed!${NC}\nCheck ~/.kube/config"; exit 1; }

    fetchPods

    for NEEDLE in "${!HAYSTACK[@]}"; do
        echo -n "Assuming ${ASSUME_ROLE_NAME} for AWS Account: ${NEEDLE}... "
        
        CREDENTIALS=$(aws sts assume-role \
            --role-arn "arn:aws-us-gov:iam::$NEEDLE:role/$ASSUME_ROLE_NAME" \
            --role-session-name "VOL_CHECKUP" 2>/dev/null)
        
        if [[ -z "$CREDENTIALS" ]]; then
            # echo -e "${RED}Failed to assume role for account $NEEDLE${NC}"
            echo -e "${RED}Failed!${NC}"
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
        echo -e "${GREEN}Success${NC}, Account Alias: ${ACCOUNT_ALIAS}"
        
        fetchEbsVolumes "$NEEDLE"
        
        # Clear AWS credentials to avoid contamination
        unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
    done

    printf "%*s\n" "$COLUMNS" "" | tr " " "="
    # TOTAL_COST=$(awk 'BEGIN { print int(ARGV[1] * 0.1) }' "$TOTAL_SIZE")
    printf "Number of Accounts: %d\t\t\t Number of EBS Volumes: %d \t\t\t Total Size: %d GB \t\t\t Total Cost: \$%d/month\n" "${#HAYSTACK[@]}" "$TOTAL_COUNT" "$TOTAL_SIZE" "$TOTAL_COST"
}

# Entry Point
main
