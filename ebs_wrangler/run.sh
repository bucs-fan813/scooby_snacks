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
declare -A HAYSTACK
declare -i TOTAL_COUNT TOTAL_SIZE TOTAL_COST
declare -r ASSUME_ROLE_NAME='SERVADMIN'
declare AWS_PARTITION
declare hasResults=false

# Magic Spells
CURSOR_OFF='\e[?25l'
CURSOR_ON='\e[?25h'
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
GRAY='\e[90m'
WHITE='\e[97m'
BOLD='\e[1m'
NC='\e[0m' # No Color
COLUMNS=${COLUMNS:-$(tput cols)}

function checkPrerequisites {
    echo -n "AWS credentials check: "
    [[ $(isAuthenticated) == true ]] && echo -e "${GREEN}Passed!${NC}" || { echo -e "${RED}Failed! ${GRAY}(Check ~/.aws/credentials)${NC} "; exit 1; }
    echo -n "Kubeconfig check: "
    [[ $(hasKubeconfig) == true ]] && echo -e "${GREEN}Passed!${NC}" || { echo -e "${RED}Failed! ${GRAY}(Check ~/.kube/config)${NC}"; exit 1; }
    echo -n "VPN Connection check: "
    [[ $(hasVPNConnection) == true ]] && echo -e "${GREEN}Passed! ${GRAY}(or skipped)${NC}" || { echo -e "${YELLOW}Skipped${NC}"; }
    echo -n "Jumpbox Connection check: "
    [[ $(hasSSHConnection) == true ]] && echo -e "${GREEN}Passed!${NC}" || { echo -e "${YELLOW}Skipped${NC}"; }
    echo -n "SSH tunnel check: "
    [[ $(hasSSHTunnel) == true ]] && echo -e "${GREEN}Passed!${NC}" || { echo -e "${YELLOW}Skipped${NC}"; }
    echo -n "kubectl commands check: "
    [[ $(hasCluster) == true ]] && echo -e "${GREEN}Passed!${NC}" || { echo -e "${RED}Houston we have a problem! ${GRAY}(Are you sure your connections are setup correctly?)${NC}"; exit 1; }
}

# isAuthenticated (bool) Checks to see if valid AWS credentials are available
function isAuthenticated {
    AWS_PARTITION=$(aws sts get-caller-identity --query "Arn" --output text 2> /dev/null | cut -d':' -f2)
    [[ -n $AWS_PARTITION ]] && echo true || echo false
}

# hasCluster Checks (bool) to see if K8S cluster is available
function hasCluster {
    kubectl cluster-info > /dev/null 2>&1 && echo true || echo false
}

# hasKubeconfig (bool) Checks to see if kubectl is configured
function hasKubeconfig {
    kubectl config view > /dev/null 2>&1 && echo true || echo false
}

# hasSSHConnection (bool) Checks to see if there is an SSH connnection ESTABLISHED
function hasSSHConnection {
    # Make sure netstat is available
    if [ ! -x "$(command -v netstat 2>/dev/null)" ]; then
        # Retrieve `/etc/os-release` information for OS using `source`
        [[ -f /etc/os-release ]] && source /etc/os-release
        if [ "${ID_LIKE}" == "fedora" ]; then
            yum install -yq net-tools
        elif [ "${ID_LIKE}" == "debian" ]; then
            apt install -yqqq netstat-nat
        else
            echo "Uhh ohh, you're using a Mac arent't you!?! netsat is not available."
            exit 1
        fi
    fi

    local LOCAL_ADDRESS=$(ip addr | awk '/inet / {print $2}' | grep '^10\.' | cut -d'/' -f1 | tail -n 1)
    local NETSTAT=$(netstat -tnp4 | grep -E ".*${LOCAL_ADDRESS}.*ESTABLISHED.*ssh\s*$")
    [[ ! -n $NETSTAT ]] && { echo false; exit 1; }
    local PROTO=$(awk '{ print $1 }' <<< $NETSTAT)
    local SSH_SERVER_ADDRESS=$(awk '{ print $5 }' <<< $NETSTAT | cut -d ":" -f1)
    local SSH_SERVER_PORT=$(awk '{ print $5 }' <<< $NETSTAT | cut -d ":" -f2)
    local STATUS=$(awk '{ print $6 }' <<< $NETSTAT)
    local PROCESS=$(awk '{ print $7 }' <<< $NETSTAT)
    local SSH_SERVER_FQDN=$(getent hosts $SSH_SERVER_ADDRESS | tr -s ' ' | cut -d " " -f2) 
    # Only show for --debug
    echo "SSH connection ${STATUS} to ${SSH_SERVER_ADDRESS} (${SSH_SERVER_FQDN}) on ${PROTO}/${SSH_SERVER_PORT}" > /dev/null 2>&1
    echo true
}

# hasSSHTunnel (bool) Checks to see if there is an SSH connnection LISTENing
# TODO: Is there a way to correlate the listening and established connections to make sure we have the correct tunnel?
function hasSSHTunnel {
    local NETSTAT=$(netstat -tlnp4 | grep -E '.*ssh\s*$')
    [[ ! -n $NETSTAT ]] && { echo false; exit 1; }
    local PROTO=$(awk '{ print $1 }' <<< $NETSTAT)
    local SSH_TUNNEL_ADDRESS=$(awk '{ print $4 }' <<< $NETSTAT | cut -d ":" -f1)
    local SSH_TUNNEL_PORT=$(awk '{ print $4 }' <<< $NETSTAT | cut -d ":" -f2)
    local STATUS=$(awk '{ print $6 }' <<< $NETSTAT)
    local PROCESS=$(awk '{ print $7 }' <<< $NETSTAT)
    # Only show for --debug
    echo "SSH connection ${STATUS} to ${SSH_SERVER_ADDRESS} on ${PROTO}/${SSH_SERVER_PORT}" > /dev/null 2>&1
    echo true
}

# hasVPNConnection (bool) Checks to see if there is connectivity to the ingress point (poor man's VPN check)
function hasVPNConnection {
    local HOST_NAME=${1:-'ingress-live-black-aec2dda42feecce6.elb.us-gov-west-1.amazonaws.com'}
    local HOST_PORT=${2:-'22'}
    # /dev/tcp is a special file that allows you to establish network connections using the TCP/IP protocol
    timeout 0.5s bash -c "echo -n 2>/dev/null < /dev/tcp/${HOST_NAME}/${HOST_PORT}" && echo true || echo false
}

# fetchEbsVolumes gets the EBS volume data for the account
function fetchEbsVolumes {
    local ACCOUNT=$1 # For future use
    # Fetch unused EBS Volumes in JSON format
    local json_data=$(aws ec2 describe-volumes --query 'sort_by(Volumes[?State==`available`],&CreateTime)[].[VolumeId,State,VolumeType,AvailabilityZone,CreateTime,Size]' --output json)
    # json_data=$(aws ec2 describe-volumes --filters "Name=status,Values=available" --query 'sort_by(Volumes[?!not_null(Tags[?Key==`ebs.csi.aws.com/cluster`].Value)],&CreateTime)[].[VolumeId,State,VolumeType,AvailabilityZone,CreateTime,Size]' --output json)

    # Check if JSON data is empty
    if [[ -z "$json_data" || "$json_data" == "[]" ]]; then
        echo "No available volumes found or failed to retrieve data."
        return
    fi

    # Get the count of volumes
    local count=$(jq 'length' <<< "$json_data")

    # Initialize total cost and size
    let account_cost=0
    let account_size=0

    # Print table headers with a width of HEADER_WIDTH < DATA_WIDTH ? DATA_WIDTH : HEADER_WIDTH
    printf "%-21s\t%-9s\t%-4s\t%-17s\t%-32s\t%-9s\n" "Volume ID" "State" "Type" "Availability Zone" "Create Time" "Size (GB)"
    printf "%*s\n" "$COLUMNS" "" | tr " " "="

    # Parse JSON and print table format output
    while IFS=$'\t' read -r volume_id state volume_type az create_time size; do
        printf "%-21s\t%-9s\t%-4s\t%-17s\t%-32s\t%-9s\n" "$volume_id" "$state" "$volume_type" "$az" "$create_time" "$size"
        ((account_size += size))
    # NOTE: Don't use piping or subshells with while loop
    done < <(echo "$json_data" | jq -r '.[] | @tsv')

    # Print summation row and update globals
    account_cost=$(awk 'BEGIN { print int(ARGV[1] * 0.1) }' "$account_size")
    TOTAL_COUNT+=$count
    TOTAL_SIZE+=$account_size
    TOTAL_COST+=$account_cost

    # Print table footer
    printf "%*s\n" "$COLUMNS" "" | tr " " "="
    printf "Sub-total: %s volumes\t\t\t %d GB\t\t\tCost: \$%d/month\n" "$count" "$account_size" "$account_cost"
}

# fetchPods Gets the list of namespaces and pod names
function fetchPods {
    printf $CURSOR_OFF
    local CLUSTER_ARN=$(kubectl config current-context)
    local CLUSTER_NAME=$(sed -E 's#.*\W(\w*)#\1#' <<< "${CLUSTER_ARN}")
    echo -e "Fetching pods from: ${BLUE}${BOLD}${CLUSTER_NAME}${NC} ${GRAY}(${CLUSTER_ARN})${NC}..."

    let i=0
    # Get the list of namespaces and pod names (kubectl get pods -A --no-headers -o custom-columns="Namespace:metadata.namespace,Pod:metadata.name")
    while read -r NAMESPACE POD; do
        # Ensure both namespace and pod values are non-empty
        if [[ -n "$NAMESPACE" && -n "$POD" ]]; then
            # Retrieve environment variables from the pod
            local ENVS=$(kubectl exec -n "$NAMESPACE" "$POD" -- printenv 2>/dev/null)

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

            # Skip invalid AWS ACCOUNTs
            if ! [[ "$AWS_ACCOUNT" =~ ^[0-9]{12}$ ]]; then
                echo -e "Invalid: ${RED}$AWS_ACCOUNT${NC}, Namespace: $NAMESPACE, Pod: $POD"
                continue
            # Skip duplicates
            elif [[ -n "${HAYSTACK[$AWS_ACCOUNT]}" ]]; then
                echo -e "Duplicate: ${YELLOW}$AWS_ACCOUNT${NC}, Namespace: $NAMESPACE, Pod: $POD"
                continue
            fi

            # Store valid accounts (and don't create additional spinners)
            [[ $hasResults == false ]] && { hasResults=true; echo ""; }
            HAYSTACK["$AWS_ACCOUNT"]="$POD"
            echo -e "Added: ${GREEN}$AWS_ACCOUNT${NC}, Namespace: $NAMESPACE, Pod: $POD"
        fi
    # NOTE: Don't use piping or subshells with while loop
    done < <(kubectl get pods -A --no-headers -o custom-columns="Namespace:metadata.namespace,Pod:metadata.name")

    # Print summation row
    printf "%*s\n" "$COLUMNS" "" | tr " " "="
    echo -e "${BOLD}${WHITE}${#HAYSTACK[@]} AWS Accounts found: [${!HAYSTACK[@]}]${NC}"
    printf "%*s\n" "$COLUMNS" "" | tr " " "="
    printf $CURSOR_ON
}

# generateReport Prints the report of each AWS account in HAYSTACK
function generateReport {
    for NEEDLE in "${!HAYSTACK[@]}"; do
        echo -en "Assuming ${WHITE}${BOLD}${ASSUME_ROLE_NAME}${NC} for AWS Account: ${BLUE}${NEEDLE}... "
        
        local CREDENTIALS=$(aws sts assume-role \
            --role-arn "arn:${AWS_PARTITION}:iam::${NEEDLE}:role/${ASSUME_ROLE_NAME}" \
            --role-session-name "VOL_CHECKUP" 2>/dev/null)
        
        if [[ -z "$CREDENTIALS" ]]; then
            echo -e "${RED}Failed!${NC}"
            unset HAYSTACK["$NEEDLE"]
            continue
        fi
        
        export AWS_ACCESS_KEY_ID=$(echo "$CREDENTIALS" | jq -r '.Credentials.AccessKeyId')
        export AWS_SECRET_ACCESS_KEY=$(echo "$CREDENTIALS" | jq -r '.Credentials.SecretAccessKey')
        export AWS_SESSION_TOKEN=$(echo "$CREDENTIALS" | jq -r '.Credentials.SessionToken')
        
        local ACCOUNT_ALIAS=$(aws iam list-account-aliases --query 'AccountAliases[0]' --output text 2>/dev/null | awk '{print toupper($0)}')
        
        # Use the oringinal pod name from HAYSTACK["$NEEDLE"], if there is not an AWS account alias available
        if [[ -z "$ACCOUNT_ALIAS" || "$ACCOUNT_ALIAS" == "None" ]]; then
            ACCOUNT_ALIAS=${HAYSTACK["$NEEDLE"]}
        fi
        
        HAYSTACK["$NEEDLE"]="$ACCOUNT_ALIAS"
        echo -e "${GREEN}Success${NC}, Account Alias: ${ACCOUNT_ALIAS}"
        
        fetchEbsVolumes "$NEEDLE"
        
        # Clear AWS credentials to avoid roid-rage!
        unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
    done

    # Print table footer
    printf "%*s\n" "$COLUMNS" "" | tr " " "="
    printf "${WHITE}${BOLD}Number of Accounts:${NC} %d\t\t\t ${WHITE}${BOLD}Number of EBS Volumes:${NC} %d \t\t\t ${WHITE}${BOLD}Total Size:${NC} %d GB \t\t\t ${WHITE}${BOLD}Total Cost:${NC} \$%d/month ${GRAY}(@ \$0.10/GB)${NC}\n" "${#HAYSTACK[@]}" "$TOTAL_COUNT" "$TOTAL_SIZE" "$TOTAL_COST"
}

# Cause why not!?!
spinner() {
    [[ $hasResults == true ]] && return
	local i=$1
	local sp="◐◓◑◒"
    # NOTE: https://unix.stackexchange.com/questions/225179/display-spinner-while-waiting-for-some-process-to-finish
	printf "\b${sp:i++%${#sp}:1}"
    # sleep 0.1
}

function main {
    checkPrerequisites
    fetchPods
    generateReport
}

# usage Displays help
function usage {
TAB=$'\t'
# ${t} works too?
cat << EOF
Usage: $0 [options]
EBS Wrangler features:
	o Checks all pre-requesites are satisfied to run $0
	o Gathers K8S Pods that contain AWS account info for management and tenants
	o Gathers and reports unattached EBS volume data and costs

	MANDATORY PARAMETERS
	None.

	OPTIONS
${TAB} -h|--help ${TAB} Display usage help.
${TAB} -d|--debug ${TAB} Display debugging info
EOF
}

# Entry Point
GETOPT=`getopt -n $0 -o ,h,d \
    -l help,debug`
#eval set -- "$GETOPT"
while true;
do
    case "$1" in
    "")
        # Default
        break
        ;;
    -h|--help)
        usage
        exit 1
        ;;
    -d|--debug)
        set -x
        break
        ;;
    *)
		echo "Unrecognized option(s)... continuing with defaults"
        break
		;;
    esac
done
main
