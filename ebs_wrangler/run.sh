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
declare -A HAYSTACK                                 # Associative array (dictionary)
declare -a ALL_EBS_VOL_IDS ACCOUNT_EBS_VOL_IDS      # Indexed array
declare -i TOTAL_COUNT TOTAL_SIZE TOTAL_COST        # Integers
declare -r ASSUME_ROLE_NAME='SERVADMIN'             # Read-only
declare HAS_RESULTS=false                           # Boolean
declare DELETE_VOLS=false                           # Boolean
declare CREATE_SNAPSHOTS=true                       # Boolean
declare INCLUDE_TENANTS=false                       # Boolean
declare GET_ALL_UNATTACHED=false                    # Boolean

# Future use
declare EXCLUDE_NAMESPACES                          # String (comma separated)
declare INGRESS_ENDPOINT                            # String
# declare -r REGION=$(aws configure list | grep region | awk '{print $2}')

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

# checkPrerequisites Checks credentials and connectivity to K8S cluster
function checkPrerequisites {
    echo -n "Root context check: "
    [[ $(isRoot) == true ]] && echo -e "${GREEN}Passed!${NC}" || { echo -e "${RED}Failed! ${GRAY}(Please use \"sudo\" or run as root)${NC} "; exit 1; }
    echo -n "AWS credentials check: "
    [[ $(isAuthenticated) == true ]] && echo -e "${GREEN}Passed!${NC}" || { echo -e "${RED}Failed! ${GRAY}(Check ~/.aws/credentials or ENVs)${NC} "; exit 1; }
    echo -n "Kubeconfig check: "
    [[ $(hasKubeconfig) == true ]] && echo -e "${GREEN}Passed!${NC}" || { echo -e "${RED}Failed! ${GRAY}(Check ~/.kube/config)${NC}"; exit 1; }
    echo -n "VPN Connection check: "
    [[ $(hasVPNConnection $INGRESS_ENDPOINT) == true ]] && echo -e "${GREEN}Passed! ${GRAY}(or skipped)${NC}" || echo -e "${YELLOW}Skipped${NC}"
    echo -n "Jumpbox Connection check: "
    [[ $(hasSSHConnection) == true ]] && echo -e "${GREEN}Passed!${NC}" || echo -e "${YELLOW}Skipped${NC}"
    echo -n "SSH tunnel check: "
    [[ $(hasSSHTunnel) == true ]] && echo -e "${GREEN}Passed!${NC}" || echo -e "${YELLOW}Skipped${NC}"
    echo -n "Data Lifecycle Manager Check: "
    [[ $(hasDLMPolicy) == true ]] && echo -e "${GREEN}Passed!${NC}" || echo -e "${YELLOW}DLM is not available with the current credentials ${GRAY}(See: https://docs.aws.amazon.com/cli/latest/reference/dlm/)${NC}"
    echo -n "kubectl commands check: "
    [[ $(hasCluster) == true ]] && echo -e "${GREEN}Passed!${NC}" || { echo -e "${RED}Houston we have a problem! ${GRAY}(Are you sure your connections and AWS credentials are setup correctly?)${NC}"; exit 1; }
}

# isRoot Check for sudo or root context
function isRoot {
    [[ "$EUID" -eq 0 ]]	&& echo true || echo false
}

# isAuthenticated (bool) Checks to see if valid AWS credentials are available
function isAuthenticated {
    aws sts get-caller-identity > /dev/null 2>&1 && echo true || echo false
}

# excludeNamespaces Formats a comma separated string of values. EXCLUDE_NAMESPACES will contain the values to exclude from kubectl --field-selector
function excludeNamespaces {
    local input=$1
    [[ -n $input ]] || { echo -e "${RED}At least one namespace must be provided when using -e|--exclude${NC}"; exit 1; }
    # Prepend metadata.namespace!= to each item in the list
    EXCLUDE_NAMESPACES=$(sed 's/,/ metadata.namespace!=/g' <<< "$input" | sed 's/^/metadata.namespace!=/')
}

# hasCluster Checks (bool) to see if K8S cluster is available
function hasCluster {
    kubectl cluster-info > /dev/null 2>&1 && echo true || echo false
}

# hasDLMPolicy Checks (bool) to see if DLM is available
function hasDLMPolicy {
    aws dlm get-lifecycle-policies > /dev/null 2>&1 && echo true || echo false
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
            echo "Uhh ohh, netsat is not available! Are you using a Mac!?! "
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
    # Only show when --debug is used
    (>/dev/null echo "SSH connection ${STATUS} to ${SSH_SERVER_ADDRESS} (${SSH_SERVER_FQDN}) on ${PROTO}/${SSH_SERVER_PORT}")
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
    # Only show when --debug is used
    (>/dev/null echo "SSH connection ${STATUS} to ${SSH_SERVER_ADDRESS} on ${PROTO}/${SSH_SERVER_PORT}")
    echo true
}

# hasVPNConnection (bool) Checks to see if there is connectivity to the ingress point (poor man's VPN check)
function hasVPNConnection {
    local HOST_NAME=${1:-'ingress-live-black-aec2dda42feecce6.elb.us-gov-west-1.amazonaws.com'}
    local HOST_PORT=${2:-'22'}
    # /dev/tcp is a special (POSIX compliant) file that allows you to establish network connections using the TCP/IP protocol
    timeout 0.5s bash -c "echo -n 2>/dev/null < /dev/tcp/${HOST_NAME}/${HOST_PORT}" && echo true || echo false
}

# createDLMPolicy Deletes EBS volumes discovered by fetchEbsVolumes
function createDLMPolicy {
    # Check if DLM Policy for EBS Wrangler already exists
    if aws dlm get-lifecycle-policies --query 'Policies[?Tags.CreatedBy==`EBS Wrangler`].[PolicyId]' > /dev/null 2>&1 ; then
        return 0
    fi

    local ACCOUNT=$1
    local AWS_PARTITION=$(aws sts get-caller-identity --query "Arn" --output text 2> /dev/null | cut -d':' -f2)
    
    # https://cloud.google.com/scheduler/docs/configuring/cron-job-schedules#sample_schedules
    aws dlm create-lifecycle-policy --execution-role-arn "arn:${AWS_PARTITION}:iam::${ACCOUNT}:role/${ASSUME_ROLE_NAME}" \
    --description "EBS Wrangler - Move snapshots to archive after 90 days and delete after 1 year" \
    --state ENABLED \
    --tags "CreatedBy=EBS Wrangler" \
    --policy-details '{
    "PolicyType": "EBS_SNAPSHOT_MANAGEMENT",
    "ResourceTypes": ["VOLUME"],
    "TargetTags": [{"Key": "CreatedBy", "Value": "EBS Wrangler"}],
    "Schedules": [{
        "Name": "EBS Wrangler",
        "CopyTags": true,
        "TagsToAdd": [{"Key":"ManagedBy","Value":"dlm"}],
        "CreateRule": {
            "CronExpression": "cron(0 0 1 1,4,7,10 ? *)"
        },
        "RetainRule": {"Interval": 90, "IntervalUnit": "DAYS"},
        "ArchiveRule": {
            "RetainRule":{ 
                "RetentionArchiveTier": {"Interval": 5, "IntervalUnit": "YEARS"}
            }
        }
    }]}'
}

# createSnapshot Deletes EBS volumes discovered by fetchEbsVolumes
function createSnapshot {
    [[ -z $1 ]] && { echo -e "${RED}Missing EBS Volume ID!${NC} "; exit 1; }
    local VOLUME=$1
    
    aws ec2 create-snapshot --dry-run \
    --volume-id "${VOLUME}" \
    --description "Created by EBS Wrangler for ${VOLUME}" \
    --tag-specifications 'ResourceType=snapshot,Tags=[{Key=CreatedBy,Value=EBS Wrangler},{Key=JIRA,Value=NGICAWS-32204}]'
}

# deleteEbsVolumes Deletes EBS volumes discovered by fetchEbsVolumes
function deleteEbsVolumes {
    for VOLUME in "${ACCOUNT_EBS_VOL_IDS[@]}"; do
        # Create snapshots before deleting (default)
        [[ $CREATE_SNAPSHOTS == true ]] && createSnapshot "${VOLUME}"
        
        # Get Persistent Volumes and their volumeHandle (EBS Volume IDs)
        PV=$(kubectl get pv -A --no-headers -o custom-columns="PersistentVolume:metadata.name,PersistentVolume:spec.csi.volumeHandle" | grep ${VOLUME})

        # Check to see if the cluster is aware of the EBS volume and delete by changing the K8S ReclaimPolicy.
        if [[ -n ${PV} ]]; then
            PV_NAME=$(awk '{ print $1 }' <<< $PV)
            # PV_VOL_HANDLE=$(awk '{ print $2 }' <<< $PV) # future use
            kubectl patch pv ${PV_NAME} -p '{"spec":{"persistentVolumeReclaimPolicy":"Delete"}}'
        else
            # Only use the  or AWS CLI if the K8S cluster is unaware of the volume
            aws ec2 delete-volume --volume-id $VOLUME 2>/dev/null
        fi
    done
}

# fetchEbsVolumes gets the EBS volume data for the account
function fetchEbsVolumes {
    local ACCOUNT=$1
    ACCOUNT_EBS_VOL_IDS=() # Reset array for each account
    local json_data
    if [ "$GET_ALL_UNATTACHED" == true ]; then
        # Query all unattached volumes 
        json_data=$(aws ec2 describe-volumes --query "sort_by(Volumes[?State=='available'], &CreateTime)[].[VolumeId, State, VolumeType, AvailabilityZone, CreateTime, Size]" --output json)
    else
        # Query unattached volumes older than 1 year
        json_data=$(aws ec2 describe-volumes --query "sort_by(Volumes[?State=='available' && CreateTime<=\`$(date -u -d '1 year ago' +%Y-%m-%dT%H:%M:%SZ)\`], &CreateTime)[].[VolumeId, State, VolumeType, AvailabilityZone, CreateTime, Size]" --output json)
    fi
    # 3) Query unattached volumes with `ebs.csi.aws.com/cluster` tag
    # local json_data=$(aws ec2 describe-volumes --filters "Name=status,Values=available" --query 'sort_by(Volumes[?!not_null(Tags[?Key==`ebs.csi.aws.com/cluster`].Value)],&CreateTime)[].[VolumeId,State,VolumeType,AvailabilityZone,CreateTime,Size]' --output json)

    # Check if JSON data is empty
    if [[ -z "$json_data" || "$json_data" == "[]" ]]; then
        echo -e "${RED}No available volumes found or failed to retrieve data.${NC}"
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
        ACCOUNT_EBS_VOL_IDS+=($volume_id)
        ALL_EBS_VOL_IDS+=($volume_id)
    # NOTE: Don't use piping or subshells with while loop
    done < <(jq -r '.[] | @tsv' <<< "$json_data")

    # Print summation row and update globals
    account_cost=$(awk 'BEGIN { print int(ARGV[1] * 0.1) }' "$account_size")
    TOTAL_COUNT+=$count
    TOTAL_SIZE+=$account_size
    TOTAL_COST+=$account_cost

    # Print table footer
    printf "%*s\n" "$COLUMNS" "" | tr " " "="
    printf "${WHITE}${BOLD}Account# %s Sub-total:\t\tUnattached EBS Volumes:${NC} %s\t\t\t\t${WHITE}${BOLD}Size:${NC} %d GB\t\t\t\t${WHITE}${BOLD}Cost:${NC} \$%d/month ${GRAY}(@ \$0.10/GB)${NC}\n" "$ACCOUNT" "$count" "$account_size" "$account_cost"
}

# fetchPods Gets the list of namespaces and pod names
function fetchPods {
    local CLUSTER_ARN=$(kubectl config current-context)
    local CLUSTER_NAME=$(sed -E 's#.*\W(\w*)#\1#' <<< "${CLUSTER_ARN}")
    let i=0
    
    printf $CURSOR_OFF
    echo -en "Fetching pods from: ${BLUE}${BOLD}${CLUSTER_NAME}${NC} ${GRAY}(${CLUSTER_ARN})${NC}... "

    [[ $INCLUDE_TENANTS == false ]] && { excludeNamespaces 'tenants'; echo -e "${YELLOW}Excluding tenants!${NC}"; } || echo -e "${BLUE}Including tenants!${NC}"
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

            # Extract AWS ACCOUNT from either `ENVS[ACCOUNT]` or `ENVS[AWS_ROLE_ARN]`
            AWS_ACCOUNT=$(grep -E '^ACCOUNT=' <<< "$ENVS" | cut -d= -f2)
            if [[ -z "$AWS_ACCOUNT" ]]; then
                AWS_ROLE_ARN=$(grep -E '^AWS_ROLE_ARN=' <<< "$ENVS" | cut -d= -f2)
                if [[ -n "$AWS_ROLE_ARN" ]]; then
                    AWS_ACCOUNT=$(sed -E 's/.*:([0-9]{12}):.*/\1/' <<< "$AWS_ROLE_ARN")
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
            [[ $HAS_RESULTS == false ]] && { HAS_RESULTS=true; echo ""; }
            HAYSTACK["$AWS_ACCOUNT"]="$POD"
            echo -e "Added: ${GREEN}$AWS_ACCOUNT${NC}, Namespace: $NAMESPACE, Pod: $POD"
        fi
    # NOTE: Don't use piping or subshells with while loop
    done < <(kubectl get pods -A --no-headers --field-selector="${EXCLUDE_NAMESPACES}" -o custom-columns="Namespace:metadata.namespace,Pod:metadata.name")

    # Print summation row
    printf "%*s\n" "$COLUMNS" "" | tr " " "="
    echo -e "${BOLD}${WHITE}${#HAYSTACK[@]} AWS Accounts found: [${!HAYSTACK[@]}]${NC}"
    printf "%*s\n" "$COLUMNS" "" | tr " " "="
    printf $CURSOR_ON
}

# generateReport Prints the report of each AWS account in HAYSTACK
function generateReport {
    # FIXME: Why cant I set AWS_PARTITION from isAuthenticated? Functions doent always bring in global scoped vars?
    local AWS_PARTITION=$(aws sts get-caller-identity --query "Arn" --output text 2> /dev/null | cut -d':' -f2)
    for NEEDLE in "${!HAYSTACK[@]}"; do
        echo -en "Assuming ${WHITE}${BOLD}arn:${AWS_PARTITION}:iam::${NEEDLE}:role/${ASSUME_ROLE_NAME}${NC} for AWS Account: ${BLUE}${NEEDLE}${NC}... "

        local CREDENTIALS=$(aws sts assume-role \
            --role-arn "arn:${AWS_PARTITION}:iam::${NEEDLE}:role/${ASSUME_ROLE_NAME}" \
            --role-session-name "${NEEDLE}_${VOL_CHECKUP}" 2>/dev/null)
        
        if [[ -z "$CREDENTIALS" ]]; then
            echo -e "${RED}Failed!${NC}"
            unset HAYSTACK["$NEEDLE"]
            continue
        fi
        
        export AWS_ACCESS_KEY_ID=$(jq -r '.Credentials.AccessKeyId' <<< $CREDENTIALS)
        export AWS_SECRET_ACCESS_KEY=$(jq -r '.Credentials.SecretAccessKey' <<< $CREDENTIALS)
        export AWS_SESSION_TOKEN=$(jq -r '.Credentials.SessionToken' <<< $CREDENTIALS)
        
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
        [[ $DELETE_VOLS == true ]] && { createDLMPolicy "$NEEDLE"; deleteEbsVolumes; }
    done
    # Print table footer
    printf "%*s\n" "$COLUMNS" "" | tr " " "="
    printf "${WHITE}${BOLD}Total Number of Accounts:${NC} %d\t\t\t${WHITE}${BOLD}Total Unattached EBS Volumes:${NC} %d\t\t\t${WHITE}${BOLD}Total Size:${NC} %d GB\t\t\t${WHITE}${BOLD}Total Cost:${NC} \$%d/month ${GRAY}(@ \$0.10/GB)${NC}\n" "${#HAYSTACK[@]}" "$TOTAL_COUNT" "$TOTAL_SIZE" "$TOTAL_COST"
    # Only show when --debug is used
    (>/dev/null echo "${#ALL_EBS_VOL_IDS[@]} Volumes will be deleted: [${ALL_EBS_VOL_IDS[@]}]")
}

# Cause why not!?!
spinner() {
    [[ $HAS_RESULTS == true ]] && return
	let i=$1
	local sp="-\|/"
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
${TAB}o Checks all pre-requesites are satisfied to run $0
${TAB}o Gathers K8S Pods that contain AWS account info for management and/or tenants
${TAB}o Gathers and reports unattached EBS volume data and costs
${TAB}o Creates EBS snapshots and Data Lifecycle Manager policy
${TAB}o Tags all resources created by this script
${TAB}o Deletes unattached EBS volumes
${TAB}MANDATORY PARAMETERS
${TAB}None.

${TAB}OPTIONS
${TAB}-a|--all ${TAB}${TAB}Report all unattached EBS Volumes. Default behavior is to report EBS Volumes older than 1 year old from today's date.
${TAB}-c|--check ${TAB}${TAB}Check credentials and connectivity to K8S cluster.
${TAB}-d|--delete ${TAB}${TAB}Delete the volumes shown in the report. (remove --dry-run from deleteEbsVolumes() after all environments have been tested)
${TAB}-h|--help ${TAB}${TAB}Display usage help.
${TAB}-i|--ingress ${TAB}${TAB}Specify the ingress point (ELB) of the environment. (this is ignored when running from within the VPC, ie: workstation)
${TAB}-n|--no-snapshots ${TAB}Don't create snapshots of volumes (snapshots created by default).
${TAB}-t|--tenants ${TAB}${TAB}Include tenant pods/accounts in the report.
${TAB}-v|--debug ${TAB}${TAB}Display debugging info with output.
EOF
}

# Entry Point
GETOPT=`getopt -o acdhintv \
    -l all,check,delete,help,ingress,no-snapshots,tenants,debug: -- "$@"`

# Exit if getopt fails
if [ $? -ne 0 ]; then
    echo "Invalid option(s) provided."
    exit 1
fi

# Parse arguments
eval set -- "$GETOPT"

while true; do
    case "$1" in
    -a|--all)
        GET_ALL_UNATTACHED=true
        shift
        ;;
    -c|--check)
        checkPrerequisites
        exit 0
        ;;
    -h|--help)
        usage
        exit 0
        ;;
    -i|--ingress)
        INGRESS_ENDPOINT=$2
        shift 2
        ;;
    -d|--delete)
        DELETE_VOLS=true
        shift
        ;;
    -n|--no-snapshots)
        CREATE_SNAPSHOTS=false
        shift
        ;;
    -v|--debug)
        set -x
        shift
        ;;
    -t|--tenants)
		INCLUDE_TENANTS=true
        shift
        ;;
    --) 
        shift 
        break 
        ;;
    *)
        echo "Unrecognized option: $1"
        exit 1
        ;;
    esac
done
main