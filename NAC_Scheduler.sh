#!/bin/bash
##branch 330
##############################################
## Pre-Requisite(S):						##
## 		- Git, AWS CLI, JQ 					##
##		- AWS Profile Setup as nasuni		##
##############################################
DATE_WITH_TIME=$(date "+%Y%m%d-%H%M%S")
START=$(date +%s)

add_Rules_To_SecurityGroup() {
    SG_ID="$1"
    PORT="$2"
    CIDR="$3"
    PROFILE="$4"
    REGION="$5"
    echo "INFO ::: Updating Security Rule to allow inbound traffic from port $PORT"
    aws ec2 authorize-security-group-ingress --group-id $SG_ID --protocol tcp --port $PORT --cidr $CIDR --profile $PROFILE --region $REGION  2> /dev/null
    if [[ $? -ne 0 ]]; then
        echo "INFO ::: Security Rule to allow inbound traffic from port $PORT already Exist !!!"
    else
        echo "INFO ::: Security Rule Updated Successfully for port $PORT"
    fi
}

Create_NAC_ES_SecurityGroup() {
    VPC_ID="$1"
    PROFILE="$2"
    REGION="$3"
    CIDR=$(aws ec2 describe-vpcs --profile $PROFILE --region $REGION | jq -r '.Vpcs[]|select(.VpcId == '\"$VPC_ID\"')|{CidrBlock}' | jq -r '.CidrBlock')
    echo "CIDR: $CIDR"

    CHECK_SG=$(aws ec2 describe-security-groups --filters Name=group-name,Values=*nasuni-labs-SG-$REGION* --query "SecurityGroups[*].{Name:GroupName,ID:GroupId}" --profile $PROFILE --region $REGION | jq -r '.[].ID')
    if [[ $CHECK_SG == "" ]] || [[ $CHECK_SG == "null" ]]; then
        echo "INFO ::: Security Group Does Not Exist !!!"

        CREATE_SG=$(aws ec2 create-security-group --group-name "nasuni-labs-SG-$REGION" --description "NAC-ES Infrastructure security group" --profile $PROFILE --region $REGION)
        SG_ID=$(echo $CREATE_SG | jq -r '.GroupId')
        echo "INFO ::: New Security Group Created with ID = $SG_ID"
    else
        SG_ID="$CHECK_SG"
        echo "INFO ::: Security Group $SG_ID Already Exists !!!"
    fi
	NAC_ES_SECURITYGROUP_ID="$SG_ID"
    add_Rules_To_SecurityGroup $SG_ID 22 $CIDR $PROFILE $REGION
    add_Rules_To_SecurityGroup $SG_ID 80 $CIDR $PROFILE $REGION
    add_Rules_To_SecurityGroup $SG_ID 443 $CIDR $PROFILE $REGION
    add_Rules_To_SecurityGroup $SG_ID 8080 $CIDR $PROFILE $REGION
}

check_if_subnet_exists(){
	INPUT_SUBNET="$1"
	INPUT_VPC="$2"
	SUBNET_CHECK=`aws ec2 describe-subnets --filters "Name=subnet-id,Values=$INPUT_SUBNET" --region ${AWS_REGION} --profile "${AWS_PROFILE}"`
	SUBNET=`echo $SUBNET_CHECK | jq -r '.Subnets[].SubnetId'`
	SUBNET_VPC=`echo $SUBNET_CHECK | jq -r '.Subnets[].VpcId'`
	VPC_IS="$SUBNET_VPC"
	SUBNET_IS="$SUBNET"
	AZ_IS=`echo $SUBNET_CHECK | jq -r '.Subnets[].AvailabilityZone'`
	echo "INFO ::: SUBNET_IS=$SUBNET_IS , VPC_IS=$VPC_IS, AZ_IS=$AZ_IS"
	if [ "$INPUT_VPC" == "" ] ; then
		INPUT_VPC=$VPC_IS
	fi
	if [ "$VPC_IS" != "$INPUT_VPC" ] ; then
		echo "ERROR ::: $INPUT_SUBNET is not a valid Subnet in VPC $INPUT_VPC."
		exit 1
	fi

	if [ "$SUBNET" == "null" ] || [ "$SUBNET" == "" ]; then
		echo "ERROR ::: Subnet $INPUT_SUBNET not available. Please provide a valid Subnet ID."
		exit 1
	else
		echo "INFO ::: Subnet $SUBNET_IS exists in VPC $VPC_IS" 
	fi
}
current_folder(){
CURRENT_FOLDER=`pwd`
echo "INFO ::: Current Folder: $CURRENT_FOLDER"
}

check_if_opensearch_exists(){

	OS_ADMIIN_SECRET="$1"
	AWS_REGION="$2"
	AWS_PROFILE="$3"
	GITHUB_ORGANIZATION="$4"

	######################## Check If ES Domain Available ###############################################
	ES_DOMAIN_NAME=$(aws secretsmanager get-secret-value --secret-id "${OS_ADMIIN_SECRET}" --region "${AWS_REGION}" --profile "${AWS_PROFILE}" | jq -r '.SecretString' | jq -r '.es_domain_name')
	echo "INFO ::: ES_DOMAIN NAME : $ES_DOMAIN_NAME"
	IS_ES="N"
	if [ "$ES_DOMAIN_NAME" == "" ] || [ "$ES_DOMAIN_NAME" == null ]; then
		echo "INFO ::: Amazon_OpenSearch_Service configuration is Not found in admin secret"
		IS_ES="N"
	else
		ES_CREATED=$(aws es describe-elasticsearch-domain --domain-name "${ES_DOMAIN_NAME}" --region "${AWS_REGION}"  --profile "${AWS_PROFILE}" | jq -r '.DomainStatus.Created')
		if [ $? -eq 0 ]; then
			echo "INFO ::: ES_CREATED : $ES_CREATED"
			ES_PROCESSING=$(aws es describe-elasticsearch-domain --domain-name "${ES_DOMAIN_NAME}" --region "${AWS_REGION}"  --profile "${AWS_PROFILE}" | jq -r '.DomainStatus.Processing')
			echo "INFO ::: ES_PROCESSING : $ES_PROCESSING"
			ES_UPGRADE_PROCESSING=$(aws es describe-elasticsearch-domain --domain-name "${ES_DOMAIN_NAME}" --region "${AWS_REGION}"  --profile "${AWS_PROFILE}" | jq -r '.DomainStatus.UpgradeProcessing')
			echo "INFO ::: ES_UPGRADE_PROCESSING : $ES_UPGRADE_PROCESSING"

			if [ "$ES_PROCESSING" == "false" ] &&  [ "$ES_UPGRADE_PROCESSING" == "false" ]; then
				echo "INFO ::: Amazon_OpenSearch_Service ::: $ES_DOMAIN_NAME is Active"
				IS_ES="Y"
			else
				echo "ERROR ::: Amazon_OpenSearch_Service ::: $ES_DOMAIN_NAME is either unavailable Or Not Active"
				IS_ES="N"
			fi
		else
			echo "ERROR ::: Amazon_OpenSearch_Service ::: $ES_DOMAIN_NAME not found"
			IS_ES="N"
		fi
	fi

	### Create a new Amazon_OpenSearch_Service if IS_ES = N
	
	if [ "$IS_ES" == "N" ]; then
		echo "INFO ::: Amazon_OpenSearch_Service is Not Configured. Need to Provision Amazon_OpenSearch_Service Before, NAC Provisioning."
		echo "INFO ::: Begin Amazon_OpenSearch_Service Provisioning."
		######################## Check If ES ServiceLink Role Available ###############################################
		ES_ServiceLink_NAME=$(aws iam get-role --role-name AWSServiceRoleForAmazonOpenSearchService --profile "${AWS_PROFILE}" | jq -r '.Role' | jq -r '.RoleName')
		if [ "$ES_ServiceLink_NAME" == "" ] || [ "$ES_ServiceLink_NAME" == null ]; then
			echo "ERROR ::: OpenSearch ServiceLink Role is Not Available, Creating Servicelink Role."
			Create_ServiceLink_NAME=$(aws iam create-service-linked-role --aws-service-name opensearchservice.amazonaws.com --profile "${AWS_PROFILE}")
			if [ "$Create_ServiceLink_NAME" != "" ]; then
				RoleOS=$(echo $Create_ServiceLink_NAME | jq -r '.Role' | jq -r '.RoleName')
				echo "INFO ::: OpenSearch ServiceLink Role Created : $RoleOS"
			fi
		else
			echo "INFO ::: ES_ServiceLink name : $ES_ServiceLink_NAME"
			echo "INFO ::: OpenSearch ServiceLink Role already Available !!!"
		fi
		
		########## Download Amazon_OpenSearch_Service provisioning Code from GitHub ##########
		### GITHUB_ORGANIZATION defaults to nasuni-labs
		REPO_FOLDER="nasuni-awsopensearch"
		validate_github $GITHUB_ORGANIZATION $REPO_FOLDER
		########################### Git Clone  ###############################################################
		echo "INFO ::: BEGIN - Git Clone !!!"
		### Download Provisioning Code from GitHub
		GIT_REPO_NAME=$(echo ${GIT_REPO} | sed 's/.*\/\([^ ]*\/[^.]*\).*/nasuni-\1/' | cut -d "/" -f 2)
		echo "INFO ::: GIT_REPO $GIT_REPO , GIT_BRANCH $GIT_BRANCH"
		echo "INFO ::: GIT_REPO_NAME $GIT_REPO_NAME"
		current_folder
		echo "INFO ::: Removing ${GIT_REPO_NAME}"
		rm -rf "${GIT_REPO_NAME}"
		current_folder
		COMMAND="git clone -b $GIT_BRANCH ${GIT_REPO}"
		$COMMAND
		RESULT=$?
		if [ $RESULT -eq 0 ]; then
			echo "INFO ::: FINISH ::: GIT clone SUCCESS for repo ::: $GIT_REPO_NAME"
		else
			echo "INFO ::: FINISH ::: GIT Clone FAILED for repo ::: $GIT_REPO_NAME"
			exit 1
		fi
		cd "${GIT_REPO_NAME}"
		##### RUN terraform init
		echo "INFO ::: Amazon_OpenSearch_Service provisioning ::: BEGIN ::: Executing ::: Terraform init . . . . . . . . "
		COMMAND="terraform init"
		$COMMAND
		echo "INFO ::: Amazon_OpenSearch_Service provisioning ::: FINISH - Executing ::: Terraform init."

		##### RUN terraform Apply
		echo "INFO ::: Amazon_OpenSearch_Service provisioning ::: Creating TFVARS File."
		#### Create TFVARS FILE FOR OS Provisioning
		# echo "USE_PRIVATE_IP $USE_PRIVATE_IP
		USE_PRIVATE_IP=$(echo $USE_PRIVATE_IP|tr -d '"')
		USER_SUBNET_ID=$(echo $USER_SUBNET_ID|tr -d '"')
		USER_VPC_ID=$(echo $USER_VPC_ID|tr -d '"')
		AWS_REGION=$(echo $AWS_REGION|tr -d '"')
		echo "INFO ::: USE_PRIVATE_IP : $USE_PRIVATE_IP "
		if [[ "$USE_PRIVATE_IP" = Y ]]; then
			OS_TFVARS="Os.tfvars"
			echo "user_subnet_id="\"$USER_SUBNET_ID\" >$OS_TFVARS
			echo "user_vpc_id="\"$USER_VPC_ID\" >>$OS_TFVARS
			echo "use_private_ip="\"$USE_PRIVATE_IP\" >>$OS_TFVARS
			echo "es_region="\"$AWS_REGION\" >>$OS_TFVARS
			echo "nac_es_securitygroup_id="\"$NAC_ES_SECURITYGROUP_ID\" >>$OS_TFVARS
			echo "" >>$OS_TFVARS
			echo "INFO ::: TFVARS $OS_TFVARS File created for OpenSearch Provisioning"
			echo "INFO ::: Amazon_OpenSearch_Service provisioning ::: BEGIN ::: Executing ::: Terraform apply . . . . . . . . . . . . . . . . . . ."
			COMMAND="terraform apply -var-file=$OS_TFVARS -auto-approve"
			$COMMAND
		else
			chmod 755 $(pwd)/*
			# exit 1
			##### RUN terraform Apply
			echo "INFO ::: Amazon_OpenSearch_Service provisioning ::: BEGIN ::: Executing ::: Terraform apply . . . . . . . . . . . . . . . . . . ."
			COMMAND="terraform apply -auto-approve"
			$COMMAND
		fi

		if [ $? -eq 0 ]; then
			echo "INFO ::: Amazon_OpenSearch_Service provisioning ::: FINISH ::: Executing ::: Terraform apply ::: SUCCESS"
		else
			echo "ERROR ::: Amazon_OpenSearch_Service provisioning ::: FINISH ::: Executing ::: Terraform apply ::: FAILED "
			exit 1
		fi
		cd ..
	else
		echo "INFO ::: Amazon_OpenSearch_Service is Active . . . . . . . . . ."
		echo "INFO ::: BEGIN ::: NAC Provisioning . . . . . . . . . . . ."
	fi

	##################################### END ES Domain ###################################################################
		
}

check_if_vpc_exists(){
INPUT_VPC="$1"

VPC_CHECK=`aws ec2 describe-vpcs --filters "Name=vpc-id,Values=$INPUT_VPC" --region ${AWS_REGION} --profile "${AWS_PROFILE}" | jq -r '.Vpcs[].VpcId'`
echo "$?"
VPC_0_SUBNET=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$INPUT_VPC" --region ${AWS_REGION} --profile "${AWS_PROFILE}" | jq -r '.Subnets[0].SubnetId')
VPC_IS="$VPC_CHECK"
SUBNET_IS="$VPC_0_SUBNET"
AZ_IS=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$INPUT_VPC" --region ${AWS_REGION} --profile "${AWS_PROFILE}" | jq -r '.Subnets[0].AvailabilityZone')
echo "SUBNET_IS=$VPC_0_SUBNET , VPC_IS=$VPC_CHECK, AZ_IS=$AZ_IS"
if [ "$VPC_CHECK" == "null" ] || [ "$VPC_CHECK" == "" ]; then
	echo "ERROR ::: VPC $INPUT_VPC not available. Please provide a valid VPC ID."
	exit 1
else
	echo "INFO ::: VPC $VPC_IS is Valid" 
fi
}

check_if_pem_file_exists() {
FILE=$(echo "$1" | tr -d '"')
if [ -f "$FILE" ]; then
	echo "INFO ::: $FILE exists."
else 
	echo "ERROR ::: $FILE does not exist."
	exit 1
fi

}

validate_github() {
	GITHUB_ORGANIZATION=$1
	REPO_FOLDER=$2
	if [ "$GITHUB_ORGANIZATION" != "" ]; then
		echo "INFO ::: Value of github_organization is $GITHUB_ORGANIZATION"	
	else 
		GITHUB_ORGANIZATION="nasuni-labs"
		echo "INFO ::: Value of github_organization is set to default as $GITHUB_ORGANIZATION"	
	fi
	GIT_REPO="https://github.com/$GITHUB_ORGANIZATION/$REPO_FOLDER.git"
	echo "INFO ::: git repo $GIT_REPO"
	git ls-remote $GIT_REPO -q
	REPO_EXISTS=$?
	if [ $REPO_EXISTS -ne 0 ]; then
		echo "ERROR ::: Unable to Access the git repo $GIT_REPO. Execution STOPPED"
		exit 1
	else
		echo "INFO ::: git repo accessible. Continue . . . Provisioning . . . "
	fi
}

nmc_endpoint_accessibility() {
	NAC_SCHEDULER_NAME="$1"
	NAC_SCHEDULER_IP_ADDR="$2"
    NMC_API_ENDPOINT="$3"
	NMC_API_USERNAME="$4"
	NMC_API_PASSWORD="$5" #14-19
	PEM="$PEM_KEY_PATH"
	
	chmod 400 $PEM
	### nac_scheduler_name = from FourthArgument of NAC_Scheduler.sh, user_sec.txt
	### parse_textfile_for_user_secret_keys_values user_sec.txt
	echo "INFO ::: NAC_SCHEDULER_NAME ::: ${NAC_SCHEDULER_NAME}"
	echo "INFO ::: NAC_SCHEDULER_IP_ADDR ::: ${NAC_SCHEDULER_IP_ADDR}"
	echo "INFO ::: NMC_API_ENDPOINT ::: ${NMC_API_ENDPOINT}"
	
	echo "INFO ::: NAC_SCHEDULER_IP_ADDR : "$NAC_SCHEDULER_IP_ADDR
	py_file_name=$(ls check_nmc_visiblity.py)
	echo "INFO ::: Executing Python code file : "$py_file_name
	cat $py_file_name | ssh -i "$PEM" ubuntu@$NAC_SCHEDULER_IP_ADDR -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null python3 - $NMC_API_USERNAME $NMC_API_PASSWORD $NMC_API_ENDPOINT
	if [ $? -eq 0 ]; then
		echo "INFO ::: NAC Scheduler with IP : ${NAC_SCHEDULER_IP_ADDR}, have access to NMC API ${NMC_API_ENDPOINT} "
	else
		echo "ERROR ::: NAC Scheduler with IP : ${NAC_SCHEDULER_IP_ADDR}, Does NOT have access to NMC API ${NMC_API_ENDPOINT}. Please configure access to NMC "
		exit 1
	fi
	echo "INFO ::: Completed NMC endpoint accessibility Check. !!!"

}
parse_4thArgument_for_nac_scheduler_name() {
	file="$1"
	if [ -f "$file" ]; then
		dos2unix $file
		while IFS="=" read -r key value; do
			case "$key" in
			"nac_scheduler_name") NAC_SCHEDULER_NAME="$value" ;;
			"pem_key_path") PEM_KEY_PATH="$value" ;;
			"github_organization") GITHUB_ORGANIZATION="$value" ;;
			"user_vpc_id") USER_VPC_ID="$value" ;;
			"user_subnet_id") USER_SUBNET_ID="$value" ;;
			"use_private_ip") USE_PRIVATE_IP="$value" ;;
			"git_branch") GIT_BRANCH="$value" ;;
			esac
		done <"$file"
	else
		SECRET_NAME="$file"
		SECRET_STRING=$(aws secretsmanager get-secret-value --secret-id "$SECRET_NAME" --region "${AWS_REGION}" --profile "${AWS_PROFILE}")

		NAC_SCHEDULER_NAME=$(echo $SECRET_STRING | jq -r '.SecretString' | jq -r '.nac_scheduler_name')
		NMC_API_USERNAME=$(echo $SECRET_STRING  | jq -r '.SecretString' | jq -r '.nmc_api_username')
		NMC_API_PASSWORD=$(echo $SECRET_STRING  | jq -r '.SecretString' | jq -r '.nmc_api_password')
		NMC_API_ENDPOINT=$(echo $SECRET_STRING  | jq -r '.SecretString' | jq -r '.nmc_api_endpoint')
		PEM_KEY_PATH=$(echo $SECRET_STRING  | jq -r '.SecretString' | jq -r '.pem_key_path')
		GITHUB_ORGANIZATION=$(echo $SECRET_STRING  | jq -r '.SecretString' | jq -r '.github_organization')
		USER_VPC_ID=$(echo $SECRET_STRING  | jq -r '.SecretString' | jq -r '.user_vpc_id')
		USER_SUBNET_ID=$(echo $SECRET_STRING  | jq -r '.SecretString' | jq -r '.user_subnet_id')
		USE_PRIVATE_IP=$(echo $SECRET_STRING  | jq -r '.SecretString' | jq -r '.use_private_ip')
		GIT_BRANCH=$(echo $SECRET_STRING  | jq -r '.SecretString' | jq -r '.git_branch')
		
		echo "INFO ::: github_organization=$GITHUB_ORGANIZATION :: nac_scheduler_name=$NAC_SCHEDULER_NAME :: nmc_api_username=$NMC_API_USERNAME :: nmc_api_password=$NMC_API_PASSWORD :: nmc_api_endpoint=$NMC_API_ENDPOINT :: pem_key_path=$PEM_KEY_PATH"
	fi
	if [ "$GITHUB_ORGANIZATION" == "" ] || [ "$GITHUB_ORGANIZATION" == "null" ]; then
		GITHUB_ORGANIZATION="nasuni-labs"
		echo "INFO ::: Value of github_organization is set to default as $GITHUB_ORGANIZATION"	
	else 
		echo "INFO ::: Value of github_organization is $GITHUB_ORGANIZATION"	
	fi
	if [ "$GIT_BRANCH" == "" ] || [ "$GIT_BRANCH" == "null" ]; then
		GIT_BRANCH="main"
	fi
	echo "INFO ::: Value of git_branch is: $GIT_BRANCH"
}

append_nac_keys_values_to_tfvars() {
	inputFile="$1" ### Read InputFile
	outFile="$2"
	dos2unix $inputFile
	while IFS="=" read -r key value; do
		echo "$key ::: $value "
		if [ ${#key} -ne 0 ]; then
			echo "$key=$value" >>$outFile
		fi
	done <"$inputFile"
	echo "INFO ::: Append NAC key-value(s) to tfvars, ::: $outFile"
}

check_if_secret_exists() {
	USER_SECRET="$1"
	AWS_PROFILE="$2"
	AWS_REGION="$3"

	# Verify the Secret Exists
	if [[ -n $USER_SECRET ]]; then
		COMMAND=$(aws secretsmanager list-secrets --profile "${AWS_PROFILE}" --region "${AWS_REGION}" | jq -r '.SecretList[]| select(.Name == '\"$USER_SECRET\"') | {Name}' | jq -r '.Name')

		if [[ "$COMMAND" = "$USER_SECRET" ]]; then
			### echo "INFO ::: Secret ${USER_SECRET} Exists. $RES"
			echo "Y"
		else
			### echo "ERROR ::: $RES :: Secret ${USER_SECRET} Does'nt Exist in ${AWS_REGION} region. OR, Invalid Secret name passed as 4th parameter"
			echo "N"
			# exit 0
		fi
	fi
}

validate_kvp() {
	key="$1"
	val="$2"
	if [[ $val == "" ]]; then
		echo "ERROR ::: Empty Value provided. Please provide a valid value for ${key}."
		exit 1
	else
		echo "INFO ::: Value of ${key} is ${val}"
	fi
} 
validate_secret_values() {
	SECRET_NAME=$1
	SECRET_KEY=$2
	AWS_REGION=$3
	AWS_PROFILE=$4
	echo "INFO ::: Validating Secret_key ::: $SECRET_KEY in secret-id $SECRET_NAME (in region $AWS_REGION)"
	SECRET_VALUE=""
	if [ "$SECRET_KEY" == "nmc_api_username" ]; then
		SECRET_VALUE=$(aws secretsmanager get-secret-value --secret-id "$SECRET_NAME" --region "${AWS_REGION}" --profile "${AWS_PROFILE}" | jq -r '.SecretString' | jq -r '.nmc_api_username')
	elif [ "$SECRET_KEY" == "nmc_api_password" ]; then
		SECRET_VALUE=$(aws secretsmanager get-secret-value --secret-id "$SECRET_NAME" --region "${AWS_REGION}" --profile "${AWS_PROFILE}" | jq -r '.SecretString' | jq -r '.nmc_api_password')
	elif [ "$SECRET_KEY" == "nac_product_key" ]; then
		SECRET_VALUE=$(aws secretsmanager get-secret-value --secret-id "$SECRET_NAME" --region "${AWS_REGION}" --profile "${AWS_PROFILE}" | jq -r '.SecretString' | jq -r '.nac_product_key')
	elif [ "$SECRET_KEY" == "nmc_api_endpoint" ]; then
		SECRET_VALUE=$(aws secretsmanager get-secret-value --secret-id "$SECRET_NAME" --region "${AWS_REGION}" --profile "${AWS_PROFILE}" | jq -r '.SecretString' | jq -r '.nmc_api_endpoint')
	elif [ "$SECRET_KEY" == "web_access_appliance_address" ]; then
		SECRET_VALUE=$(aws secretsmanager get-secret-value --secret-id "$SECRET_NAME" --region "${AWS_REGION}" --profile "${AWS_PROFILE}" | jq -r '.SecretString' | jq -r '.web_access_appliance_address')
	elif [ "$SECRET_KEY" == "destination_bucket" ]; then
		SECRET_VALUE=$(aws secretsmanager get-secret-value --secret-id "$SECRET_NAME" --region "${AWS_REGION}" --profile "${AWS_PROFILE}" | jq -r '.SecretString' | jq -r '.destination_bucket')
	elif [ "$SECRET_KEY" == "volume_key" ]; then
		SECRET_VALUE=$(aws secretsmanager get-secret-value --secret-id "$SECRET_NAME" --region "${AWS_REGION}" --profile "${AWS_PROFILE}" | jq -r '.SecretString' | jq -r '.volume_key')
	elif [ "$SECRET_KEY" == "pem_key_path" ]; then
		SECRET_VALUE=$(aws secretsmanager get-secret-value --secret-id "$SECRET_NAME" --region "${AWS_REGION}" --profile "${AWS_PROFILE}" | jq -r '.SecretString' | jq -r '.pem_key_path')
	fi
	if [ -z "$SECRET_VALUE" ] ; then
        echo "ERROR ::: Validation FAILED as, Empty String Value passed to key $SECRET_KEY = $SECRET_VALUE in secret $SECRET_NAME."
        exit 1
	else
		if [ "$SECRET_VALUE" == "null" ] ; then
			echo "ERROR ::: Validation FAILED as, Key $SECRET_KEY does not exists in secret $SECRET_NAME." 
			exit 1
		else 
			echo "INFO ::: Validation SUCCESS, as key $SECRET_KEY has value $SECRET_VALUE in secret $SECRET_NAME."
		fi
	fi
}

parse_textfile_for_user_secret_keys_values() {
	file="$1"
	while IFS="=" read -r key value; do
		case "$key" in
		"nmc_api_username") NMC_API_USERNAME="$value" ;;
		"nmc_api_password") NMC_API_PASSWORD="$value" ;;
		"nac_product_key") NAC_PRODUCT_KEY="$value" ;;
		"nmc_api_endpoint") NMC_API_ENDPOINT="$value" ;;
		"web_access_appliance_address") WEB_ACCESS_APPLIANCE_ADDRESS="$value" ;;
		"volume_key") VOLUME_KEY="$value" ;;
		"volume_key_passphrase") VOLUME_KEY_PASSPHRASE="$value" ;;
		"destination_bucket") DESTINATION_BUCKET="$value" ;;
		"pem_key_path") PEM_KEY_PATH="$value" ;;
		"github_organization") GITHUB_ORGANIZATION="$value" ;;
		"git_branch") GIT_BRANCH="$value" ;;
		"user_vpc_id") USER_VPC_ID="$value" ;;
		"user_subnet_id") USER_SUBNET_ID="$value" ;;
		"use_private_ip") USE_PRIVATE_IP="$value" ;;
		esac
	done <"$file"
	if [ "$GITHUB_ORGANIZATION" != "" ]; then
		echo "INFO ::: Value of github_organization is $GITHUB_ORGANIZATION"	
	else 
		GITHUB_ORGANIZATION="nasuni-labs"
		echo "INFO ::: Value of github_organization is set to default as $GITHUB_ORGANIZATION"	
	fi
	if [ "$USER_VPC_ID" != "" ]; then
		echo "INFO ::: Value of user_vpc_id is $USER_VPC_ID"	
	fi
	if [ "$GIT_BRANCH" == "" ] || [ "$GIT_BRANCH" == "null" ]; then
		GIT_BRANCH="main"
	fi
	echo "INFO ::: Validating the user data file ${file} and the provided values"
	validate_kvp nmc_api_username "${NMC_API_USERNAME}"
	validate_kvp nmc_api_password "${NMC_API_PASSWORD}"
	validate_kvp nac_product_key "${NAC_PRODUCT_KEY}"
	validate_kvp nmc_api_endpoint "${NMC_API_ENDPOINT}"
	validate_kvp web_access_appliance_address "${WEB_ACCESS_APPLIANCE_ADDRESS}"
	validate_kvp destination_bucket "${DESTINATION_BUCKET}"
	validate_kvp pem_key_path "${PEM_KEY_PATH}"
}
create_JSON_from_Input_user_KVPfile() {
	file_name=$1
	last_line=$(wc -l <$file_name)
	current_line=0
	echo "{"
	while read line; do
		current_line=$(($current_line + 1))
		if [[ $current_line -ne $last_line ]]; then
			[ -z "$line" ] && continue
			echo $line | awk -F'=' '{ print " \""$1"\" : \""$2"\","}' | grep -iv '\"#'
		else
			echo $line | awk -F'=' '{ print " \""$1"\" : \""$2"\""}' | grep -iv '\"#'
		fi
	done <$file_name
	echo "}"
}

###########Adding Local IP to Security Group which is realted to NAC Public IP Address
add_ip_to_sec_grp() {
	NAC_SCHEDULER_IP_ADDR=$1
	echo "INFO ::: Extracting Public IP of the JumpBox"
	echo $(curl checkip.amazonaws.com) >LOCAL_IP.txt

	LOCAL_IP=$(cat LOCAL_IP.txt)
	rm -rf LOCAL_IP.txt
	echo "INFO ::: Public IP of the JumpBox machine is ${LOCAL_IP}"
	NEW_CIDR="${LOCAL_IP}"/32
	echo "INFO ::: NEW_CIDR :- ${NEW_CIDR}"
	### Get Security group of NAC Scheduler
	SECURITY_GROUP_ID=$(aws ec2 describe-instances --query "Reservations[].Instances[].{Name:Tags[?Key=='Name']|[0].Value,Status:State.Name,SecurityGroups:SecurityGroups[*]}" --filters "Name=tag:Name,Values='$NAC_SCHEDULER_NAME'" "Name=instance-state-name,Values=running" --region $AWS_REGION --profile $AWS_PROFILE | grep -e "GroupId" | cut -d":" -f 2 | tr -d '"')
	echo $SECURITY_GROUP_ID
	echo "INFO ::: Security group of $NAC_SCHEDULER_NAME is $SECURITY_GROUP_ID"
	status=$(aws ec2 authorize-security-group-ingress --group-id ${SECURITY_GROUP_ID} --profile "${AWS_PROFILE}" --protocol tcp --port 22 --cidr ${NEW_CIDR} 2>/dev/null)
	if [ $? -eq 0 ]; then
		echo "INFO ::: JumpBox Computer IP $NEW_CIDR updated to inbound rule of Security Group $SECURITY_GROUP_ID"
	else
		echo "INFO ::: IP $NEW_CIDR already available in inbound rule of Security Group $SECURITY_GROUP_ID"
	fi

}

AWS_PROFILE="nasuni"
AWS_REGION=""
AWS_ACCESS_KEY_ID=""
AWS_SECRET_ACCESS_KEY=""
ARG_COUNT="$#"
######################## Validating AWS profile for NAC ####################################
validate_aws_profile() {
	echo "INFO ::: Validating AWS profile ${AWS_PROFILE} for NAC  . . . . . . . . . . . . . . . . !!!"

	if [[ "$(grep '^[[]profile' <~/.aws/config | awk '{print $2}' | sed 's/]$//' | grep "${AWS_PROFILE}")" == "" ]]; then
		echo "ERROR ::: AWS profile ${AWS_PROFILE} does not exists. To Create AWS PROFILE, Run cli command - aws configure "
		exit 1
	else # AWS Profile nasuni available in JumpBox machine
		echo "INFO ::: AWS profile $AWS_PROFILE exists in JumpBox Computer !!!"
		AWS_ACCESS_KEY_ID=$(aws configure get aws_access_key_id --profile ${AWS_PROFILE})
		AWS_SECRET_ACCESS_KEY=$(aws configure get aws_secret_access_key --profile ${AWS_PROFILE})
		AWS_REGION=`aws configure get region --profile ${AWS_PROFILE}`
		echo "INFO ::: AWS profile Validation SUCCESS !!!"
	fi
}
########################## Create CRON ############################################################
Schedule_CRON_JOB() {
	NAC_SCHEDULER_IP_ADDR=$1
	PEM="$PEM_KEY_PATH"
	check_if_pem_file_exists $PEM

	chmod 400 $PEM

	echo "INFO ::: Scheduling CRON_JOB :: Public IP Address:- $NAC_SCHEDULER_IP_ADDR"
	echo "ssh -i "$PEM" ubuntu@$NAC_SCHEDULER_IP_ADDR -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null"
	### Create TFVARS File for PROVISION_NAC.SH which is Used by CRON JOB - to Provision NAC Stack
	CRON_DIR_NAME="${NMC_VOLUME_NAME}_${ANALYTICS_SERVICE}"
	TFVARS_FILE_NAME="${CRON_DIR_NAME}.tfvars"
	rm -rf "$TFVARS_FILE_NAME"
	arn=$(aws sts get-caller-identity --profile nasuni| jq -r '.Arn' )
	AWS_CURRENT_USER=$(cut -d'/' -f2 <<<"$arn")
	echo "INFO ::: $AWS_CURRENT_USER which will be added for lambda layer::: "
	NEW_NAC_IP=$(echo $NAC_SCHEDULER_IP_ADDR | tr '.' '-')
	RND=$(( $RANDOM % 1000000 )); 
	LAMBDA_LAYER_SUFFIX=$(echo $RND)

	echo "INFO ::: Scheduling CRON_JOB :: $NEW_NAC_IP which will be added for lambda layer::: "
	echo "aws_profile="\"$AWS_PROFILE\" >>$TFVARS_FILE_NAME
	echo "region="\"$AWS_REGION\" >>$TFVARS_FILE_NAME
	echo "volume_name="\"$NMC_VOLUME_NAME\" >>$TFVARS_FILE_NAME
	echo "user_secret="\"$USER_SECRET\" >>$TFVARS_FILE_NAME
	echo "github_organization="\"$GITHUB_ORGANIZATION\" >>$TFVARS_FILE_NAME
	echo "git_branch="\"$GIT_BRANCH\" >>$TFVARS_FILE_NAME
	echo "nac_scheduler_ip_addr="\"$NEW_NAC_IP\" >>$TFVARS_FILE_NAME 
	echo "aws_current_user="\"$AWS_CURRENT_USER\" >>$TFVARS_FILE_NAME ### Append Current aws user
	echo "user_vpc_id="\"$USER_VPC_ID\" >>$TFVARS_FILE_NAME
	echo "user_subnet_id="\"$USER_SUBNET_ID\" >>$TFVARS_FILE_NAME
	echo "lambda_layer_suffix="\"$LAMBDA_LAYER_SUFFIX\" >>$TFVARS_FILE_NAME
	echo "frequency="\"$FREQUENCY\" >>$TFVARS_FILE_NAME
	echo "nac_scheduler_name="\"$NAC_SCHEDULER_NAME\" >>$TFVARS_FILE_NAME
	echo "nac_es_securitygroup_id="\"$NAC_ES_SECURITYGROUP_ID\" >>$TFVARS_FILE_NAME
	if [[ "$USE_PRIVATE_IP" == "Y" ]]; then
		echo "use_private_ip="\"$USE_PRIVATE_IP\" >>$TFVARS_FILE_NAME
	fi
	if [ $ARG_COUNT -eq 5 ]; then
		echo "INFO ::: $ARG_COUNT th Argument is supplied as ::: $NAC_INPUT_KVP"
		append_nac_keys_values_to_tfvars $NAC_INPUT_KVP $TFVARS_FILE_NAME
	fi
	scp -i "$PEM" -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null create_layer.sh tracker_json.py ubuntu@$NAC_SCHEDULER_IP_ADDR:~/ #SSA
	RES="$?"
	if [ $RES -ne 0 ]; then
		echo "ERROR ::: Failed to Copy create_layer.sh to NAC_Scheduer Instance."
		exit 1
	elif [ $RES -eq 0 ]; then
		echo "INFO ::: create_layer.sh Uploaded Successfully to NAC_Scheduer Instance."
	fi
	ssh -i "$PEM" ubuntu@"$NAC_SCHEDULER_IP_ADDR" -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null "dos2unix create_layer.sh" #SSA
	RES="$?"
	if [ $RES -ne 0 ]; then
		echo "ERROR ::: Failed to do dos2unix create_layer.sh to NAC_Scheduer Instance."
		exit 1
	elif [ $RES -eq 0 ]; then
		echo "INFO ::: create_layer.sh executed dos2unix Successfully to NAC_Scheduer Instance."
	fi
	#IAM_USER to be defined. et user 
	ssh -i "$PEM" ubuntu@"$NAC_SCHEDULER_IP_ADDR" -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null "sh create_layer.sh nasuni-labs-os-lambda-layer $AWS_PROFILE $NAC_SCHEDULER_IP_ADDR $AWS_CURRENT_USER $LAMBDA_LAYER_SUFFIX" #SSA
	RES="$?"
	if [ $RES -ne 0 ]; then
		echo "ERROR ::: Scheduling CRON_JOB :: Failed to execute create_layer.sh to NAC_Scheduer Instance."
		exit 1
	elif [ $RES -eq 0 ]; then
		echo "INFO ::: create_layer.sh executed Successfully to NAC_Scheduer Instance."
	fi
	### Create Directory for each Volume
	ssh -i "$PEM" ubuntu@"$NAC_SCHEDULER_IP_ADDR" -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null "[ ! -d $CRON_DIR_NAME ] && mkdir $CRON_DIR_NAME "
	### Copy TFVARS and provision_nac.sh to NACScheduler
	scp -i "$PEM" -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null provision_nac.sh "$TFVARS_FILE_NAME" ubuntu@$NAC_SCHEDULER_IP_ADDR:~/$CRON_DIR_NAME

	RES="$?"
	if [ $RES -ne 0 ]; then
		echo "ERROR ::: Failed to Copy $TFVARS_FILE_NAME to NAC_Scheduer Instance."
		exit 1
	elif [ $RES -eq 0 ]; then
		echo "INFO ::: $TFVARS_FILE_NAME Uploaded Successfully to NAC_Scheduer Instance."
	fi
	rm -rf $TFVARS_FILE_NAME
	#dos2unix command execute
	ssh -i "$PEM" ubuntu@"$NAC_SCHEDULER_IP_ADDR" -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null "dos2unix ~/$CRON_DIR_NAME/provision_nac.sh"
	### Check If CRON JOB is running for a specific VOLUME_NAME
	CRON_VOL=$(ssh -i "$PEM" -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null ubuntu@"$NAC_SCHEDULER_IP_ADDR" "crontab -l |grep \"~/$CRON_DIR_NAME/$TFVARS_FILE_NAME\"")
	if [ "$CRON_VOL" != "" ]; then
		### DO Nothing. CRON JOB takes care of NAC Provisioning
		echo "INFO ::: crontab does not require volume entry. As it is already present.:::::"
	else
		### Set up a new CRON JOB for NAC Provisioning

		echo "INFO ::: Setting CRON JOB for $CRON_DIR_NAME as it is not present"
		ssh -i "$PEM" ubuntu@$NAC_SCHEDULER_IP_ADDR -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null "(crontab -l ; echo '*/$FREQUENCY * * * * cd ~/$CRON_DIR_NAME && /bin/bash provision_nac.sh  ~/$CRON_DIR_NAME/$TFVARS_FILE_NAME >> ~/$CRON_DIR_NAME/CRON_log-$CRON_DIR_NAME-$DATE_WITH_TIME.log 2>&1') | sort - | uniq - | crontab -"
		if [ $? -eq 0 ]; then
			echo "INFO :::  Scheduling CRON_JOB :: SUCCESS :: for NMC VOLUME and Service :: $CRON_DIR_NAME"
			exit 0
		else
			echo "ERROR :::  Scheduling CRON_JOB :: FAILED :: for NMC VOLUME and Service :: $CRON_DIR_NAME"
			exit 1
		fi
	fi
}

##################################### START - SCRIPT Execution HERE ##################################################

if [ $# -eq 0 ]; then
	echo "ERROR ::: No argument(s) supplied. This Script Takes 4 Mandatory Arguments 1) NMC Volume_Name, 2) Service, 3) Frequency and 4) User Secret(either Existing Secret Name Or Secret KVPs in a text file)"
	exit 1
elif [ $# -lt 4 ]; then
	echo "ERROR ::: $# argument(s) supplied. This Script Takes 4 Mandatory Arguments 1) NMC Volume_Name, 2) Service, 3) Frequency and 4) User Secret(either Existing Secret Name Or Secret KVPs in a text file)"
	exit 1
fi
#################### Validate Arguments Passed to NAC_Scheduler.sh ####################
NMC_VOLUME_NAME="$1"   ### 1st argument  ::: NMC_VOLUME_NAME
ANALYTICS_SERVICE="$2" ### 2nd argument  ::: ANALYTICS_SERVICE
FREQUENCY="$3"         ### 3rd argument  ::: FREQUENCY
FOURTH_ARG="$4"        ### 4th argument  ::: User Secret a KVP file Or an existing Secret
NAC_INPUT_KVP="$5"     ### 5th argument  ::: User defined KVP file for passing arguments to NAC
GIT_BRANCH="main"	   ### Setting Up default Git Branch as "main". For debugging change the value of your branch and execute.
# GIT_BRANCH="Optimization"
echo "INFO ::: Validating Arguments Passed to NAC_Scheduler.sh"
if [ "${#NMC_VOLUME_NAME}" -lt 3 ]; then
	echo "ERROR ::: Something went wrong. Please re-check 1st argument and provide a valid NMC Volume Name."
	exit 1
fi
if [[ "${#ANALYTICS_SERVICE}" -lt 2 ]]; then
	echo "INFO ::: The length of Service name provided as 2nd argument is too small, So, It will consider ES as the default Analytics Service."
	ANALYTICS_SERVICE="ES" # Amazon_OpenSearch_Service as default
fi
if [[ "${#FREQUENCY}" -lt 2 ]]; then
	echo "ERROR ::: Mandatory 3rd argument is invalid"
	exit 1
else
	REX="^[0-9]+([.][0-9]+)?$"
	if ! [[ $FREQUENCY =~ $REX ]]; then
		echo "ERROR ::: the 3rd Argument is Not a number" >&2
		exit 1
	fi
fi

### Validate aws_profile
validate_aws_profile

########## Check If fourth argument is provided
USER_SECRET_EXISTS="N"
if [[ -n "$FOURTH_ARG" ]]; then
	### Check If fourth argument is a file
	if [ -f "$FOURTH_ARG" ]; then
		echo "INFO ::: Fourth argument is a File ${FOURTH_ARG}"

		### Parse the user data - KVP
		parse_textfile_for_user_secret_keys_values "$FOURTH_ARG"
		### Validate the user data file and the provided values
		check_if_pem_file_exists $PEM_KEY_PATH
		### nac_scheduler_name   - Get the value -- If its not null / "" then NAC_SCHEDULER_NAME = ${nac_scheduler_name}
		create_JSON_from_Input_user_KVPfile $FOURTH_ARG >user_creds_"${NMC_VOLUME_NAME}"_"${ANALYTICS_SERVICE}".json
		### Formation of User Secret Name
		USER_SECRET="prod/nac/admin/$NMC_VOLUME_NAME/$ANALYTICS_SERVICE"
		### Verify the Secret Exists
		USER_SECRET_EXISTS=$(check_if_secret_exists $USER_SECRET $AWS_PROFILE $AWS_REGION)
		echo "INFO ::: USER_SECRET_EXISTS ::: $USER_SECRET_EXISTS "
		if [ "$USER_SECRET_EXISTS" != "N" ]; then
			echo "INFO ::: Fourth argument is a File && the User Secret exists ==> User wants to Update the Secret Values"
			### Update Secret
			echo "INFO ::: Update Secret $USER_SECRET "
			### Update Secret
			aws secretsmanager update-secret --secret-id "${USER_SECRET}" \
			--secret-string file://user_creds_"${NMC_VOLUME_NAME}"_"${ANALYTICS_SERVICE}".json \
			--region "${AWS_REGION}" --profile "${AWS_PROFILE}"
			RES="$?"
			if [ $RES -ne 0 ]; then
				echo "INFO ::: $RES Failed to Update Secret $USER_SECRET."
				exit 1
			elif [ $RES -eq 0 ]; then
				echo "INFO ::: Secret $USER_SECRET Updated SUCCESSFULLY"
			fi
		else
			## Fourth argument is a File && the User Secret Doesn't exist ==> User wants to Create a new Secret
			### Create Secret
			echo "INFO ::: Create Secret $USER_SECRET"
			aws secretsmanager create-secret --name "${USER_SECRET}" \
			--description "Preserving User specific data/secrets to be used for NAC Scheduling" \
			--secret-string file://user_creds_"${NMC_VOLUME_NAME}"_"${ANALYTICS_SERVICE}".json \
			--region "${AWS_REGION}" --profile "${AWS_PROFILE}"
			RES="$?"
			if [ $RES -ne 0 ]; then
				echo "ERROR ::: $RES Failed to Create Secret $USER_SECRET as, its already exists."
				exit 1
			elif [ $RES -eq 0 ]; then
				echo "INFO ::: Secret $USER_SECRET Created"
			fi
		fi
		rm -rf *"${NMC_VOLUME_NAME}"_"${ANALYTICS_SERVICE}".json
	else ####  Fourth Argument is passed as User Secret Name
		echo "INFO ::: Fourth Argument $FOURTH_ARG is passed as User Secret Name"
		USER_SECRET="$FOURTH_ARG"
		
		### Verify the Secret Exists
		USER_SECRET_EXISTS=$(check_if_secret_exists $USER_SECRET ${AWS_PROFILE} ${AWS_REGION}) # | jq -r .Name)
		echo "INFO ::: User secret Exists:: $USER_SECRET_EXISTS"
		# if [ "${#USER_SECRET_EXISTS}" -gt 0 ]; then
		if [ "$USER_SECRET_EXISTS" == "Y" ]; then
			### Validate Keys in the Secret
			echo "INFO ::: Check if all Keys are provided"
			validate_secret_values "$USER_SECRET" nmc_api_username "$AWS_REGION" "$AWS_PROFILE"
			validate_secret_values "$USER_SECRET" nmc_api_password "$AWS_REGION" "$AWS_PROFILE"
			validate_secret_values "$USER_SECRET" nac_product_key "$AWS_REGION" "$AWS_PROFILE"
			validate_secret_values "$USER_SECRET" nmc_api_endpoint "$AWS_REGION" "$AWS_PROFILE"
			validate_secret_values "$USER_SECRET" web_access_appliance_address "$AWS_REGION" "$AWS_PROFILE"
			validate_secret_values "$USER_SECRET" destination_bucket "$AWS_REGION" "$AWS_PROFILE"
			validate_secret_values "$USER_SECRET" volume_key "$AWS_REGION" "$AWS_PROFILE"
			validate_secret_values "$USER_SECRET" pem_key_path "$AWS_REGION" "$AWS_PROFILE"
			echo "INFO ::: Validation SUCCESS for all mandatory Secret-Keys !!!" 
		fi
	fi
else
	echo "INFO ::: Fourth argument is NOT provided, So, It will consider prod/nac/admin as the default user secret."
fi
######################  NAC Scheduler Instance is Available ##############################
NAC_SCHEDULER_NAME=""
### parse_textfile_for_nac_scheduler_name "$FOURTH_ARG"
parse_4thArgument_for_nac_scheduler_name "$FOURTH_ARG"

########################Create OS Admin Secret, If its not available ###############

OS_ADMIIN_SECRET="nasuni-labs-os-admin"
### Verify the Secret Exists
OS_ADMIIN_SECRET_EXISTS=""
OS_ADMIIN_SECRET_EXISTS=$(check_if_secret_exists $OS_ADMIIN_SECRET $AWS_PROFILE $AWS_REGION)
echo "INFO ::: OS_ADMIIN_SECRET_EXISTS ::: $OS_ADMIIN_SECRET_EXISTS "

if [ "$OS_ADMIIN_SECRET_EXISTS" == "N" ]; then
	## Fourth argument is a File && the User Secret Doesn't exist ==> User wants to Create a new Secret
	### Create Secret
	echo "INFO ::: Create Secret $OS_ADMIIN_SECRET"
	aws secretsmanager create-secret --name "${OS_ADMIIN_SECRET}" \
		--description "Preserving OpenSearch specific data/secrets" \
		--region "${AWS_REGION}" --profile "${AWS_PROFILE}"
			RES="$?"
			if [ $RES -ne 0 ]; then
				echo "ERROR ::: $RES Failed to Create Secret $OS_ADMIIN_SECRET as, its already exists."
				exit 1
			elif [ $RES -eq 0 ]; then
				echo "INFO ::: Secret $OS_ADMIIN_SECRET Created"
			fi
		else
			echo "INFO ::: Secret $OS_ADMIIN_SECRET Already Exists"
fi
######################## Check If NAC_ES_Security Available ###############################################
NAC_ES_SECURITYGROUP_ID=""
Create_NAC_ES_SecurityGroup ${USER_VPC_ID} ${AWS_PROFILE} ${AWS_REGION}
echo "INFO ::: NAC_ES_SecurityGroup :: $NAC_ES_SECURITYGROUP_ID"

######################## Check If ES Domain Available ###############################################
check_if_opensearch_exists $OS_ADMIIN_SECRET $AWS_REGION $AWS_PROFILE $GITHUB_ORGANIZATION $NAC_ES_SECURITYGROUP_ID

echo "INFO ::: Get IP Address of NAC Scheduler Instance"
######################  NAC Scheduler Instance is Available ##############################

# NAC_SCHEDULER_NAME=""
# ### parse_textfile_for_nac_scheduler_name "$FOURTH_ARG"
# parse_4thArgument_for_nac_scheduler_name "$FOURTH_ARG"
echo "INFO ::: nac_scheduler_name = $NAC_SCHEDULER_NAME "

if [ "$NAC_SCHEDULER_NAME" != "" ]; then
	### User has provided the NACScheduler Name as Key-Value from 4th Argument
	if [[ "$USE_PRIVATE_IP" != "Y" ]]; then
		### Getting Public_IP of NAC Scheduler
		NAC_SCHEDULER_IP_ADDR=$(aws ec2 describe-instances --query "Reservations[*].Instances[*].{Name:Tags[?Key=='Name']|[0].Value,Status:State.Name,PublicIP:PublicIpAddress}" --filters "Name=tag:Name,Values='$NAC_SCHEDULER_NAME'" "Name=instance-state-name,Values=running" --region "${AWS_REGION}" --profile ${AWS_PROFILE}| grep -e "PublicIP" | cut -d":" -f 2 | tr -d '"' | tr -d ' ')
		echo "INFO ::: Public_IP of NAC Scheduler is: $NAC_SCHEDULER_IP_ADDR"
	else
		### Getting Private_IP of NAC Scheduler
		echo "INFO ::: Private_IP of NAC Scheduler is: $NAC_SCHEDULER_IP_ADDR"
		NAC_SCHEDULER_IP_ADDR=`aws ec2 describe-instances --query "Reservations[*].Instances[*].{Name:Tags[?Key=='Name']|[0].Value,Status:State.Name,PrivateIp:PrivateIpAddress}" --filters "Name=tag:Name,Values='$NAC_SCHEDULER_NAME'" "Name=instance-state-name,Values=running" --region "${AWS_REGION}" --profile ${AWS_PROFILE} | grep -e "PrivateIp" | cut -d":" -f 2 | tr -d '"' | tr -d ' '`
	fi
else
	NAC_SCHEDULER_IP_ADDR=$(aws ec2 describe-instances --query "Reservations[*].Instances[*].{Name:Tags[?Key=='Name']|[0].Value,Status:State.Name,PublicIP:PublicIpAddress}" --filters "Name=tag:Name,Values='NACScheduler'" "Name=instance-state-name,Values=running" --region "${AWS_REGION}" --profile ${AWS_PROFILE}| grep -e "PublicIP" | cut -d":" -f 2 | tr -d '"' | tr -d ' ')
fi
echo "INFO ::: NAC_SCHEDULER_IP_ADDR ::: $NAC_SCHEDULER_IP_ADDR"
if [ "$NAC_SCHEDULER_IP_ADDR" != "" ]; then
	echo "INFO ::: NAC Scheduler Instance is Available. IP Address: $NAC_SCHEDULER_IP_ADDR"
	### Call this function to add Local public IP to Security group of NAC_SCHEDULER IP
	add_ip_to_sec_grp $NAC_SCHEDULER_IP_ADDR $NAC_SCHEDULER_NAME
	### nmc endpoint accessibility $NAC_SCHEDULER_NAME $NAC_SCHEDULER_IP_ADDR
	nmc_endpoint_accessibility  $NAC_SCHEDULER_NAME $NAC_SCHEDULER_IP_ADDR $NMC_API_ENDPOINT $NMC_API_USERNAME $NMC_API_PASSWORD #458
	Schedule_CRON_JOB $NAC_SCHEDULER_IP_ADDR

###################### NAC Scheduler EC2 Instance is NOT Available ##############################
else
	## "NAC Scheduler is not present. Creating new EC2 machine."
	if [ "$USER_VPC_ID" == "" ] || [ "$USER_VPC_ID" == "null" ]; then
		echo "INFO ::: user_vpc_id not provided in the user Secret"  
		if [ "$USER_SUBNET_ID" == "" ] || [ "$USER_SUBNET_ID" == "null" ]; then
		### Both user_vpc_id and user_subnet_id not provided , It will take Default VPC and Subnet
			echo "INFO ::: user_subnet_id not provided in the user Secret, Provisioning will be done in the Default VPC Subnet"
		
		else
		### user_vpc_id not provided but, user_subnet_id provided 
			echo "INFO ::: user_subnet_id provided in the user Secret as user_subnet_id=$USER_SUBNET_ID"  
			check_if_subnet_exists $USER_SUBNET_ID $USER_VPC_ID

		fi
	else
		### If user_vpc_id provided
		if [ "$USER_SUBNET_ID" == "" ] || [ "$USER_SUBNET_ID" == "null" ]; then
		### If user_vpc_id provided and user_subnet_id not Provided, It will take the provided VPC ID and its default Subnet
			echo "INFO ::: user_subnet_id not provided in the user Secret, Provisioning will be done in the Provided VPC $USER_VPC_ID and its default Subnet"
			check_if_vpc_exists $USER_VPC_ID

		else
		### If user_vpc_id provided and user_subnet_id Provided, It will take the provided VPC ID and provided Subnet
			echo "INFO ::: user_vpc_id and user_subnet_id Provided in the user Secret, Provisioning will be done in the Provided VPC $USER_VPC_ID and Subnet $USER_SUBNET_ID"
			# check_if_subnet_exists $USER_SUBNET_ID
			check_if_subnet_exists $USER_SUBNET_ID $USER_VPC_ID

		fi
	fi
	echo "INFO ::: NAC Scheduler Instance is not present. Creating new EC2 machine."
	########## Download NAC Scheduler Instance Provisioning Code from GitHub ##########
	### GITHUB_ORGANIZATION defaults to nasuni-labs
	REPO_FOLDER="nasuni-analyticsconnector-manager"
	validate_github $GITHUB_ORGANIZATION $REPO_FOLDER 
	GIT_REPO_NAME=$(echo ${GIT_REPO} | sed 's/.*\/\([^ ]*\/[^.]*\).*/\1/' | cut -d "/" -f 2)
	echo "INFO ::: Begin - Git Clone to ${GIT_REPO} -b $GIT_BRANCH"
	echo "INFO ::: $GIT_REPO"
	echo "INFO ::: GIT_REPO_NAME - $GIT_REPO_NAME"
	current_folder
	# ls
	rm -rf "${GIT_REPO_NAME}"
	COMMAND="git clone -b $GIT_BRANCH ${GIT_REPO}"
	$COMMAND
	# exit 88888
	RESULT=$?
	if [ $RESULT -eq 0 ]; then
		echo "INFO ::: git clone SUCCESS for repo ::: $GIT_REPO_NAME"
		cd "${GIT_REPO_NAME}"
	elif [ $RESULT -eq 128 ]; then
		cd "${GIT_REPO_NAME}"
		echo "$GIT_REPO_NAME"
		COMMAND="git pull origin $GIT_BRANCH"
		$COMMAND
	fi
	### Download Provisioning Code from GitHub completed
	echo "INFO ::: NAC Scheduler EC2 provisioning ::: BEGIN - Executing ::: Terraform init . . . . . . . . "
	COMMAND="terraform init"
	$COMMAND
	echo "INFO ::: NAC Scheduler EC2 provisioning ::: FINISH - Executing ::: Terraform init."
	echo "INFO ::: NAC Scheduler EC2 provisioning ::: BEGIN - Executing ::: Terraform apply . . . . . . . . . . . . . . . . . . ."
	### Create .tfvars file to be used by the NACScheduler Instance Provisioning
	current_folder
	TFVARS_NAC_SCHEDULER="NACScheduler.tfvars"
	rm -rf "$TFVARS_NAC_SCHEDULER" 
    AWS_KEY=$(echo ${PEM_KEY_PATH} | sed 's/.*\/\([^ ]*\/[^.]*\).*/\1/' | cut -d "/" -f 2)
	# echo $AWS_KEY
	PEM="$AWS_KEY.pem"
	### Copy the Pem Key from provided path to current folder
	cp $PEM_KEY_PATH ./
	chmod 400 $PEM
	echo "aws_profile="\"$AWS_PROFILE\" >>$TFVARS_NAC_SCHEDULER
	echo "region="\"$AWS_REGION\" >>$TFVARS_NAC_SCHEDULER
	echo "nac_es_securitygroup_id="\"$NAC_ES_SECURITYGROUP_ID\" >>$TFVARS_NAC_SCHEDULER
	if [[ "$NAC_SCHEDULER_NAME" != "" ]]; then
		echo "nac_scheduler_name="\"$NAC_SCHEDULER_NAME\" >>$TFVARS_NAC_SCHEDULER
		### Create entries about the Pem Key in the TFVARS File
		echo "pem_key_file="\"$PEM\" >>$TFVARS_NAC_SCHEDULER
		echo "aws_key="\"$AWS_KEY\" >>$TFVARS_NAC_SCHEDULER
	fi
	echo "github_organization="\"$GITHUB_ORGANIZATION\" >>$TFVARS_NAC_SCHEDULER
	echo "git_branch="\"$GIT_BRANCH\" >>$TFVARS_NAC_SCHEDULER
	if [[ "$VPC_IS" != "" ]]; then
		echo "user_vpc_id="\"$VPC_IS\" >>$TFVARS_NAC_SCHEDULER
	fi
	if [[ "$SUBNET_IS" != "" ]]; then
		echo "user_subnet_id="\"$SUBNET_IS\" >>$TFVARS_NAC_SCHEDULER
	fi
	if [[ "$AZ_IS" != "" ]]; then
		echo "subnet_availability_zone="\"$AZ_IS\" >>$TFVARS_NAC_SCHEDULER
	fi
	if [[ "$USE_PRIVATE_IP" != "" ]]; then
		echo "use_private_ip="\"$USE_PRIVATE_IP\" >>$TFVARS_NAC_SCHEDULER
	fi
	echo "$TFVARS_NAC_SCHEDULER created"
	echo `cat $TFVARS_NAC_SCHEDULER`

	dos2unix $TFVARS_NAC_SCHEDULER
	COMMAND="terraform apply -var-file=$TFVARS_NAC_SCHEDULER -auto-approve"
	$COMMAND
	if [ $? -eq 0 ]; then
		echo "INFO ::: NAC Scheduler EC2 provisioning ::: FINISH - Executing ::: Terraform apply ::: SUCCESS."
	else
		echo "ERROR ::: NAC Scheduler EC2 provisioning ::: FINISH - Executing ::: Terraform apply ::: FAILED."
		exit 1
	fi
	ip=$(cat NACScheduler_IP.txt)
	NAC_SCHEDULER_IP_ADDR=$ip
	echo 'INFO ::: New pubilc IP just created:-'$ip
	current_folder
	cd ../
	current_folder
	## Call this function to add Local public IP to Security group of NAC_SCHEDULER IP
	add_ip_to_sec_grp ${NAC_SCHEDULER_IP_ADDR}
	## nmc endpoint accessibility $NAC_SCHEDULER_NAME $NAC_SCHEDULER_IP_ADDR
	nmc_endpoint_accessibility  $NAC_SCHEDULER_NAME ${NAC_SCHEDULER_IP_ADDR} $NMC_API_ENDPOINT $NMC_API_USERNAME $NMC_API_PASSWORD #458
	Schedule_CRON_JOB $NAC_SCHEDULER_IP_ADDR
	## Setup_Search_Lambda
	## Setup_Search_UI

fi

END=$(date +%s)
secs=$((END - START))
DIFF=$(printf '%02dh:%02dm:%02ds\n' $((secs / 3600)) $((secs % 3600 / 60)) $((secs % 60)))
echo "INFO ::: Total execution Time ::: $DIFF !!!"
#exit 0
