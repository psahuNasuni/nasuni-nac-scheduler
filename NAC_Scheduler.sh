#!/bin/bash

##############################################
## Pre-Requisite(S):						##
## 		- Git, aws CLI, JQ 					##
##		- AWS Profile Setup as nasuni		##
##############################################

validate_kvp()
{
	key="$1"
	val="$2"
	if [[ $val == "" ]]; then
		echo "INFO ::: Empty Value provided. Please provide a valid value for ${key}."
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
	echo "SECRET_KEY ::: $SECRET_KEY"
	SECRET_VALUE=""
	if [ "$SECRET_KEY" == "nmc_api_username" ];then
		SECRET_VALUE=$(aws secretsmanager get-secret-value --secret-id "$SECRET_NAME" --region "${AWS_REGION}"  --profile "${AWS_PROFILE}" | jq -r '.SecretString' | jq -r '.nmc_api_username')
	elif [ "$SECRET_KEY" == "nmc_api_password" ];then
		SECRET_VALUE=$(aws secretsmanager get-secret-value --secret-id "$SECRET_NAME" --region "${AWS_REGION}"  --profile "${AWS_PROFILE}" | jq -r '.SecretString' | jq -r '.nmc_api_password')
	elif [ "$SECRET_KEY" == "nac_product_key" ];then
		SECRET_VALUE=$(aws secretsmanager get-secret-value --secret-id "$SECRET_NAME" --region "${AWS_REGION}"  --profile "${AWS_PROFILE}" | jq -r '.SecretString' | jq -r '.nac_product_key')
	elif [ "$SECRET_KEY" == "nmc_api_endpoint" ];then
		SECRET_VALUE=$(aws secretsmanager get-secret-value --secret-id "$SECRET_NAME" --region "${AWS_REGION}"  --profile "${AWS_PROFILE}" | jq -r '.SecretString' | jq -r '.nmc_api_endpoint')
	elif [ "$SECRET_KEY" == "web_access_appliance_address" ];then
		SECRET_VALUE=$(aws secretsmanager get-secret-value --secret-id "$SECRET_NAME" --region "${AWS_REGION}"  --profile "${AWS_PROFILE}" | jq -r '.SecretString' | jq -r '.web_access_appliance_address')
	elif [ "$SECRET_KEY" == "destination_bucket" ];then
		SECRET_VALUE=$(aws secretsmanager get-secret-value --secret-id "$SECRET_NAME" --region "${AWS_REGION}"  --profile "${AWS_PROFILE}" | jq -r '.SecretString' | jq -r '.destination_bucket')
	elif [ "$SECRET_KEY" == "volume_key" ];then
		SECRET_VALUE=$(aws secretsmanager get-secret-value --secret-id "$SECRET_NAME" --region "${AWS_REGION}"  --profile "${AWS_PROFILE}" | jq -r '.SecretString' | jq -r '.volume_key')
	# elif [ "$SECRET_KEY" == "volume_keyZ" ];then   ## Testing Negative flow
	# 	SECRET_VALUE=$(aws secretsmanager get-secret-value --secret-id "$SECRET_NAME" --region "${AWS_REGION}"  --profile "${AWS_PROFILE}" | jq -r '.SecretString' | jq -r '.volume_keyZ')
	fi
	# echo "SECRET_VALUE :::::::::::::::::::::::::: $SECRET_VALUE"
	if [ -n "$SECRET_VALUE" ]; then
		echo "SEC ::: $SECRET_NAME ::: $SECRET_KEY ::: $SECRET_VALUE"
	else   # NOT WORKING - It should go to else part when  SECRET_VALUE is null
		echo "ERROR ::: Secret Key $SECRET_KEY Does not Exist."
		echo "ERROR ::: Invalid value for Key $SECRET_KEY."
		exit 1
	fi

}
parse_textfile_for_keys_values() {
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
    esac
  done < "$file"
}
AWS_PROFILE="nasuni"
AWS_REGION=""
AWS_ACCESS_KEY_ID=""
AWS_SECRET_ACCESS_KEY=""
######################## Validating AWS profile for NAC ####################################
validate_aws_profile() {
	echo "INFO ::: Validating AWS profile for NAC  . . . . . . . . . . . . . . . . !!!"

	if [[ "$(grep '^[[]profile' <~/.aws/config | awk '{print $2}' | sed 's/]$//' | grep "${AWS_PROFILE}")" == "" ]]; then
		echo "ERROR ::: AWS profile ${AWS_PROFILE} does not exists. To Create AWS PROFILE, Run cli command - aws configure "
		exit 1
	else   # AWS Profile nasuni available in local machine
		AWS_ACCESS_KEY_ID=$(aws configure get aws_access_key_id --profile ${AWS_PROFILE})
		AWS_SECRET_ACCESS_KEY=$(aws configure get aws_secret_access_key --profile ${AWS_PROFILE})
		AWS_REGION=$(aws configure get region --profile ${AWS_PROFILE})
	fi

	echo "INFO ::: AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID"
	echo "INFO ::: AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY"
	echo "INFO ::: AWS_REGION=$AWS_REGION"
	echo "INFO ::: NMC_VOLUME_NAME=$NMC_VOLUME_NAME"
	echo "INFO ::: AWS profile Validation SUCCESS !!!"

}
#######################################################################################

if [ $# -eq 0 ]; then
    echo "ERROR ::: No arguments supplied. This Script Takes 4 Mandatory Arguments 1) NMC Volume_Name, 2) Service, 3) Frequency and 4) User Secret(either Existing Secret Name Or Secret KVPs in a text file)"
	exit 1
elif [ $# -lt 4 ]; then
    echo "ERROR ::: $# argument(s) supplied. This Script Takes 4 Mandatory Arguments 1) NMC Volume_Name, 2) Service, 3) Frequency and 4) User Secret(either Existing Secret Name Or Secret KVPs in a text file)"
	exit 1
fi
#################### Validate Arguments Passed to NAC_Scheduler.sh ####################
NMC_VOLUME_NAME="$1"  		### 1st argument  ::: NMC_VOLUME_NAME
ANALYTICS_SERVICE="$2"		### 2nd argument  ::: ANALYTICS_SERVICE
FREQUENCY="$3"     			### 3rd argument  ::: FREQUENCY
FOURTH_ARG="$4"  			### 4th argument  ::: User Secret a KVP file Or an existing Secret
echo "INFO ::: Validating Arguments Passed to NAC_Scheduler.sh"
if [ "${#NMC_VOLUME_NAME}" -lt 3 ]
then 
	echo "INFO ::: Something went wrong. Please re-check 1st argument and provide a valid NMC Volume Name."
	exit 1
fi
if [[ "${#ANALYTICS_SERVICE}" -lt 2 ]]; then  
	echo "INFO ::: The length of Service name provided as 2nd argument is too small, So, It will consider ES as the default Analytics Service."
	ANALYTICS_SERVICE="ES"    # ElasticSearch Service as default
fi
if [[ "${#FREQUENCY}" -lt 2  ]]; then  
	echo "INFO ::: Mandatory 3rd argument is invalid"
	exit 1
fi
### Validate aws_profile
validate_aws_profile
########## Check If fourth argument is provided 
USER_SECRET_EXISTS="N"
if [[ -n "$FOURTH_ARG" ]]; then  
########## Check If fourth argument is a file 
	if [ -f "$FOURTH_ARG" ]; then
		echo "INFO ::: Fourth argument is a File ${FOURTH_ARG}"

        # Parse the user data - KVP
        parse_textfile_for_keys_values "$FOURTH_ARG"
		#### Validate the user data file and the provided values 
		echo "INFO ::: Validating the user data file ${FOURTH_ARG} and the provided values" 
		validate_kvp nmc_api_username "${NMC_API_USERNAME}" 
		validate_kvp nmc_api_password "${NMC_API_PASSWORD}"
		validate_kvp nac_product_key "${NAC_PRODUCT_KEY}"
		validate_kvp nac_product_key "${NAC_PRODUCT_KEY}"
		validate_kvp nmc_api_endpoint "${NMC_API_ENDPOINT}"
		validate_kvp web_access_appliance_address "${WEB_ACCESS_APPLIANCE_ADDRESS}"
		# validate_kvp	volume_key "${VOLUME_KEY}"
		# validate_kvp	volume_key_passphrase "${VOLUME_KEY_PASSPHRASE}"
		validate_kvp destination_bucket "${DESTINATION_BUCKET}"
		
JSON_STRING=$(cat <<EOF
{
"nmc_api_username":"$NMC_API_USERNAME",
"nmc_api_password":"$NMC_API_PASSWORD",
"nac_product_key":"$NAC_PRODUCT_KEY",
"nmc_api_endpoint":"$NMC_API_ENDPOINT",
"web_access_appliance_address":
"$WEB_ACCESS_APPLIANCE_ADDRESS",
"volume_key":"$VOLUME_KEY",
"volume_key_passphrase":"$VOLUME_KEY_PASSPHRASE",
"destination_bucket":"$DESTINATION_BUCKET"
}
 
EOF
)
		# Create JSON Scring for User specific data
		echo "$JSON_STRING" | tr -d '\n' | tr -d '\r' > user_creds_"${NMC_VOLUME_NAME}"_"${ANALYTICS_SERVICE}".json


		# Create user Secret
		USER_SECRET="prod/nac/admin/$NMC_VOLUME_NAME/$ANALYTICS_SERVICE"
		aws secretsmanager create-secret --name "${USER_SECRET}" \
		--description "Preserving User specific data/secrets to be used for NAC Scheduling" \
		--secret-string file://user_creds_"${NMC_VOLUME_NAME}"_"${ANALYTICS_SERVICE}".json 
		rm -rf user_creds_"${NMC_VOLUME_NAME}"_"${ANALYTICS_SERVICE}".json
	else  ####  Fourth Argument $FOURTH_ARG is passed as User Secret Name
		echo "INFO ::: Fourth Argument $FOURTH_ARG is passed as User Secret Name"
		USER_SECRET="$FOURTH_ARG"
		
		# Verify the Secret Exists 
		if [[ -n $USER_SECRET ]]; then
			echo "USER SECRET:    $USER_SECRET"
			COMMAND="aws secretsmanager get-secret-value --secret-id ${USER_SECRET} --profile ${AWS_PROFILE} --region ${AWS_REGION}"
			$COMMAND
			if [[ $? -eq 0 ]]; then
				echo "INFO ::: Secret ${USER_SECRET} Exists. $?"
				USER_SECRET_EXISTS="Y"
			else
				echo "ERROR ::: $? :: Secret ${USER_SECRET} Does'nt Exist. OR, Invalid Secret name passed as 4th parameter"
				exit 0
			fi
		fi
		# exit 0
		if [ "$USER_SECRET_EXISTS" == "Y" ]; then
			# Validate Keys in the Secret 
			echo  "INFO ::: Check if all Keys are provided"
			#  SUMEET :: TBD :::::: :: Check if all Keys/Values are provided

			validate_secret_values "$USER_SECRET" nmc_api_username "$AWS_REGION" "$AWS_PROFILE" 
			validate_secret_values "$USER_SECRET" nmc_api_password "$AWS_REGION" "$AWS_PROFILE" 
			validate_secret_values "$USER_SECRET" nac_product_key "$AWS_REGION" "$AWS_PROFILE" 
			validate_secret_values "$USER_SECRET" nmc_api_endpoint "$AWS_REGION" "$AWS_PROFILE" 
			validate_secret_values "$USER_SECRET" web_access_appliance_address "$AWS_REGION" "$AWS_PROFILE" 
			validate_secret_values "$USER_SECRET" destination_bucket "$AWS_REGION" "$AWS_PROFILE" 
			validate_secret_values "$USER_SECRET" volume_key "$AWS_REGION" "$AWS_PROFILE" 
			validate_secret_values "$USER_SECRET" volume_keyZ "$AWS_REGION" "$AWS_PROFILE" 
			validate_secret_values "$USER_SECRET" volume_keyZ "$AWS_REGION" "$AWS_PROFILE" 
			# echo "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH"
			# exit 1
			# nmc_api_username	
			# nmc_api_password	
			# nac_product_key	
			# nmc_api_endpoint	
			# web_access_appliance_address	
			# destination_bucket
			# volume_key
		fi
	fi
else 
	echo "INFO ::: Fourth argument is NOT provided, So, It will consider prod/nac/admin as the default user secret."
fi

# exit 1

######################  NAC Scheduler Instance is Available ##############################
PUB_IP_ADDR=$(aws ec2 describe-instances --query "Reservations[*].Instances[*].{Name:Tags[?Key=='Name']|[0].Value,Status:State.Name,PublicIP:PublicIpAddress}" --filters "Name=tag:Name,Values='NACScheduler'" "Name=instance-state-name,Values=running" --region "${AWS_REGION}" | grep -e "PublicIP" |cut -d":" -f 2|tr -d '"'|tr -d ' ') 
echo "PUB_IP_ADDR ::: ${PUB_IP_ADDR}"


if [ "$PUB_IP_ADDR" != "" ];then 
	echo "INFO ::: NAC Scheduler Instance is Available. IP Address: $PUB_IP_ADDR"

	# Temporary Code Till alternative for PEM file is found
	if [[ ${AWS_REGION} == "us-east-2" ]]; then
		PEM="nac-manager.pem"
	elif [[ "${AWS_REGION}" == "us-east-1" ]]; then
		PEM="nac-manager-nv.pem"
	fi

	echo "INFO ::: Public IP Address:- $PUB_IP_ADDR"
	echo "ssh -i "$PEM" ubuntu@$PUB_IP_ADDR -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null"
	### Create TFVARS File
	CRON_DIR_NAME="${NMC_VOLUME_NAME}_${ANALYTICS_SERVICE}"
	TFVARS_FILE_NAME="${CRON_DIR_NAME}.tfvars"
	rm -rf "$TFVARS_FILE_NAME"
	echo "aws_profile="\"$AWS_PROFILE\" >> $TFVARS_FILE_NAME
	echo "region="\"$AWS_REGION\" >> $TFVARS_FILE_NAME
	echo "volume_name="\"$NMC_VOLUME_NAME\" >> $TFVARS_FILE_NAME
	echo "user_secret="\"$USER_SECRET\" >> $TFVARS_FILE_NAME

	### Create Directory for each Volume 
	# ssh -i "$PEM" ubuntu@"$PUB_IP_ADDR" -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null "[ ! -d $NMC_VOLUME_NAME ] && mkdir $NMC_VOLUME_NAME "
	ssh -i "$PEM" ubuntu@"$PUB_IP_ADDR" -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null "[ ! -d $CRON_DIR_NAME ] && mkdir $CRON_DIR_NAME "
	echo "11111111  Test message"
	### Copy TFVARS and provision_nac.sh to NACScheduler
	scp -i "$PEM" -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null provision_nac.sh "$TFVARS_FILE_NAME" ubuntu@$PUB_IP_ADDR:~/$CRON_DIR_NAME
	
	#dos2unix command execute
	ssh -i "$PEM" ubuntu@"$PUB_IP_ADDR" -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null "dos2unix ~/$CRON_DIR_NAME/provision_nac.sh"
	### Check If CRON JOB is running for a specific VOLUME_NAME
	CRON_VOL=$(ssh -i "$PEM" -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null ubuntu@"$PUB_IP_ADDR" "crontab -l |grep /home/ubuntu/$CRON_DIR_NAME/$TFVARS_FILE_NAME")
	#*/2 * * * * sh /home/ubuntu/file.sh SA-ES-VOL
	if [ "$CRON_VOL" != "" ]
	then
		### DO Nothing. CRON JOB takes care of NAC Provisioning
		echo "INFO ::: crontab does not require volume entry.As it is already present.:::::"
	else
		### Set up a new CRON JOB for NAC Provisioning

		echo "INFO ::: Setting CRON JOB for $CRON_DIR_NAME as it is not present"
			
		ssh -i "$PEM" ubuntu@$PUB_IP_ADDR -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null "(crontab -l ; echo '*/45 * * * * sh ~/$CRON_DIR_NAME/provision_nac.sh  ~/$CRON_DIR_NAME/$TFVARS_FILE_NAME >> ~/$CRON_DIR_NAME/cronlog.log') | sort - | uniq - | crontab -"
		if [ $? -eq 0 ]; then
			echo "INFO ::: CRON JOB Scheduled for NMC VOLUME and Service :: $CRON_DIR_NAME"
			exit 0
		else
			echo "ERROR ::: FAILED to Schedule CRON JOB for NMC VOLUME and Service :: $CRON_DIR_NAME"
			exit 1
		fi
	fi
	
exit 1
###################### NAC Scheduler EC2 Instance is NOT Available ##############################
else 
	## "NAC Scheduler is not present. Creating new EC2 machine."
	exit 1
	echo "INFO ::: NAC Scheduler Instance is not present. Creating new EC2 machine."
    ### Download Provisioning Code from GitHub
    GIT_REPO="https://github.com/psahuNasuni/prov_nacmanager.git"
    GIT_REPO_NAME=$(echo ${GIT_REPO} | sed 's/.*\/\([^ ]*\/[^.]*\).*/\1/' | cut -d "/" -f 2)
	echo "INFO ::: Start - Git Clone to ${GIT_REPO}"
    echo "$GIT_REPO"
    echo "GIT_REPO_NAME $GIT_REPO_NAME"
    pwd 
    ls
    rm -rf "${GIT_REPO_NAME}"
    COMMAND="git clone -b main ${GIT_REPO}"
    $COMMAND
    RESULT=$?
    if [ $RESULT -eq 0 ]; then
        echo "INFO ::: git clone SUCCESS"
        cd "${GIT_REPO_NAME}"
    elif [ $RESULT -eq 128 ]; then    
        cd "${GIT_REPO_NAME}"
        echo "$GIT_REPO_NAME"
        COMMAND="git pull origin main"
        $COMMAND
	fi
	### Download Provisioning Code from GitHub completed
	echo "INFO ::: NAC Scheduler EC2 PROVISIONING ::: STARTED ::: Executing the Terraform scripts . . . . . . . . . . . ."
    COMMAND="terraform init"
    $COMMAND
	echo "INFO ::: NAC Scheduler EC2 PROVISIONING ::: Initialized Terraform Libraries/Dependencies"
    echo "INFO ::: NAC Scheduler EC2 PROVISIONING ::: STARTED ::: Terraform apply . . . . . . . . . . . . . . . . . . ."
	##update dev.tfvars file to pass region as AWS_REGION sed --task 
	pwd
	sed 's/us-east-2/'${AWS_REGION}'/g' dev.tfvars >temp.txt
	rm -f dev.tfvars
	mv temp.txt dev.tfvars
	
    COMMAND="terraform apply -var-file=dev.tfvars -auto-approve"
    $COMMAND
    if [ $? -eq 0 ]; then
        echo "INFO ::: NAC Scheduler EC2 PROVISIONING ::: Terraform apply ::: COMPLETED . . . . . . . . . . . . . . . . . . ."
	else
		echo "INFO ::: NAC Scheduler EC2 PROVISIONING ::: Terraform apply ::: FAILED."
		exit 1
	fi
	ip=`cat NACScheduler_IP.txt`
	echo 'New pubilc IP just created:-'$ip
	pwd
	cd ../
	pwd
	ssh -i "$1" ubuntu@$ip 'sh install_req_pkgs.sh'
fi



Download_git_code(){
	echo "INFO ::: Start - Git Clone "
    ### Download Provisioning Code from GitHub
    GIT_REPO="$1"
    GIT_REPO_NAME=$(echo ${GIT_REPO} | sed 's/.*\/\([^ ]*\/[^.]*\).*/\1/' | cut -d "/" -f 2)
    echo "INFO ::: GIT_REPO $GIT_REPO"
    echo "INFO ::: GIT_REPO_NAME $GIT_REPO_NAME"
    pwd
    ls
    rm -rf "${GIT_REPO_NAME}"
    COMMAND="git clone -b main ${GIT_REPO}"
    $COMMAND
    RESULT=$?
    if [ $RESULT -eq 0 ]; then
        echo "INFO ::: git clone SUCCESS"
        cd "${GIT_REPO_NAME}"
    elif [ $RESULT -eq 128 ]; then    
        cd "${GIT_REPO_NAME}"
        COMMAND="git pull origin main"
        $COMMAND
	fi


}

