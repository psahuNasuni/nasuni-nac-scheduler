#!/bin/bash

##############################################
## Pre-Requisite(S):						##
## 		- Git, AWS CLI, JQ 					##
##		- AWS Profile Setup as nasuni		##
##############################################
DATE_WITH_TIME=$(date "+%Y%m%d-%H%M%S")
START=$(date +%s)

#CTPROJECT-169
NMC_ENDPOINT_ACCESSIBILITY() {
	# NMC_ENDPOINT_ACCESSIBILITY $NAC_SCHEDULER_NAME $PUB_IP_ADDR_NAC_SCHEDULER #$PEM
	NAC_SCHEDULER_NAME="$1"
	PUB_IP_ADDR_NAC_SCHEDULER="$2"
	# exit 0
	# PEM="$3"
	#SSA
    NMC_API_ENDPOINT="$3"
	NMC_API_USERNAME="$4"
	NMC_API_PASSWORD="$5" #14-19

	if [[ ${AWS_REGION} == "us-east-2" ]]; then
		PEM="nac-manager.pem"
	elif [[ "${AWS_REGION}" == "us-east-1" ]]; then
		PEM="nac-manager-nv.pem"
	fi
	chmod 400 $PEM
	# nac_scheduler_name = from FourthArgument of NAC_Scheduler.sh, user_sec.txt
	# parse_textfile_for_user_secret_keys_values user_sec.txt
	echo "Inside NMC_ENDPOINT_ACCESSIBILITY"
	echo "INFO ::: NAC_SCHEDULER_NAME ::: ${NAC_SCHEDULER_NAME}"
	echo "INFO ::: PUB_IP_ADDR_NAC_SCHEDULER ::: ${PUB_IP_ADDR_NAC_SCHEDULER}"
	echo "INFO ::: PEM ::: ${PEM}"
	echo "INFO ::: NMC_API_ENDPOINT ::: ${NMC_API_ENDPOINT}"
	echo "INFO ::: NMC_API_USERNAME ::: ${NMC_API_USERNAME}"
	echo "INFO ::: NMC_API_PASSWORD ::: ${NMC_API_PASSWORD}" # 31-37

	echo "PUB_IP_ADDR_NAC_SCHEDULER :"$PUB_IP_ADDR_NAC_SCHEDULER
	py_file_name=$(ls check_nmc_visiblity.py)
	echo "Python File Name-"$py_file_name
	cat $py_file_name | ssh -i "$PEM" ubuntu@$PUB_IP_ADDR_NAC_SCHEDULER -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null python3 - $NMC_API_USERNAME $NMC_API_PASSWORD $NMC_API_ENDPOINT
	if [ $? -eq 0 ]; then
		echo "NAC Scheduler with IP : ${PUB_IP_ADDR_NAC_SCHEDULER}, have access to NMC API ${NMC_API_ENDPOINT} "
	else
		echo "NAC Scheduler with IP : ${PUB_IP_ADDR_NAC_SCHEDULER}, Does NOT have access to NMC API ${NMC_API_ENDPOINT}. Please configure access to NMC "
		exit 1
	fi
	echo "Completed NMC_ENDPOINT_ACCESSIBILITY Exitting"

}
parse_4thArgument_for_nac_scheduler_name() {
	file="$1"
	if [ -f "$file" ]; then
		dos2unix $file
		while IFS="=" read -r key value; do
			case "$key" in
			"nac_scheduler_name") NAC_SCHEDULER_NAME="$value" ;;
			esac
		done <"$file"
	else
		SECRET_NAME="$file"
		SECRET_STRING=$(aws secretsmanager get-secret-value --secret-id "$SECRET_NAME" --region "${AWS_REGION}" --profile "${AWS_PROFILE}")

		NAC_SCHEDULER_NAME=$(echo $SECRET_STRING | jq -r '.SecretString' | jq -r '.nac_scheduler_name')
		NMC_API_USERNAME=$(echo $SECRET_STRING  | jq -r '.SecretString' | jq -r '.nmc_api_username')
		NMC_API_PASSWORD=$(echo $SECRET_STRING  | jq -r '.SecretString' | jq -r '.nmc_api_password')
		NMC_API_ENDPOINT=$(echo $SECRET_STRING  | jq -r '.SecretString' | jq -r '.nmc_api_endpoint')
		
		echo "nac_scheduler_name=$NAC_SCHEDULER_NAME :: nmc_api_username=$NMC_API_USERNAME :: nmc_api_password=$NMC_API_PASSWORD :: nmc_api_endpoint=$NMC_API_ENDPOINT"
	fi
}

append_nac_keys_values_to_tfvars() {
	inputFile="$1" ### Read InputFile
	outFile="$2"
	dos2unix $inputFile
	echo "inputFile ::: $inputFile"
	echo "outFile ::: $outFile"
	# echo " " >> $outFile
	while IFS="=" read -r key value; do
		echo "$key ::: $value "
		if [ ${#key} -ne 0 ]; then
			echo "$key=$value" >>$outFile
		fi
	done <"$inputFile"
}

check_if_secret_exists() {
	USER_SECRET="$1"
	AWS_PROFILE="$2"
	AWS_REGION="$3"
	# Verify the Secret Exists
	if [[ -n $USER_SECRET ]]; then
		# echo "USER SECRET:    $USER_SECRET"
		COMMAND="aws secretsmanager get-secret-value --secret-id ${USER_SECRET} --profile ${AWS_PROFILE} --region ${AWS_REGION}"
		$COMMAND
		RES=$?
		#  echo "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  $RES"
		if [[ $RES -eq 0 ]]; then
			# echo "INFO ::: Secret ${USER_SECRET} Exists. $RES"
			echo "Y"
		else
			# echo "ERROR ::: $RES :: Secret ${USER_SECRET} Does'nt Exist in ${AWS_REGION} region. OR, Invalid Secret name passed as 4th parameter"
			echo "N"
			# exit 0
		fi
		

	fi
}

validate_kvp() {
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
	fi
	if [ -n "$SECRET_VALUE" ]; then
		echo "SEC ::: $SECRET_NAME ::: $SECRET_KEY ::: $SECRET_VALUE"
	else # NOT WORKING - It should go to else part when  SECRET_VALUE is null
		echo "ERROR ::: Secret Key $SECRET_KEY Does not Exist."
		echo "ERROR ::: Invalid value for Key $SECRET_KEY."
		exit 1
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
		esac
	done <"$file"
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
	echo "NAC_SCHEDULER_PUB_IP_ADDR add_ip_to_sec_grp ${NAC_SCHEDULER_IP_ADDR}"
	echo $(curl checkip.amazonaws.com) >test.txt

	LOCAL_IP=$(cat test.txt)

	echo "Public IP of the local machine is ${LOCAL_IP}"
	NEW_CIDR="${LOCAL_IP}"/32
	echo "NEW_CIDR :- ${NEW_CIDR}"
	#Get NAC Manager IP

	# NAC_SCHEDULER_PUB_IP_ADDR=$(aws ec2 describe-instances --query "Reservations[].Instances[].{Name:Tags[?Key=='Name']|[0].Value,Status:State.Name,PublicIP:PublicIpAddress}" --filters "Name=tag:Name,Values='NACScheduler'" "Name=instance-state-name,Values=running" --region us-east-2 --profile nasuni | grep -e "PublicIP" |cut -d":" -f 2|tr -d '"'|tr -d ' ')
	# echo "NAC_SCHEDULER_IP_ADDR ::: ${NAC_SCHEDULER_IP_ADDR}"
	#SecGrp=$(aws ec2 describe-instances --query "Reservations[].Instances[].{Name:Tags[?Key=='Name']|[0].Value,Status:State.Name,PublicIP:PublicIpAddress,SecGrp:GroupId}" --filters "Name=tag:Name,Values='NACScheduler'" "Name=instance-state-name,Values=running" --region us-east-2 --profile nasuni | grep -e "SecGrp" |cut -d":" -f 2|tr -d '"'|tr -d ' ')
	if [ "$NAC_SCHEDULER_NAME" != "" ]; then
		#PUB_IP_ADDR_NAC_SCHEDULER=$(aws ec2 describe-instances --query "Reservations[*].Instances[*].{Name:Tags[?Key=='Name']|[0].Value,Status:State.Name,PublicIP:PublicIpAddress}" --filters "Name=tag:Name,Values='$NAC_SCHEDULER_NAME'" "Name=instance-state-name,Values=running" --region "${AWS_REGION}" | grep -e "PublicIP" |cut -d":" -f 2|tr -d '"'|tr -d ' ')
		SECURITY_GROUP_ID=$(aws ec2 describe-instances --query "Reservations[].Instances[].{Name:Tags[?Key=='Name']|[0].Value,Status:State.Name,PublicIP:PublicIpAddress,SecurityGroups:SecurityGroups[*]}" --filters "Name=tag:Name,Values='$NAC_SCHEDULER_NAME'" "Name=instance-state-name,Values=running" --region us-east-2 --profile nasuni | grep -e "GroupId" | cut -d":" -f 2 | tr -d '"')
		echo "Security group of $NAC_SCHEDULER_NAME is ${SECURITY_GROUP_ID}"
	else
		echo "NAC_Schedluer is present .So fetch its sec group."
		SECURITY_GROUP_ID=$(aws ec2 describe-instances --query "Reservations[].Instances[].{Name:Tags[?Key=='Name']|[0].Value,Status:State.Name,PublicIP:PublicIpAddress,SecurityGroups:SecurityGroups[*]}" --filters "Name=tag:Name,Values='NACScheduler'" "Name=instance-state-name,Values=running" --region us-east-2 --profile nasuni | grep -e "GroupId" | cut -d":" -f 2 | tr -d '"')
		echo "Security group of NACScheduler is ${SECURITY_GROUP_ID}"
	fi
	# SECURITY_GROUP_ID=`aws ec2 describe-instances --query "Reservations[].Instances[].{Name:Tags[?Key=='Name']|[0].Value,Status:State.Name,PublicIP:PublicIpAddress,SecurityGroups:SecurityGroups[*]}" --filters "Name=tag:Name,Values='NACScheduler'" "Name=instance-state-name,Values=running" --region us-east-2 --profile nasuni |grep -e "GroupId" |cut -d":" -f 2|tr -d '"'`
	echo "Security group of NACScheduler is ${SECURITY_GROUP_ID}"

	#If OS name is windows
	#status= $(aws ec2 authorize-security-group-ingress --group-id ${SECURITY_GROUP_NAME} --protocol tcp --port 22 --cidr ${NEW_CIDR})
	status=$(aws ec2 authorize-security-group-ingress --group-id ${SECURITY_GROUP_ID} --protocol tcp --port 22 --cidr ${NEW_CIDR} 2>/dev/null)
	# aws ec2 authorize-security-group-ingress --group-name sg-a3204ac8 --protocol tcp --port 22 --cidr 103.168.202.24/24
	if [ $? -eq 0 ]; then
		echo "${NEW_CIDR}  updateed to Security Group ${SECURITY_GROUP_ID}"
	else
		echo ${NEW_CIDR} already available to Security Group ${SECURITY_GROUP_ID}
		# echo "FAIL"
	fi

}

AWS_PROFILE="nasuni"
AWS_REGION=""
AWS_ACCESS_KEY_ID=""
AWS_SECRET_ACCESS_KEY=""
ARG_COUNT="$#"
######################## Validating AWS profile for NAC ####################################
validate_aws_profile() {
	echo "INFO ::: Validating AWS profile for NAC  . . . . . . . . . . . . . . . . !!!"

	if [[ "$(grep '^[[]profile' <~/.aws/config | awk '{print $2}' | sed 's/]$//' | grep "${AWS_PROFILE}")" == "" ]]; then
		echo "ERROR ::: AWS profile ${AWS_PROFILE} does not exists. To Create AWS PROFILE, Run cli command - aws configure "
		exit 1
	else # AWS Profile nasuni available in local machine
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
########################## Create CRON ############################################################
Schedule_CRON_JOB() {
	NAC_SCHEDULER_IP_ADDR=$1
	# Temporary Code Till alternative for PEM file is found
	if [[ ${AWS_REGION} == "us-east-2" ]]; then
		PEM="nac-manager.pem"
	elif [[ "${AWS_REGION}" == "us-east-1" ]]; then
		PEM="nac-manager-nv.pem"
	fi

	chmod 400 $PEM

	echo "INFO ::: Public IP Address:- $NAC_SCHEDULER_IP_ADDR"
	echo "ssh -i "$PEM" ubuntu@$NAC_SCHEDULER_IP_ADDR -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null"
	### Create TFVARS File
	CRON_DIR_NAME="${NMC_VOLUME_NAME}_${ANALYTICS_SERVICE}"
	TFVARS_FILE_NAME="${CRON_DIR_NAME}.tfvars"
	rm -rf "$TFVARS_FILE_NAME"
	echo "aws_profile="\"$AWS_PROFILE\" >>$TFVARS_FILE_NAME
	echo "region="\"$AWS_REGION\" >>$TFVARS_FILE_NAME
	echo "volume_name="\"$NMC_VOLUME_NAME\" >>$TFVARS_FILE_NAME
	echo "user_secret="\"$USER_SECRET\" >>$TFVARS_FILE_NAME
	if [ $ARG_COUNT -eq 5 ]; then
		echo "INFO ::: $ARG_COUNT th Argument is supplied as ::: $NAC_INPUT_KVP"
		append_nac_keys_values_to_tfvars $NAC_INPUT_KVP $TFVARS_FILE_NAME
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
	CRON_VOL=$(ssh -i "$PEM" -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null ubuntu@"$NAC_SCHEDULER_IP_ADDR" "crontab -l |grep /home/ubuntu/$CRON_DIR_NAME/$TFVARS_FILE_NAME")
	if [ "$CRON_VOL" != "" ]; then
		### DO Nothing. CRON JOB takes care of NAC Provisioning
		echo "INFO ::: crontab does not require volume entry.As it is already present.:::::"
	else
		### Set up a new CRON JOB for NAC Provisioning

		echo "INFO ::: Setting CRON JOB for $CRON_DIR_NAME as it is not present"
		ssh -i "$PEM" ubuntu@$NAC_SCHEDULER_IP_ADDR -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null "(crontab -l ; echo '*/$FREQUENCY * * * * sh ~/$CRON_DIR_NAME/provision_nac.sh  ~/$CRON_DIR_NAME/$TFVARS_FILE_NAME >> ~/$CRON_DIR_NAME/CRON_log-$CRON_DIR_NAME-$DATE_WITH_TIME.log') | sort - | uniq - | crontab -"
		if [ $? -eq 0 ]; then
			echo "INFO ::: CRON JOB Scheduled for NMC VOLUME and Service :: $CRON_DIR_NAME"
			exit 0
		else
			echo "ERROR ::: FAILED to Schedule CRON JOB for NMC VOLUME and Service :: $CRON_DIR_NAME"
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
echo "INFO ::: Validating Arguments Passed to NAC_Scheduler.sh"
if [ "${#NMC_VOLUME_NAME}" -lt 3 ]; then
	echo "ERROR ::: Something went wrong. Please re-check 1st argument and provide a valid NMC Volume Name."
	exit 1
fi
if [[ "${#ANALYTICS_SERVICE}" -lt 2 ]]; then
	echo "INFO ::: The length of Service name provided as 2nd argument is too small, So, It will consider ES as the default Analytics Service."
	ANALYTICS_SERVICE="ES" # ElasticSearch Service as default
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

# echo "@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#"
# exit 1
### Validate aws_profile
validate_aws_profile
########## Check If fourth argument is provided
USER_SECRET_EXISTS="N"
if [[ -n "$FOURTH_ARG" ]]; then
	########## Check If fourth argument is a file
	if [ -f "$FOURTH_ARG" ]; then
		echo "INFO ::: Fourth argument is a File ${FOURTH_ARG}"

		# Parse the user data - KVP
		parse_textfile_for_user_secret_keys_values "$FOURTH_ARG"

		#### Validate the user data file and the provided values
		echo "INFO ::: Validating the user data file ${FOURTH_ARG} and the provided values"
		validate_kvp nmc_api_username "${NMC_API_USERNAME}"
		validate_kvp nmc_api_password "${NMC_API_PASSWORD}"
		validate_kvp nac_product_key "${NAC_PRODUCT_KEY}"
		validate_kvp nmc_api_endpoint "${NMC_API_ENDPOINT}"
		validate_kvp web_access_appliance_address "${WEB_ACCESS_APPLIANCE_ADDRESS}"
		validate_kvp destination_bucket "${DESTINATION_BUCKET}"
		# nac_scheduler_name   - Get the value -- If its not null / "" then NAC_SCHEDULER_NAME = ${nac_scheduler_name}
		create_JSON_from_Input_user_KVPfile $FOURTH_ARG >user_creds_"${NMC_VOLUME_NAME}"_"${ANALYTICS_SERVICE}".json
		#  echo "@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#"
		# exit 1
		# Formation of User Secret Name
		USER_SECRET="prod/nac/admin/$NMC_VOLUME_NAME/$ANALYTICS_SERVICE"
		# Verify the Secret Exists
		USER_SECRET_EXISTS=$(check_if_secret_exists $USER_SECRET $AWS_PROFILE $AWS_REGION)
		# echo "INFO ::: USER_SECRET_EXISTS ::: $USER_SECRET_EXISTS "
		if [ "$USER_SECRET_EXISTS" != "N" ]; then
			# echo "&&&&&&&&&&&&&&&&&&&&&&&&&& ::: $USER_SECRET_EXISTS "
			echo "INFO ::: Fourth argument is a File && the User Secret exists ==> User wants to Update the Secret Values"
			# Update Secret
			echo "INFO ::: Update Secret $USER_SECRET "
			# Update Secret
			aws secretsmanager update-secret --secret-id "${USER_SECRET}" \
			--secret-string file://user_creds_"${NMC_VOLUME_NAME}"_"${ANALYTICS_SERVICE}".json \
			--region "${AWS_REGION}"
			RES="$?"
			if [ $RES -ne 0 ]; then
				echo "INFO ::: $RES Failed to Update Secret $USER_SECRET."
				exit 1
			elif [ $RES -eq 0 ]; then
				echo "INFO ::: Secret $USER_SECRET Updated SUCCESSFULLY"
			fi
		else
			## Fourth argument is a File && the User Secret Doesn't exist ==> User wants to Create a new Secret
			# echo "################################# ::: $USER_SECRET_EXISTS "
			# Create Secret
			echo "INFO ::: Create Secret $USER_SECRET"
			aws secretsmanager create-secret --name "${USER_SECRET}" \
			--description "Preserving User specific data/secrets to be used for NAC Scheduling" \
			--secret-string file://user_creds_"${NMC_VOLUME_NAME}"_"${ANALYTICS_SERVICE}".json \
			--region "${AWS_REGION}"
			RES="$?"
			if [ $RES -ne 0 ]; then
				echo "INFO ::: $RES Failed to Create Secret $USER_SECRET as, its already exists."
				exit 1
			elif [ $RES -eq 0 ]; then
				echo "INFO ::: Secret $USER_SECRET Created"
			fi
		fi
		rm -rf *"${NMC_VOLUME_NAME}"_"${ANALYTICS_SERVICE}".json
	else ####  Fourth Argument is passed as User Secret Name
		echo "INFO ::: Fourth Argument $FOURTH_ARG is passed as User Secret Name"
		USER_SECRET="$FOURTH_ARG"

		# Verify the Secret Exists
		USER_SECRET_EXISTS=$(check_if_secret_exists $USER_SECRET ${AWS_PROFILE} ${AWS_REGION} | jq -r .Name)
		# echo "INFOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO $USER_SECRET_EXISTS"
		if [ "${#USER_SECRET_EXISTS}" -gt 0 ]; then
		# if [ "$USER_SECRET_EXISTS" == "Y" ]; then
			# Validate Keys in the Secret
			echo "INFO ::: Check if all Keys are provided"
			validate_secret_values "$USER_SECRET" nmc_api_username "$AWS_REGION" "$AWS_PROFILE"
			validate_secret_values "$USER_SECRET" nmc_api_password "$AWS_REGION" "$AWS_PROFILE"
			validate_secret_values "$USER_SECRET" nac_product_key "$AWS_REGION" "$AWS_PROFILE"
			validate_secret_values "$USER_SECRET" nmc_api_endpoint "$AWS_REGION" "$AWS_PROFILE"
			validate_secret_values "$USER_SECRET" web_access_appliance_address "$AWS_REGION" "$AWS_PROFILE"
			validate_secret_values "$USER_SECRET" destination_bucket "$AWS_REGION" "$AWS_PROFILE"
			validate_secret_values "$USER_SECRET" volume_key "$AWS_REGION" "$AWS_PROFILE"
		fi
	fi
else
	echo "INFO ::: Fourth argument is NOT provided, So, It will consider prod/nac/admin as the default user secret."
fi

echo "INFO ::: Get IP Address of NAC Scheduler Instance"
######################  NAC Scheduler Instance is Available ##############################

NAC_SCHEDULER_NAME=""
# parse_textfile_for_nac_scheduler_name "$FOURTH_ARG"
parse_4thArgument_for_nac_scheduler_name "$FOURTH_ARG"
echo "nac_scheduler_name ========== $NAC_SCHEDULER_NAME "
if [ "$NAC_SCHEDULER_NAME" != "" ]; then
	### User has provided the NACScheduler Name as Key-Value from 4th Argument
	PUB_IP_ADDR_NAC_SCHEDULER=$(aws ec2 describe-instances --query "Reservations[*].Instances[*].{Name:Tags[?Key=='Name']|[0].Value,Status:State.Name,PublicIP:PublicIpAddress}" --filters "Name=tag:Name,Values='$NAC_SCHEDULER_NAME'" "Name=instance-state-name,Values=running" --region "${AWS_REGION}" | grep -e "PublicIP" | cut -d":" -f 2 | tr -d '"' | tr -d ' ')
else
	PUB_IP_ADDR_NAC_SCHEDULER=$(aws ec2 describe-instances --query "Reservations[*].Instances[*].{Name:Tags[?Key=='Name']|[0].Value,Status:State.Name,PublicIP:PublicIpAddress}" --filters "Name=tag:Name,Values='NACScheduler'" "Name=instance-state-name,Values=running" --region "${AWS_REGION}" | grep -e "PublicIP" | cut -d":" -f 2 | tr -d '"' | tr -d ' ')
fi

# PUB_IP_ADDR_NAC_SCHEDULER=3.144.254.220
echo "INFO ::: PUB_IP_ADDR_NAC_SCHEDULER ::: ${PUB_IP_ADDR_NAC_SCHEDULER}"
if [ "$PUB_IP_ADDR_NAC_SCHEDULER" != "" ]; then
	echo "INFO ::: NAC Scheduler Instance is Available. IP Address: $PUB_IP_ADDR_NAC_SCHEDULER"
	# Call this function to add Local public IP to Security group of NAC_SCHEDULER IP
	add_ip_to_sec_grp $PUB_IP_ADDR_NAC_SCHEDULER $NAC_SCHEDULER_NAME
	#CTPROJECT-169
	# NMC_ENDPOINT_ACCESSIBILITY $NAC_SCHEDULER_NAME $PUB_IP_ADDR_NAC_SCHEDULER
	NMC_ENDPOINT_ACCESSIBILITY $NAC_SCHEDULER_NAME $PUB_IP_ADDR_NAC_SCHEDULER $NMC_API_ENDPOINT $NMC_API_USERNAME $NMC_API_PASSWORD #458

	echo "exiting NMC_ENDPOINT_ACCESSIBILITY add_ip_to_sec_grp completed"
	# exit 1
	Schedule_CRON_JOB $PUB_IP_ADDR_NAC_SCHEDULER

###################### NAC Scheduler EC2 Instance is NOT Available ##############################
else
	## "NAC Scheduler is not present. Creating new EC2 machine."
	echo "INFO ::: NAC Scheduler Instance is not present. Creating new EC2 machine."
	# echo "&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&"
	# exit 1
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
	## Create .tfvars file to pass region as AWS_REGION sed --task
	pwd
	TFVARS_NAC_SCHEDULER="NACScheduler.tfvars"
	rm -rf "$TFVARS_NAC_SCHEDULER"
	echo "aws_profile="\"$AWS_PROFILE\" >>$TFVARS_NAC_SCHEDULER
	echo "region="\"$AWS_REGION\" >>$TFVARS_NAC_SCHEDULER
	if [[ "$NAC_SCHEDULER_NAME" != "" ]]; then
		echo "nac_scheduler_name="\"$NAC_SCHEDULER_NAME\" >>$TFVARS_NAC_SCHEDULER
	fi

	# dos2unix $TFVARS_NAC_SCHEDULER
	# exit 0
	COMMAND="terraform apply -var-file=$TFVARS_NAC_SCHEDULER -auto-approve"
	$COMMAND
	if [ $? -eq 0 ]; then
		echo "INFO ::: NAC Scheduler EC2 PROVISIONING ::: Terraform apply ::: COMPLETED . . . . . . . . . . . . . . . . . . ."
	else
		echo "INFO ::: NAC Scheduler EC2 PROVISIONING ::: Terraform apply ::: FAILED."
		exit 1
	fi
	# rm -rf "$TFVARS_NAC_SCHEDULER"
	ip=$(cat NACScheduler_IP.txt)
	NAC_SCHEDULER_IP_ADDR=$ip
	echo 'New pubilc IP just created:-'$ip
	pwd
	cd ../
	pwd
	# Call this function to add Local public IP to Security group of NAC_SCHEDULER IP
	add_ip_to_sec_grp ${NAC_SCHEDULER_IP_ADDR}
	#CTPROJECT-169
	#NMC_ENDPOINT_ACCESSIBILITY $NAC_SCHEDULER_NAME $PUB_IP_ADDR_NAC_SCHEDULER
	NMC_ENDPOINT_ACCESSIBILITY $NAC_SCHEDULER_NAME ${NAC_SCHEDULER_IP_ADDR} $NMC_API_ENDPOINT $NMC_API_USERNAME $NMC_API_PASSWORD #458
	Schedule_CRON_JOB $NAC_SCHEDULER_IP_ADDR
	# Setup_Search_Lambda
	# Setup_Search_UI

fi

END=$(date +%s)
secs=$((END - START))
DIFF=$(printf '%02dh:%02dm:%02ds\n' $((secs / 3600)) $((secs % 3600 / 60)) $((secs % 60)))
echo "INFO ::: Total execution Time ::: $DIFF"
#exit 0
