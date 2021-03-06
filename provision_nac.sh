#!/bin/bash
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
#############################################################################################
#### This Script Targets NAC Deployment from any Linux Box
#### Prequisites:
####       1- Software need to be Installed:
####             a- AWS CLI V2
####             b- Python 3
####             c- curl
####             d- git
####             e- jq
####             f- wget
####             e- Terraform V 1.0.7
####       2- AWS User Profile should be configured
####             a- If not configured run the command as below and provide correct values:
####                  aws configure --profile nasuni
####       3- NMC Volume
####       5- User Specific AWS UserSecret
####             a- User need to provide/Update valid values for below keys:
####
#############################################################################################
set -e

START=$(date +%s)
{
	TFVARS_FILE=$1
	read_TFVARS() {
		file="$TFVARS_FILE"
		while IFS="=" read -r key value; do
			case "$key" in
				"aws_profile") AWS_PROFILE="$value" ;;
				"region") AWS_REGION="$value" ;;
				"volume_name") NMC_VOLUME_NAME="$value" ;;
				"github_organization") GITHUB_ORGANIZATION="$value" ;;
				"user_vpc_id") USER_VPC_ID="$value" ;;
				"user_subnet_id") USER_SUBNET_ID="$value" ;;
				"use_private_ip") USE_PRIVATE_IP="$value" ;;
				"frequency") FREQUENCY="$value" ;;
				"nac_scheduler_name") NAC_SCHEDULER_NAME="$value" ;;
			esac
		done < "$file"
	}

generate_tracker_json(){
	echo "INFO ::: Updating TRACKER JSON ... "
	OS_URL=$1
	KIBANA_URL=$2
	DEFAULT_URL=$3
	FREQUENCY=$4
	USER_SECRET=$5
	CREATED_BY=$6
	CREATED_ON=$7
	TRACKER_NMC_VOLUME_NAME=$8
	ANALYTICS_SERVICE=$9
	MOST_RECENT_RUN=${10}
	CURRENT_STATE=${11}
	LATEST_TOC_HANDLE_PROCESSED=${12}
	NAC_SCHEDULER_NAME=$(echo "${13}" | tr -d '"')
	python3 /home/ubuntu/tracker_json.py $OS_URL $KIBANA_URL $DEFAULT_URL $FREQUENCY $USER_SECRET $CREATED_BY $CREATED_ON $TRACKER_NMC_VOLUME_NAME $ANALYTICS_SERVICE $MOST_RECENT_RUN $CURRENT_STATE $LATEST_TOC_HANDLE_PROCESSED $NAC_SCHEDULER_NAME
	echo "INFO ::: TRACKER JSON  Updated"
}

check_if_secret_exists() {
	USER_SECRET="$1"
	AWS_PROFILE="$2"
	AWS_REGION="$3"
	# Verify the Secret Exists
	if [[ -n $USER_SECRET ]]; then
		COMMAND=$(aws secretsmanager get-secret-value --secret-id ${USER_SECRET} --profile ${AWS_PROFILE} --region ${AWS_REGION})
		#$COMMAND ###SSA
		RES=$?
		if [[ $RES -eq 0 ]]; then
			### echo "INFO ::: Secret ${USER_SECRET} Exists. $RES"
			echo "Y"
		else
			### echo "ERROR ::: $RES :: Secret ${USER_SECRET} Does'nt Exist in ${AWS_REGION} region. OR, Invalid Secret name passed as 4th parameter"
			echo "N"
			# exit 0
		fi
	fi
}

validate_github() {
	GITHUB_ORGANIZATION=$1
	REPO_FOLDER=$2
	if [[ $GITHUB_ORGANIZATION == "" ]];then
		GITHUB_ORGANIZATION="nasuni-labs"
		echo "INFO ::: github_organization not provided as Secret Key-Value pair. So considering nasuni-labs as the default value !!!"
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

read_TFVARS "$TFVARS_FILE"

AWS_PROFILE=$(echo "$AWS_PROFILE" | tr -d '"')
AWS_REGION=$(echo "$AWS_REGION" | tr -d '"')
NMC_VOLUME_NAME=$(echo "$NMC_VOLUME_NAME" | tr -d '"')
GITHUB_ORGANIZATION=$(echo "$GITHUB_ORGANIZATION" | tr -d '"')
NAC_SCHEDULER_NAME=$(echo "$NAC_SCHEDULER_NAME" | tr -d '"')
echo NAC_SCHDULER_NAME $NAC_SCHEDULER_NAME
OS_ADMIIN_SECRET="nasuni-labs-os-admin"

######################## Check If ES Domain Available ###############################################
ES_DOMAIN_NAME=$(aws secretsmanager get-secret-value --secret-id $OS_ADMIIN_SECRET --region "${AWS_REGION}" --profile "${AWS_PROFILE}" | jq -r '.SecretString' | jq -r '.es_domain_name')
echo "INFO ::: ES_DOMAIN NAME : $ES_DOMAIN_NAME"
IS_ES="N"
if [ "$ES_DOMAIN_NAME" == "" ] || [ "$ES_DOMAIN_NAME" == null ]; then
	echo "ERROR ::: ElasticSearch Domain is Not provided in admin secret"
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
			echo "INFO ::: ElasticSearch Domain ::: $ES_DOMAIN_NAME is Active"
			IS_ES="Y"
		else
			echo "ERROR ::: ElasticSearch Domain ::: $ES_DOMAIN_NAME is either unavailable Or Not Active"
			IS_ES="N"
		fi
	else
		echo "ERROR ::: ElasticSearch Domain ::: $ES_DOMAIN_NAME not found"
		IS_ES="N"
	fi
fi

if [ "$IS_ES" == "N" ]; then
	echo "INFO ::: ElasticSearch Domain is Not Configured. Need to Provision ElasticSearch Domain Before, NAC Provisioning."
	echo "INFO ::: Begin ElasticSearch Domain Provisioning."
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
		echo "INFO ::: ES_ServiceLink_NAME NAME : $ES_ServiceLink_NAME"
		echo "INFO ::: OpenSearch ServiceLink Role already Available !!!"
	fi
	#####################################################################################################


   ########## Download ElasticSearch Provisioning Code from GitHub ##########
   ### GITHUB_ORGANIZATION defaults to nasuni-labs
   REPO_FOLDER="nasuni-awsopensearch"
   validate_github $GITHUB_ORGANIZATION $REPO_FOLDER
   ########################### Git Clone  ###############################################################
   echo "INFO ::: BEGIN - Git Clone !!!"
   ### Download Provisioning Code from GitHub
   GIT_REPO_NAME=$(echo ${GIT_REPO} | sed 's/.*\/\([^ ]*\/[^.]*\).*/nasuni-\1/' | cut -d "/" -f 2)
   echo "INFO ::: $GIT_REPO"
   echo "INFO ::: GIT_REPO_NAME $GIT_REPO_NAME"
   pwd
   ls
   echo "INFO ::: Removing ${GIT_REPO_NAME}"
   rm -rf "${GIT_REPO_NAME}"
   pwd
   COMMAND="git clone -b main ${GIT_REPO}"
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
   echo "INFO ::: ElasticSearch provisioning ::: BEGIN ::: Executing ::: Terraform init . . . . . . . . "
   COMMAND="terraform init"
   $COMMAND

    ##### RUN terraform Apply
    echo "INFO ::: ElasticSearch provisioning ::: BEGIN ::: Executing ::: Terraform apply . . . . . . . . . . . . . . . . . . ."
    #### Create TFVARS FILE FOR OS Provisioning
    echo USE_PRIVATE_IP $USE_PRIVATE_IP
    USE_PRIVATE_IP=$(echo $USE_PRIVATE_IP|tr -d '"')
    USER_SUBNET_ID=$(echo $USER_SUBNET_ID|tr -d '"')
    USER_VPC_ID=$(echo $USER_VPC_ID|tr -d '"')
    AWS_REGION=$(echo $AWS_REGION|tr -d '"')
    echo USE_PRIVATE_IP $USE_PRIVATE_IP
    if [[ "$USE_PRIVATE_IP" = Y ]]; then
	    OS_TFVARS="Os.tfvars"
	    echo "user_subnet_id="\"$USER_SUBNET_ID\" >$OS_TFVARS
	    echo "user_vpc_id="\"$USER_VPC_ID\" >>$OS_TFVARS
	    echo "use_private_ip="\"$USE_PRIVATE_IP\" >>$OS_TFVARS
	    echo "es_region="\"$AWS_REGION\" >>$OS_TFVARS
	    echo "" >>$OS_TFVARS
	    COMMAND="terraform apply -var-file=$OS_TFVARS -auto-approve"
	    $COMMAND
    else
	    chmod 755 $(pwd)/*
	    # exit 1
	    echo "INFO ::: ElasticSearch provisioning ::: FINISH - Executing ::: Terraform init."
	    ##### RUN terraform Apply
	    echo "INFO ::: ElasticSearch provisioning ::: BEGIN ::: Executing ::: Terraform apply . . . . . . . . . . . . . . . . . . ."
	    COMMAND="terraform apply -auto-approve"
	    $COMMAND
    fi

    if [ $? -eq 0 ]; then
	    echo "INFO ::: ElasticSearch provisioning ::: FINISH ::: Executing ::: Terraform apply ::: SUCCESS"
    else
	    echo "ERROR ::: ElasticSearch provisioning ::: FINISH ::: Executing ::: Terraform apply ::: FAILED "
	    exit 1
    fi
    cd ..
else
	echo "INFO ::: ElasticSearch Domain is Active . . . . . . . . . ."
	echo "INFO ::: BEGIN ::: NAC Provisioning . . . . . . . . . . . ."
fi

##################################### END ES Domain ###################################################################

##################################### START TRACKER JSON Creation ###################################################################

echo "NAC_Activity : Export In Progress"

OS_URL=$(aws secretsmanager get-secret-value --secret-id $OS_ADMIIN_SECRET --region "${AWS_REGION}" --profile "${AWS_PROFILE}" | jq -r '.SecretString' | jq -r '.nac_es_url')
KIBANA_URL=$(aws secretsmanager get-secret-value --secret-id $OS_ADMIIN_SECRET --region "${AWS_REGION}" --profile "${AWS_PROFILE}" | jq -r '.SecretString' | jq -r '.nac_kibana_url')
DEFAULT_URL="/SearchUI_Web/index.html"
USER_SECRET=$OS_ADMIIN_SECRET
CREATED_BY=$(aws secretsmanager get-secret-value --secret-id $OS_ADMIIN_SECRET --region "${AWS_REGION}" --profile "${AWS_PROFILE}" | jq -r '.SecretString' | jq -r '.nac_es_admin_user')
CREATED_ON=$(date "+%Y%m%d-%H%M%S")
TRACKER_NMC_VOLUME_NAME=$NMC_VOLUME_NAME
ANALYTICS_SERVICE=(${TFVARS_FILE//_/ })
ANALYTICS_SERVICE=$(echo "${ANALYTICS_SERVICE[-1]}" | cut -d'.' -f 1)
MOST_RECENT_RUN=$(date "+%Y:%m:%d-%H:%M:%S")
CURRENT_STATE="Export-In-progress"
LATEST_TOC_HANDLE_PROCESSED="-"
echo "INFO ::: Nach sheduler name: " ${NAC_SCHEDULER_NAME}
JSON_FILE_PATH="$HOME/TrackerJson/${NAC_SCHEDULER_NAME}_tracker.json"
echo "INFO ::: JSON_FILE_PATH:" $JSON_FILE_PATH
if [ -f "$JSON_FILE_PATH" ] ; then
	TRACEPATH="${NMC_VOLUME_NAME}_${ANALYTICS_SERVICE}"
	TRACKER_JSON=$(cat $JSON_FILE_PATH)
	echo "Tracker json" $TRACKER_JSON
	LATEST_TOC_HANDLE_PROCESSED=$(echo $TRACKER_JSON | jq -r .INTEGRATIONS.\"$TRACEPATH\"._NAC_activity.latest_toc_handle_processed)
	if [ -z "$LATEST_TOC_HANDLE_PROCESSED" -a "$LATEST_TOC_HANDLE_PROCESSED" == " " ]; then	
 		LATEST_TOC_HANDLE_PROCESSED="-"
	fi
	echo "INFO LATEST_TOC_HANDLE PROCESSED" ??$LATEST_TOC_HANDLE_PROCESSED
fi

generate_tracker_json $OS_URL $KIBANA_URL $DEFAULT_URL $FREQUENCY $USER_SECRET $CREATED_BY $CREATED_ON $TRACKER_NMC_VOLUME_NAME $ANALYTICS_SERVICE $MOST_RECENT_RUN $CURRENT_STATE $LATEST_TOC_HANDLE_PROCESSED $NAC_SCHEDULER_NAME
pwd
echo "INFO ::: current user :-"`whoami`
########## Download NAC Provisioning Code from GitHub ##########
### GITHUB_ORGANIZATION defaults to nasuni-labs
REPO_FOLDER="nasuni-analyticsconnector-opensearch"
validate_github $GITHUB_ORGANIZATION $REPO_FOLDER
########################### Git Clone : NAC Provisioning Repo ###############################################################
echo "INFO ::: BEGIN - Git Clone !!!"
### Download Provisioning Code from GitHub
GIT_REPO_NAME=$(echo ${GIT_REPO} | sed 's/.*\/\([^ ]*\/[^.]*\).*/\1/' | cut -d "/" -f 2)
echo "INFO ::: GIT_REPO : $GIT_REPO"
echo "INFO ::: GIT_REPO_NAME : $GIT_REPO_NAME"
pwd
ls
echo "INFO ::: Deleting the Directory: ${GIT_REPO_NAME}"
rm -rf "${GIT_REPO_NAME}"
pwd
COMMAND="git clone -b main ${GIT_REPO}"
$COMMAND
RESULT=$?
if [ $RESULT -eq 0 ]; then
	echo "INFO ::: FINISH ::: GIT clone SUCCESS for repo ::: $GIT_REPO_NAME"
else
	echo "ERROR ::: FINISH ::: GIT Clone FAILED for repo ::: $GIT_REPO_NAME"
	echo "ERROR ::: Unable to Proceed with NAC Provisioning."
	exit 1
fi
pwd
ls -l
########################### Completed - Git Clone  ###############################################################
echo "INFO ::: Copy TFVARS file to $(pwd)/${GIT_REPO_NAME}/${TFVARS_FILE}"
# cp "$NMC_VOLUME_NAME/${TFVARS_FILE}" $(pwd)/"${GIT_REPO_NAME}"/
cp "${TFVARS_FILE}" "${GIT_REPO_NAME}"/
cd "${GIT_REPO_NAME}"
pwd
ls

NMC_VOLUME_NAME_1=$(echo $NMC_VOLUME_NAME|tr -d '"')
ANALYTICS_SERVICE_1=$(echo $ANALYTICS_SERVICE|tr -d '"')
NAC_SCHEDULER_NAME_1=$(echo $NAC_SCHEDULER_NAME|tr -d '"')

JSON_FILE_PATH="$HOME/TrackerJson/${NAC_SCHEDULER_NAME_1}_tracker.json"
echo $JSON_FILE_PATH
LATEST_TOC_HANDLE=""
if [ ! -d "~/Trackerson" ] ; then
	TRACEPATH="${NMC_VOLUME_NAME_1}_${ANALYTICS_SERVICE_1}"
	echo $TRACEPATH
	TRACKER_JSON=$(cat $JSON_FILE_PATH)
	echo "Tracker json" $TRACKER_JSON
	LATEST_TOC_HANDLE=$(echo $TRACKER_JSON | jq -r .INTEGRATIONS.\"$TRACEPATH\"._NAC_activity.latest_toc_handle_processed)
	if [ "$LATEST_TOC_HANDLE" =  "-" ] ; then
		LATEST_TOC_HANDLE=""
	fi
	echo "LATEST_TOC_HANDLE: $LATEST_TOC_HANDLE"
else
	LATEST_TOC_HANDLE=""
	echo "ERROR:::Tracker JSON folder Not present"
fi

echo "LATEST_TOC_HANDLE" $LATEST_TOC_HANDLE
LATEST_TOC_HANDLE_PROCESSED=$LATEST_TOC_HANDLE

##appending latest_toc_handle_processed to TFVARS_FILE
echo "PrevUniFSTOCHandle="\"$LATEST_TOC_HANDLE\" >>$TFVARS_FILE 

##### RUN terraform init
echo "INFO ::: NAC provisioning ::: BEGIN - Executing ::: Terraform init."
COMMAND="terraform init"
$COMMAND
chmod 755 $(pwd)/*
# exit 1
echo "INFO ::: NAC provisioning ::: FINISH - Executing ::: Terraform init."
echo "INFO ::: NAC provisioning ::: BEGIN - Executing ::: Terraform Apply . . . . . . . . . . . "
COMMAND="terraform apply -var-file=${TFVARS_FILE} -auto-approve"
# COMMAND="terraform validate"
$COMMAND
if [ $? -eq 0 ]; then
	echo "INFO ::: NAC provisioning ::: FINISH ::: Terraform apply ::: SUCCESS"
	echo "NAC_Activity : Export Completed. Indexing in Progress"
	CURRENT_STATE="Export-completed-And-Indexing-In-progress"
	LATEST_TOC_HANDLE_PROCESSED=$(terraform output -raw latest_toc_handle_processed)
	echo "INFO ::: LATEST_TOC_HANDLE_PROCESSED for NAC Discovery is : $LATEST_TOC_HANDLE_PROCESSED"
	generate_tracker_json $OS_URL $KIBANA_URL $DEFAULT_URL $FREQUENCY $USER_SECRET $CREATED_BY $CREATED_ON $TRACKER_NMC_VOLUME_NAME $ANALYTICS_SERVICE $MOST_RECENT_RUN $CURRENT_STATE $LATEST_TOC_HANDLE_PROCESSED $NAC_SCHEDULER_NAME
else
	echo "INFO ::: NAC provisioning ::: FINISH ::: Terraform apply ::: FAILED"
	echo "NAC_Activity : Export Failed/Indexing Failed"
	CURRENT_STATE="Export-Failed-And-Indexing-Failed"
	generate_tracker_json $OS_URL $KIBANA_URL $DEFAULT_URL $FREQUENCY $USER_SECRET $CREATED_BY $CREATED_ON $TRACKER_NMC_VOLUME_NAME $ANALYTICS_SERVICE $MOST_RECENT_RUN $CURRENT_STATE $LATEST_TOC_HANDLE_PROCESSED $NAC_SCHEDULER_NAME
	exit 1
    fi
    sleep 300

    echo "NAC_Activity : Indexing Completed"
    MOST_RECENT_RUN=$(date "+%Y:%m:%d-%H:%M:%S")
    CURRENT_STATE="Indexing-Completed"

    INTERNAL_SECRET=$(head -n 1 nac_uniqui_id.txt  | tr -d "'")
    echo "INFO ::: Internal secret for NAC Discovery is : $INTERNAL_SECRET"

    generate_tracker_json $OS_URL $KIBANA_URL $DEFAULT_URL $FREQUENCY $USER_SECRET $CREATED_BY $CREATED_ON $TRACKER_NMC_VOLUME_NAME $ANALYTICS_SERVICE $MOST_RECENT_RUN $CURRENT_STATE $LATEST_TOC_HANDLE_PROCESSED $NAC_SCHEDULER_NAME

##Get the NAC discovery lambda function name
DISCOVERY_LAMBDA_NAME=$(aws secretsmanager get-secret-value --secret-id "$INTERNAL_SECRET" --region "${AWS_REGION}"  --profile "${AWS_PROFILE}" | jq -r '.SecretString' | jq -r '.discovery_lambda_name')

if [ -n "$DISCOVERY_LAMBDA_NAME" ]; then
	echo "INFO ::: Discovery lambda name :::not empty"
else
	echo "INFO ::: Discovery lambda name :::empty"
fi

echo "INFO ::: Discovery lambda name ::: ${DISCOVERY_LAMBDA_NAME}"
i_cnt=0
### Check If Lambda Execution Completed ?
LAST_UPDATE_STATUS="running"
CLEANUP="Y"
if [ "$CLEANUP" != "Y" ]; then

	if [ -z "$DISCOVERY_LAMBDA_NAME"  ]; then
		CLEANUP="Y"
	else
		while [ "$LAST_UPDATE_STATUS" != "InProgress" ]; do
			LAST_UPDATE_STATUS=$(aws lambda get-function-configuration --function-name "$DISCOVERY_LAMBDA_NAME" --region "${AWS_REGION}" | jq -r '.LastUpdateStatus')
			echo "LAST_UPDATE_STATUS ::: $LAST_UPDATE_STATUS"
			if [ "$LAST_UPDATE_STATUS" == "Successful" ]; then
				echo "INFO ::: Lambda execution COMPLETED. Preparing for cleanup of NAC Stack and dependent resources . . . . . . . . . . "
				CLEANUP="Y"
				break
			elif [ "$LAST_UPDATE_STATUS" == "Failed" ]; then
				echo "INFO ::: Lambda execution FAILED. Preparing for cleanup of NAC Stack and dependent resources . . . . . . . . . .  "
				CLEANUP="Y"
				break
			elif [[ "$LAST_UPDATE_STATUS" == "" || "$LAST_UPDATE_STATUS" == null ]]; then
				echo "INFO ::: Lambda Function Not found."
				CLEANUP="Y"
				break
	    fi
	    ((i_cnt++)) || true

	    echo " %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% $((i_cnt))"
	    if [ $((i_cnt)) -eq 5 ]; then
		    if [[ -z "${LAST_UPDATE_STATUS}" ]]; then
			    echo "WARN ::: System TimeOut"
			    CLEANUP="Y"
			    break
		fi

	    fi
    done
    fi
fi
echo "INFO ::: CleanUp Flag: $CLEANUP"
###################################################
#if [ "$CLEANUP" == "Y" ]; then
echo "INFO ::: Lambda execution COMPLETED."
echo "INFO ::: STARTED ::: CLEANUP NAC STACK and dependent resources . . . . . . . . . . . . . . . . . . . . ."
# ##### RUN terraform destroy to CLEANUP NAC STACK and dependent resources

COMMAND="terraform destroy -var-file=${TFVARS_FILE} -auto-approve"
$COMMAND
echo "INFO ::: COMPLETED ::: CLEANUP NAC STACK and dependent resources ! ! ! ! "
#    exit 0
#fi
END=$(date +%s)
secs=$((END - START))
DIFF=$(printf '%02dh:%02dm:%02ds\n' $((secs/3600)) $((secs%3600/60)) $((secs%60)))
echo "INFO ::: Total execution Time ::: $DIFF"
#exit 0

} || {
	END=$(date +%s)
	secs=$((END - START))
	DIFF=$(printf '%02dh:%02dm:%02ds\n' $((secs/3600)) $((secs%3600/60)) $((secs%60)))
	echo "INFO ::: Total execution Time ::: $DIFF"
	exit 0
	echo "INFO ::: Failed NAC Povisioning"

}
