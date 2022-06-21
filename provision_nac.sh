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
    esac
  done < "$file"
}


check_if_secret_exists() {
	USER_SECRET="$1"
	AWS_PROFILE="$2"
	AWS_REGION="$3"
	# Verify the Secret Exists
	echo USER_SECRET $USER_SECRET
	echo AWS_PROFILE $AWS_PROFILE
	echo AWS_REGION $AWS_REGION
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

########################Create OS Admin Secret, If its not available ###############

OS_ADMIIN_SECRET="nasuni-labs-os-admin"
### Verify the Secret Exists
OS_ADMIIN_SECRET_EXISTS=$(check_if_secret_exists $OS_ADMIIN_SECRET $AWS_PROFILE $AWS_REGION)
echo "INFO ::: OS_ADMIIN_SECRET_EXISTS ::: $OS_ADMIIN_SECRET_EXISTS "
#exit 1
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
    echo "ERROR ::: ElasticSearch Domain is Not Configured. Need to Provision ElasticSearch Domain Before, NAC Provisioning."
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
    #exit 1
    if [[ "$USE_PRIVATE_IP" = Y ]]; then
	echo "Inside Use private ip block"
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
# exit 0

NMC_VOLUME_NAME=$(echo "${TFVARS_FILE}" | rev | cut -d'/' -f 1 | rev |cut -d'.' -f 1)
cd "$NMC_VOLUME_NAME"
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
    else
        echo "INFO ::: NAC provisioning ::: FINISH ::: Terraform apply ::: FAILED"
        exit 1
    fi
sleep 1800

INTERNAL_SECRET=$(head -n 1 nac_uniqui_id.txt  | tr -d "'")
echo "INFO ::: Internal secret for NAC Discovery is : $INTERNAL_SECRET"
### Get the NAC discovery lambda function name
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
