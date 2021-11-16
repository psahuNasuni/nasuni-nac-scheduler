#!/bin/bash

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
    esac
  done < "$file"
}
read_TFVARS "$TFVARS_FILE"

AWS_PROFILE=$(echo "$AWS_PROFILE" | tr -d '"')
AWS_REGION=$(echo "$AWS_REGION" | tr -d '"')
NMC_VOLUME_NAME=$(echo "$NMC_VOLUME_NAME" | tr -d '"')

######################## Check If ES Domain Available ###############################################
ES_DOMAIN_NAME=$(aws secretsmanager get-secret-value --secret-id nct/nce/os/admin --region "${AWS_REGION}" | jq -r '.SecretString' | jq -r '.es_domain_name')
echo "INFO ::: ES_DOMAIN NAME : $ES_DOMAIN_NAME"
# exit 1
IS_ES="N"
if [ "$ES_DOMAIN_NAME" == "" ] || [ "$ES_DOMAIN_NAME" == null ]; then
    echo "ERROR ::: ElasticSearch Domain is Not provided in admin secret"
    IS_ES="N"
else
    ES_CREATED=$(aws es describe-elasticsearch-domain --domain-name "${ES_DOMAIN_NAME}" --region "${AWS_REGION}" | jq -r '.DomainStatus.Created')
    if [ $? -eq 0 ]; then
        echo "INFO ::: ES_CREATED : $ES_CREATED"
        ES_PROCESSING=$(aws es describe-elasticsearch-domain --domain-name "${ES_DOMAIN_NAME}" --region "${AWS_REGION}" | jq -r '.DomainStatus.Processing')
        echo "INFO ::: ES_PROCESSING : $ES_PROCESSING"
        ES_UPGRADE_PROCESSING=$(aws es describe-elasticsearch-domain --domain-name "${ES_DOMAIN_NAME}" --region "${AWS_REGION}" | jq -r '.DomainStatus.UpgradeProcessing')
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
    echo "INFO ::: Start ElasticSearch Domain Provisioning."
    ########################### Git Clone  ###############################################################
    echo "INFO ::: Start - Git Clone !!!"
    ### Download Provisioning Code from GitHub
    GIT_REPO="https://github.com/psahuNasuni/provision-es.git"
    GIT_REPO_NAME=$(echo ${GIT_REPO} | sed 's/.*\/\([^ ]*\/[^.]*\).*/\1/' | cut -d "/" -f 2)
    echo "$GIT_REPO"
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
        echo "INFO ::: GIT clone SUCCESS for repo ::: $GIT_REPO_NAME"
    else
        echo "INFO ::: GIT Clone  FAILED for repo ::: $GIT_REPO_NAME"
        exit 1
    fi
    cd "${GIT_REPO_NAME}"
    ##### RUN terraform init
    echo "INFO ::: ES PROVISIONING ::: STARTED ::: Executing the Terraform scripts . . . . . . . . . . . ."
    COMMAND="terraform init"
    $COMMAND
    chmod 755 $(pwd)/*
    # exit 1
    echo "INFO ::: ES PROVISIONING ::: Initialized Terraform Libraries/Dependencies"
    ##### RUN terraform Apply
    echo "INFO ::: ES PROVISIONING ::: STARTED ::: Terraform apply . . . . . . . . . . . . . . . . . . ."
    COMMAND="terraform apply -auto-approve"
    $COMMAND
    if [ $? -eq 0 ]; then
        echo "INFO ::: ES PROVISIONING ::: Terraform apply ::: COMPLETED . . . . . . . . . . . . . . . . . . ."
    else
        echo "ERROR ::: ES PROVISIONING ::: Terraform apply ::: FAILED."
        exit 1
    fi
    cd ..
else
    echo "INFO ::: ElasticSearch Domain is Active . . . . . . . . . ."
    echo "INFO ::: START ::: NAC Provisioning . . . . . . . . . . . ."
fi

##################################### END ES Domain ###################################################################
# exit 0

NMC_VOLUME_NAME=$(echo "${TFVARS_FILE}" | rev | cut -d'/' -f 1 | rev |cut -d'.' -f 1)
cd "$NMC_VOLUME_NAME"
pwd
echo "INFO ::: current user :-"`whoami`
########################### Git Clone : NAC Provisioning Repo ###############################################################
echo "INFO ::: Start - Git Clone !!!"
### Download Provisioning Code from GitHub
GIT_REPO="https://github.com/psahuNasuni/nac-es.git"
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
    echo "INFO ::: GIT clone SUCCESS for repo ::: $GIT_REPO_NAME"
else
    echo "INFO ::: GIT Clone  FAILED for repo ::: $GIT_REPO_NAME"
    echo "INFO ::: Unable to Proceed with NAC Provisioning."
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
echo "INFO ::: NAC PROVISIONING ::: Initializing Terraform Libraries/Dependencies STARTED . . . . . . . . . . . ."
COMMAND="terraform init"
$COMMAND
chmod 755 $(pwd)/*
# exit 1
echo "INFO ::: NAC PROVISIONING ::: Initializing Terraform Libraries/Dependencies ::: COMPLETED"
echo "INFO ::: NAC PROVISIONING ::: STARTED ::: Terraform apply . . . . . . . . . . . . . . . . . . ."
COMMAND="terraform apply -var-file=${TFVARS_FILE} -auto-approve"
$COMMAND
if [ $? -eq 0 ]; then
        echo "INFO ::: NAC PROVISIONING ::: Terraform apply ::: COMPLETED . . . . . . . . . . . . . . . . . . ."
    else
        echo "INFO ::: NAC PROVISIONING ::: Terraform apply ::: FAILED."
        exit 1
    fi
###### WAITING For Lambda to IndexData - 30Sec   (Only for Testing) "
echo "WAITING For Lambda to IndexData - 30Sec   (Only for Testing) "
sleep 30
#exit 0

INTERNAL_SECRET=$(head -n 1 nac_uniqui_id.txt  | tr -d "'")
echo "INFO ::: Internal secret for NAC Discovery is : $INTERNAL_SECRET"
### Get the NAC discovery lambda function name
DISCOVERY_LAMBDA_NAME=$(aws secretsmanager get-secret-value --secret-id "$INTERNAL_SECRET" --region "${AWS_REGION}" | jq -r '.SecretString' | jq -r '.discovery_lambda_name')
echo "INFO ::: Discovery lambda name ::: $DISCOVERY_LAMBDA_NAME"

i_cnt=0
### Check If Lambda Execution Completed ?
LAST_UPDATE_STATUS="runnung"
CLEANUP="N"

if [ "$DISCOVERY_LAMBDA_NAME" == "" ]; then
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
echo "CleanUp Flag: $CLEANUP"
###################################################
if [ "$CLEANUP" == "Y" ]; then
    echo "Lambda execution COMPLETED."
    echo "STARTED ::: CLEANUP NAC STACK and dependent resources . . . . . . . . . . . . . . . . . . . . ."
    RUN terraform destroy to CLEANUP NAC STACK and dependent resources
#  exit 1

    COMMAND="terraform destroy -var-file=${TFVARS_FILE} -auto-approve"
    $COMMAND
    echo "COMPLETED ::: CLEANUP NAC STACK and dependent resources ! ! ! ! "
    exit 0
fi
END=$(date +%s)
secs=$((END - START))
DIFF=$(printf '%02dh:%02dm:%02ds\n' $((secs/3600)) $((secs%3600/60)) $((secs%60)))
echo "Total execution Time ::: $DIFF"
exit 0

} || {
    END=$(date +%s)
	secs=$((END - START))
	DIFF=$(printf '%02dh:%02dm:%02ds\n' $((secs/3600)) $((secs%3600/60)) $((secs%60)))
	echo "Total execution Time ::: $DIFF"
	exit 0
    echo "Failed NAC Povisioning" 

}