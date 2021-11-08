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
AWS_PROFILE=""
AWS_REGION=""
TFVARS_FILE=$1
NMC_VOLUME_NAME=$(echo "${TFVARS_FILE}" | cut -d "." -f 1)
cd "$NMC_VOLUME_NAME"
pwd
# if [ -d "$NMC_VOLUME_NAME" ]; then
#     cd "$NMC_VOLUME_NAME"
# else
#     echo "INFO ::: Volume Directory not found !!!"
#     exit 1
# fi

########################### Git Clone  ###############################################################
echo "INFO ::: Start - Git Clone !!!"
### Download Provisioning Code from GitHub
GIT_REPO="https://github.com/psahuNasuni/nac-es.git"
GIT_REPO_NAME=$(echo ${GIT_REPO} | sed 's/.*\/\([^ ]*\/[^.]*\).*/\1/' | cut -d "/" -f 2)
echo "$GIT_REPO"
echo "GIT_REPO_NAME $GIT_REPO_NAME"
pwd
ls
rm -rf "${GIT_REPO_NAME}"
COMMAND="git clone -b main ${GIT_REPO}"
$COMMAND
RESULT=$?
if [ $RESULT -eq 0 ]; then
    echo "INFO ::: GIT clone SUCCESS for repo ::: $GIT_REPO_NAME"
else
    echo "INFO ::: GIT Clone  FAILED for repo ::: $GIT_REPO_NAME"
    exit 1
fi
pwd
ls -l
########################### Completed - Git Clone  ###############################################################
echo "copy TFVARS file to $(pwd)/${GIT_REPO_NAME}/${TFVARS_FILE}"
cp "~/$NMC_VOLUME_NAME/${TFVARS_FILE}" $(pwd)/"${GIT_REPO_NAME}"/
cd "${GIT_REPO_NAME}"
pwd
ls
##### RUN terraform init
echo "NAC PROVISIONING ::: STARTED ::: Executing the Terraform scripts . . . . . . . . . . . ."
COMMAND="terraform init"
$COMMAND
chmod 755 $(pwd)/*
exit 1
echo "NAC PROVISIONING ::: Initialized Terraform Libraries/Dependencies"
echo "NAC PROVISIONING ::: STARTED ::: Terraform apply . . . . . . . . . . . . . . . . . . ."
COMMAND="terraform apply -var-file=${TFVARS_FILE} -auto-approve"
$COMMAND
if [ $? -eq 0 ]; then
        echo "NAC PROVISIONING ::: Terraform apply ::: COMPLETED . . . . . . . . . . . . . . . . . . ."
    else
        echo "NAC PROVISIONING ::: Terraform apply ::: FAILED."
        exit 1
    fi
echo "WAITING For Lambda to IndexData - 20Sec   (Only for Testing) "
sleep 20
exit 0
### Get the NAC discovery lambda function name
DISCOVERY_LAMBDA_NAME=$(aws secretsmanager get-secret-value --secret-id nac-es-internal | jq -r '.SecretString' | jq -r '.discovery_lambda_name')
echo "INFO ::: Discovery lambda name ::: $DISCOVERY_LAMBDA_NAME"
# exit 1
i_cnt=0
### Check If Lambda Execution Completed ?
LAST_UPDATE_STATUS="runnung"
CLEANUP="N"
while [ "$LAST_UPDATE_STATUS" != "InProgress" ]; do
    LAST_UPDATE_STATUS=$(aws lambda get-function-configuration --function-name "$DISCOVERY_LAMBDA_NAME" | jq -r '.LastUpdateStatus')
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
echo "CleanUp Flag: $CLEANUP"
###################################################
if [ "$CLEANUP" == "Y" ]; then
    echo "Lambda execution COMPLETED."
    echo "STARTED ::: CLEANUP NAC STACK and dependent resources . . . . . . . . . . . . . . . . . . . . ."
    # RUN terraform destroy to CLEANUP NAC STACK and dependent resources
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
    echo "Failed NAC Povisioning" && throw $NACStackCreationFailed

}
