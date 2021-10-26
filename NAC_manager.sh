#!/bin/bash

NMC_VOLUME_NAME="$1"

if [ "$NMC_VOLUME_NAME" == "" ]
then 
	echo "Please Provide the mandatory NMC Volume Name"
	exit 1
fi

AWS_PROFILE="nasuni"
AWS_REGION=""
AWS_ACCESS_KEY_ID=""
AWS_SECRET_ACCESS_KEY=""

if [[ "$(aws configure list-profiles | grep "${AWS_PROFILE}")" == "" ]]; then
	echo "ERROR ::: AWS profile $AWS_PROFILE does not exists. To Create AWS PROFILE, Run cli command - aws configure "
	exit 1
else   # AWS Profile nasuni available in local machine
	AWS_ACCESS_KEY_ID=$(aws configure get aws_access_key_id --profile ${AWS_PROFILE})
	AWS_SECRET_ACCESS_KEY=$(aws configure get aws_secret_access_key --profile ${AWS_PROFILE})
	AWS_REGION=$(aws configure get region --profile ${AWS_PROFILE})
fi

echo "AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID"
echo "AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY"
echo "AWS_REGION=$AWS_REGION"
echo "NMC_VOLUME_NAME=$NMC_VOLUME_NAME"

PUB_IP_ADDR=$(aws ec2 describe-instances --query "Reservations[*].Instances[*].{Name:Tags[?Key=='Name']|[0].Value,Status:State.Name,PublicIP:PublicIpAddress}" --filters "Name=tag:Name,Values='NACManager'" "Name=instance-state-name,Values=running" --region "${AWS_REGION}" | grep -e "PublicIP" |cut -d":" -f 2|tr -d '"'|tr -d ' ') 
echo "PUB_IP_ADDR ::: ${PUB_IP_ADDR}"

###################### NACMAnager is Available ##############################
if [ "$PUB_IP_ADDR" != "" ];then 
	echo "NACMAnager is Available. IP Address: $PUB_IP_ADDR"

	# Temporary Code Till alternative for PEM file is found
	if [[ ${AWS_REGION} == "us-east-2" ]]; then
		PEM="nac-manager.pem"
	elif [[ "${AWS_REGION}" == "us-east-1" ]]; then
		PEM="nac-manager-nv.pem"
	fi

	echo "Public IP Address:- $PUB_IP_ADDR"
	echo "ssh -i "$PEM" ubuntu@$PUB_IP_ADDR -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null"
	### Create TFVARS File
	rm -rf "$NMC_VOLUME_NAME".tfvars
	echo "aws_profile="\"$AWS_PROFILE\" >> $NMC_VOLUME_NAME.tfvars
	echo "region="\"$AWS_REGION\" >> $NMC_VOLUME_NAME.tfvars
	echo "volume_name="\"$NMC_VOLUME_NAME\" >> $NMC_VOLUME_NAME.tfvars

	### Create Directory for each Volume 
	ssh -i "$PEM" ubuntu@$PUB_IP_ADDR -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null "[ ! -d $NMC_VOLUME_NAME ] && mkdir $NMC_VOLUME_NAME "
	echo "RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR"
	### Copy TFVARS and provision_nac.sh to NACManager
	scp -i "$PEM" -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null provision_nac.sh "$NMC_VOLUME_NAME".tfvars ubuntu@$PUB_IP_ADDR:~/$NMC_VOLUME_NAME

	### Check If CRON JOB is running for a specific VOLUME_NAME
	CRON_VOL=$(ssh -i "$PEM" -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null ubuntu@"$PUB_IP_ADDR" "crontab -l |grep /home/ubuntu/$NMC_VOLUME_NAME/$NMC_VOLUME_NAME.tfvars")
	#*/2 * * * * sh /home/ubuntu/file.sh SA-ES-VOL
	if [ "$CRON_VOL" != "" ]
	then
		### DO Nothing. CRON JOB takes care of NAC Provisioning
		echo "::::crontab does not require volume entry.As it is already present.:::::"
	else
		### Set up a new CRON JOB for NAC Provisioning

		echo 'Setting cronjob for '$NMC_VOLUME_NAME.tfvars' as it is not present '
			
		ssh -i "$PEM" ubuntu@$PUB_IP_ADDR -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null "(crontab -l ; echo '*/15 * * * * sh /home/ubuntu/$NMC_VOLUME_NAME/provision_nac.sh  /home/ubuntu/$NMC_VOLUME_NAME/$NMC_VOLUME_NAME.tfvars') | sort - | uniq - | crontab -"
		if [ $? -eq 0 ]; then
			echo "CRON JOB Scheduled for NMC VOLUME_NAME:: $NMC_VOLUME_NAME"
			exit 0
		else
			echo "FAILED to Schedule CRON JOB for NMC VOLUME_NAME:: $NMC_VOLUME_NAME"
			exit 1
		fi
	fi
	
exit 1
###################### NACMAnager is NOT Available ##############################
else 
	## "NACManager is not present. Creating new EC2 machine."
	
	echo "Instance is not present. Creating new EC2 machine."
	echo "INFO ::: Start - Git Clone "
    ### Download Provisioning Code from GitHub
    GIT_REPO="https://github.com/psahuNasuni/prov_nacmanager.git"
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
        echo "INFO ::: git clone SUCCESS"
        cd "${GIT_REPO_NAME}"
    elif [ $RESULT -eq 128 ]; then    
        cd "${GIT_REPO_NAME}"
        echo "$GIT_REPO_NAME"
        COMMAND="git pull origin main"
        $COMMAND
	fi
	### Download Provisioning Code from GitHub completed
	echo "NAC Manager EC2 PROVISIONING ::: STARTED ::: Executing the Terraform scripts . . . . . . . . . . . ."
    COMMAND="terraform init"
    $COMMAND
	echo "NAC Manager EC2 PROVISIONING ::: Initialized Terraform Libraries/Dependencies"
    echo "NAC Manager EC2 PROVISIONING ::: STARTED ::: Terraform apply . . . . . . . . . . . . . . . . . . ."
	##update dev.tfvars file to pass region as AWS_REGION sed --task 
	pwd
	sed 's/us-east-2/'${AWS_REGION}'/g' dev.tfvars >temp.txt
	rm -f dev.tfvars
	mv temp.txt dev.tfvars
	
    COMMAND="terraform apply -var-file=dev.tfvars -auto-approve"
    $COMMAND
    if [ $? -eq 0 ]; then
        echo "NAC PROVISIONING ::: Terraform apply ::: COMPLETED . . . . . . . . . . . . . . . . . . ."
	else
		echo "NAC PROVISIONING ::: Terraform apply ::: FAILED."
		exit 1
	fi
	ip=`cat NACManager_IP.txt`
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


}