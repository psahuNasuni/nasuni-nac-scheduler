#!/bin/bash

if [ "$1" == "" ]
then 
	echo "Pass the .pem file path as a 1st param"
	exit 0
fi

if [ "$2" == "" ]
then 
	echo "Pass the .tfvars file"
	exit 0
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


AWS_PROFILE=""
AWS_REGION=""
NMC_VOLUME_NAME=""
AWS_ACCESS_KEY_ID=""
AWS_SECRET_ACCESS_KEY=""
TFVARS_FILE=$2
if [ ! -f "$TFVARS_FILE" ]; then
	echo "ERROR ::: Required TFVARS file is missing"
	exit 1
else
	while IFS='=' read -r key value; do
		key=$(echo "$key")
		echo "key ::::: ${key} ~ ${value}"
		if [[ $(echo "${key}" | xargs) == "region" ]]; then
			AWS_REGION=$(echo "${value}" | xargs)
		fi
		if [[ $(echo "${key}" | xargs) == "volume_name" ]]; then
			NMC_VOLUME_NAME=$(echo "${value}" | xargs)
		fi
		if [[ $(echo "${key}" | xargs) == "aws_profile" ]]; then
			AWS_PROFILE=$(echo "${value}" | xargs)
			echo "$AWS_PROFILE"
			if [[ "$(aws configure list-profiles | grep "${AWS_PROFILE}")" == "" ]]; then
				echo "ERROR ::: AWS profile does not exists. To Create AWS PROFILE, Run cli command - aws configure "
			fi
		fi
	done <"$TFVARS_FILE"
fi
AWS_ACCESS_KEY_ID=$(aws configure get aws_access_key_id --profile ${AWS_PROFILE})
AWS_SECRET_ACCESS_KEY=$(aws configure get aws_secret_access_key --profile ${AWS_PROFILE})

echo "AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID
echo "AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY
echo "AWS_REGION="$AWS_REGION
echo "NMC_VOLUME_NAME="$NMC_VOLUME_NAME



cp -f $2 $NMC_VOLUME_NAME.tfvars


rm -f file.txt
if [ $? -eq 0 ]; then
	echo OK
else
	echo FAIL
	exit 0
fi
aws ec2 describe-instances --query "Reservations[*].Instances[*].{Name:Tags[?Key=='Name']|[0].Value,Status:State.Name,PublicIP:PublicIpAddress}" --filters "Name=tag:Name,Values='NACManager'" "Name=instance-state-name,Values=running" > file.txt 

data=`grep -e "NACManager" -e "running" file.txt`
if [ "$data" != "" ]
then
	echo "Instance is present"
	pub_ip_addr=`grep  PublicIP file.txt|cut -c 25-|tr -d '"'`

	# data1=`cut -b file.txt|grep  PublicIP `
	echo "Public IP Address:-"$pub_ip_addr
	echo "ssh -i "$1" ubuntu@$pub_ip_addr"
	echo "Downloading sch-nac code"
	GIT_REPO_SCH=https://github.com/psahuNasuni/sch-nac.git
	Download_git_code $GIT_REPO_SCH
	cd ../
	GIT_REPO_SCH_NAME=$(echo ${GIT_REPO_SCH} | sed 's/.*\/\([^ ]*\/[^.]*\).*/\1/' | cut -d "/" -f 2)
	echo "*****copy "$NMC_VOLUME_NAME.tfvars" file to $GIT_REPO_SCH_NAME folder"
	cp -f $NMC_VOLUME_NAME.tfvars $GIT_REPO_SCH_NAME/
	tar -czf $GIT_REPO_SCH_NAME.tar.gz $GIT_REPO_SCH_NAME/
	echo "*****copy $GIT_REPO_SCH_NAME file to remote machine "

	##ssh -i "$1" ubuntu@$pub_ip_addr "mkdir $NMC_VOLUME_NAME "
	ssh -i "$1" ubuntu@$pub_ip_addr "[ ! -d $NMC_VOLUME_NAME ] && mkdir $NMC_VOLUME_NAME "
	ssh -i "$1" ubuntu@$pub_ip_addr "echo /home/ubuntu/$NMC_VOLUME_NAME"
	scp -i "$1" $GIT_REPO_SCH_NAME.tar.gz ubuntu@$pub_ip_addr:/home/ubuntu/$NMC_VOLUME_NAME
	echo "*****extract $GIT_REPO_SCH_NAME.tar.gz file to remote machine "
	ssh -i "$1" ubuntu@$pub_ip_addr "tar -xzf /home/ubuntu/$NMC_VOLUME_NAME/$GIT_REPO_SCH_NAME.tar.gz -C /home/ubuntu/$NMC_VOLUME_NAME/"
	echo "Exporting variables AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY "
	output_format="json"
	ssh -i "$1" ubuntu@$pub_ip_addr "export AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID ; export AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY;export AWS_REGION=$AWS_REGION;export output_format=$output_format"
	# ssh -i "$1" ubuntu@$pub_ip_addr "echo  $AWS_ACCESS_KEY_ID "
	cron_vol=`ssh -i "$1" ubuntu@$pub_ip_addr "crontab -l |grep /home/ubuntu/$NMC_VOLUME_NAME/$GIT_REPO_SCH_NAME/$NMC_VOLUME_NAME.tfvars"`
	#*/2 * * * * sh /home/ubuntu/file.sh SA-ES-VOL
	if [ "$cron_vol" != "" ]
	then
		echo "::::crontab does not require volume entry.As it is already present.:::::"

	else
		echo 'Setting cronjob for '$NMC_VOLUME_NAME.tfvars' as it is not present '
		#ssh -i "$1" ubuntu@$pub_ip_addr 'cat <(crontab -l) <(echo "* * * * * * sh /home/ubuntu/file.sh") | crontab -'
		#echo "Volume Name=$2"
		
		#scp -ir  "$1" sch-nac/ ubuntu@$pub_ip_addr:/home/ubuntu/
		
		ssh -i "$1" ubuntu@$pub_ip_addr "(crontab -l ; echo '*/15 * * * * sh /home/ubuntu/$NMC_VOLUME_NAME/sch-nac/provision_nac.sh  /home/ubuntu/$NMC_VOLUME_NAME/sch-nac/$NMC_VOLUME_NAME.tfvars') | sort - | uniq - | crontab -"
		if [ $? -eq 0 ]; then
			echo OK
		else
			echo FAIL
			exit 0
		fi
	#echo '$(echo "*/2 * * * * ubuntu sh /home/ubuntu/file.sh" ; ssh -i "$1" ubuntu@$pub_ip_addr crontab -l 2>&1)' | ssh -i "$1"  ubuntu@$pub_ip_addr "crontab -"
	fi 
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