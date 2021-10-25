#!/bin/bash
TERRAFORM_VERSION=1.0.7
sudo yum update && \
sudo yum install curl jq bash ca-certificates git openssl unzip wget vim && \
    cd /tmp && \
    wget https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip && \
    unzip terraform_${TERRAFORM_VERSION}_linux_amd64.zip -d /usr/bin
sudo yum install python3 py3-pip groff less mailcap && \
    pip3 install --upgrade pip && \
    pip3 install awscli