#./creater_layer.sh <package_name> <layer_name>

#./creater_layer.sh elasticsearch my-layer
path="app"
#package="${1}"
layername="${1}"
echo $layername
existing_lambda_layer=$(aws lambda list-layers --compatible-runtime python3.8 --profile nasuni)
ext_lambda_layer=$(echo $existing_lambda_layer | jq -r '.Layers[] | select(.LayerName == '\"$layername\"') | {LayerName}')
echo ext_lambda_layer $ext_lambda_layer


if [ "$ext_lambda_layer" = "" ] ; then
  mkdir -p $path
  for i in opensearch-py requests requests_aws4auth python-pptx PyMuPDF python-docx pandas chardet openpyxl xlrd
  do
	# pip3 install "${package}" --target "${path}/python/lib/python3.9/site-packages/"
	pip3 install "$i" --target "${path}/python/lib/python3.8/site-packages/"
	#echo "$i"
  done
  cd $path && zip -r ../lambdalayer.zip .

  aws s3 mb s3://nac-discovery-lambda-layer --profile nasuni
  if [ $? -eq 0 ]; then
     echo OK
  else
     echo bucket is already exist
  fi
  cd 
  aws s3 cp lambdalayer.zip s3://nac-discovery-lambda-layer --profile nasuni

  aws lambda publish-layer-version --layer-name "${layername}" --description "Lambda layer for including all pkgs for NAC_Discovery"     --license-info "MIT" --content S3Bucket=nac-discovery-lambda-layer,S3Key=lambdalayer.zip  --compatible-runtimes python3.8 python3.9 --profile nasuni
else
  echo "The layer ${layername} is already present"
fi
