#! /usr/bin/env bash
set -xeu

mkdir -p "$HOME/.config/gcloud"
echo "$GCLOUD_CREDENTIALS_BASE64" | base64 --decode > service_account.json
export GOOGLE_APPLICATION_CREDENTIALS=`readlink -f service_account.json`
gcloud config set project "$GCLOUD_PROJECT"
echo "---
tokens:
  - key_ring: \"$GCLOUD_KEYRING\"
" > pkcs11-config.yaml
chmod 0600 pkcs11-config.yaml

export KMS_PKCS11_CONFIG=`readlink -f pkcs11-config.yaml`
export PKCS11_MODULE_PATH=/libkmsp11-1.6-linux-amd64/libkmsp11.so

# Verify signature of pkcs11 module
echo "-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEtfLbXkHUVc9oUPTNyaEK3hIwmuGRoTtd
6zDhwqjJuYaMwNd1aaFQLMawTwZgR0Xn27ymVWtqJHBe0FU9BPIQ+SFmKw+9jSwu
/FuqbJnLmTnWMJ1jRCtyHNZawvv2wbiB
-----END PUBLIC KEY-----" > pkcs11-release-signing-key.pem
openssl dgst -sha384 -verify pkcs11-release-signing-key.pem -signature "$PKCS11_MODULE_PATH.sig" "$PKCS11_MODULE_PATH"

echo "$QNAP_SIGNING_CERT_BASE64" | base64 --decode > cert.crt

>&2 TOKEN=`curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"` \
&& curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/

>&2 curl https://www.google.com/humans.txt

openssl cms \
	-sign \
	-binary \
	-nodetach \
	-engine pkcs11 \
	-keyform engine \
	-inkey "pkcs11:object=$QNAP_SIGNING_KEY_NAME" \
	-keyopt rsa_padding_mode:pss \
	-keyopt rsa_pss_saltlen:digest \
	-signer cert.crt \
	-in "$1" \
	-out -
