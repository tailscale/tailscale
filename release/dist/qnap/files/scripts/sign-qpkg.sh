#! /usr/bin/env bash
set -xeu

mkdir -p "$HOME/.config/gcloud"
echo "$GCLOUD_CREDENTIALS_BASE64" | base64 --decode > /root/.config/gcloud/application_default_credentials.json
gcloud config set project "$GCLOUD_PROJECT"

echo "---
tokens:
  - key_ring: \"$GCLOUD_KEYRING\"
log_directory: "/tmp/kmsp11"
" > pkcs11-config.yaml
chmod 0600 pkcs11-config.yaml

export KMS_PKCS11_CONFIG=`readlink -f pkcs11-config.yaml`
export PKCS11_MODULE_PATH=/libkmsp11-1.6-linux-amd64/libkmsp11.so

# Verify signature of pkcs11 module
# See https://github.com/GoogleCloudPlatform/kms-integrations/blob/master/kmsp11/docs/user_guide.md#downloading-and-verifying-the-library
echo "-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEtfLbXkHUVc9oUPTNyaEK3hIwmuGRoTtd
6zDhwqjJuYaMwNd1aaFQLMawTwZgR0Xn27ymVWtqJHBe0FU9BPIQ+SFmKw+9jSwu
/FuqbJnLmTnWMJ1jRCtyHNZawvv2wbiB
-----END PUBLIC KEY-----" > pkcs11-release-signing-key.pem
openssl dgst -sha384 -verify pkcs11-release-signing-key.pem -signature "$PKCS11_MODULE_PATH.sig" "$PKCS11_MODULE_PATH"

echo "$QNAP_SIGNING_CERT_BASE64" | base64 --decode > cert.crt

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
