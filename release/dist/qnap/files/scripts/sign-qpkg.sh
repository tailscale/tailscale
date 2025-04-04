#!/bin/bash

set -eu

QPKG="$1"
QPKG_TAIL="${QPKG}.tail"
QPKG_SHA="${QPKG}.sha"
QPKG_MSG="${QPKG}.msg"
QPKG_SIGNED="${QPKG}.signed"

# Split off 100 byte tail
head -c -100 "${QPKG}" > "$QPKG_SIGNED"
tail -c 100 "${QPKG}" > "$QPKG_TAIL"

# Generate SHA
openssl dgst -sha1 -binary "${QPKG_SIGNED}" > "${QPKG_SHA}"

# Sign head
openssl cms \
    -sign \
    -binary \
    -nodetach \
    -engine pkcs11 \
    -keyform engine \
    -inkey "pkcs11:object=signing-test" \
    -keyopt rsa_padding_mode:pss \
    -keyopt rsa_pss_saltlen:digest \
    -signer $HOME/csr/certificate.crt \
    -in "${QPKG_SHA}" \
    -out "${QPKG_MSG}"

# Add signature section
printf "QDK" >> "${QPKG_SIGNED}" # beginning of QDK area
size="$(/bin/ls -l "${QPKG_MSG}" | awk '{ print $5 }')"
printf "\\$(printf "%o" 254)" >> "${QPKG_SIGNED}" # code signing data type
for byte in $(echo $size | sed 's/../& /g')
do
    printf "\\$(printf "%o" 0x$byte)" >> "${QPKG_SIGNED}"
done
cat "${QPKG_MSG}" >> "${QPKG_SIGNED}" # the signature itself
printf "\\$(printf "%o" 255)" >> "${QPKG_SIGNED}" # end of QDK area

# Add back tail
cat "${QPKG_TAIL}" >> "${QPKG_SIGNED}"

# Move to final destination
mv "${QPKG_SIGNED}" "${QPKG}"
