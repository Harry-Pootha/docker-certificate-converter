#!/usr/bin/env bash

handle_sigterm() {
  echo "SIGTERM received - setting stop signal"
  CHECK_STOP=1
}

gencert() {
  NEW_PASSPHRASE="$CERT_PASSPHRASE"
  if [ "$NEW_PASSPHRASE" == "" ]; then
    NEW_PASSPHRASE="test"
  fi
  openssl req -x509 -newkey rsa:4096 -keyout test.key -out test.crt -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"
  openssl pkcs12 -export -in test.crt -inkey test.key -passout "pass:$NEW_PASSPHRASE" -out test.pfx
}

convert_pfx_to_pem() {
  FILENAME=${1%.pfx}

  if [ "$CERT_PASSPHRASE" == "" ]; then
    openssl pkcs12 -in "$1" -nocerts -nodes -out "$FILENAME.key"
    openssl pkcs12 -in "$1" -clcerts -nokeys -out "$FILENAME.pem"
  else
    openssl pkcs12 -in "$1" -passin "pass:$CERT_PASSPHRASE" -nocerts -nodes -out "$FILENAME.key"
    openssl pkcs12 -in "$1" -passin "pass:$CERT_PASSPHRASE" -clcerts -nokeys -out "$FILENAME.pem"
  fi
  mv "$1" "$1.converted"
}

run () {
  while [ $CHECK_STOP == 0 ]; do
    echo "Scanning for files..."
    while IFS= read -r -d '' file
    do
      echo "Found file $file"
      convert_pfx_to_pem "$file"
    done < <(find ./ -mtime -7 -name '*.pfx' -print0)
    sleep 1
  done
}

CHECK_STOP=0
trap handle_sigterm SIGTERM

if [ "$GENERATE" == "true" ]; then
  gencert
else
  run
fi

echo "Stopping"