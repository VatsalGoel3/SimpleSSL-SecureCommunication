#!/bin/bash

# Define filenames
SERVER_CERT="serverCert.pem"
SERVER_KEY="serverKey.pem"
CLIENT_CERT="clientCert.pem"
CLIENT_KEY="clientKey.pem"

# Generate Server Certificate and Key
if [[ ! -e "$SERVER_CERT" || ! -e "$SERVER_KEY" ]]; then
    echo "Generating server certificate and key..."
    openssl req -x509 -newkey rsa:4096 -keyout "$SERVER_KEY" -out "$SERVER_CERT" -days 365 -nodes -subj "/CN=mySSLServer"
else
    echo "Server certificate and key already exist."
fi

# Generate Client Certificate and Key
if [[ ! -e "$CLIENT_CERT" || ! -e "$CLIENT_KEY" ]]; then
    echo "Generating client certificate and key..."
    openssl req -x509 -newkey rsa:4096 -keyout "$CLIENT_KEY" -out "$CLIENT_CERT" -days 365 -nodes -subj "/CN=mySSLClient"
else
    echo "Client certificate and key already exist."
fi

echo "Certificate generation complete."
