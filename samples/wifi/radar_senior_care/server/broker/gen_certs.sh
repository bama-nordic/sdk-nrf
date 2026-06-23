#!/usr/bin/env bash
#
# Copyright (c) 2026 Nordic Semiconductor ASA
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#
# Generate a demo CA + broker server certificate for the TLS MQTT broker, and
# a Mosquitto password file. FOR LAB/PROTOTYPE USE ONLY.
#
#   ./gen_certs.sh [mqtt_username] [mqtt_password]
#
# Outputs (git-ignored) into ./certs and ./passwd. After running, paste
# certs/ca.crt into ../../src/certs/ca_cert.h for the firmware.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CERTS="$HERE/certs"
DAYS=3650
USERNAME="${1:-room-device}"
PASSWORD="${2:-change-me}"

# Names/addresses the broker certificate is valid for. "care-broker" matches
# the firmware CONFIG_RADAR_CARE_MQTT_TLS_HOSTNAME; the rest cover local + docker.
SAN="DNS:care-broker,DNS:localhost,DNS:mosquitto,IP:127.0.0.1"

mkdir -p "$CERTS"

echo "==> Generating CA"
openssl req -x509 -nodes -newkey rsa:2048 -days "$DAYS" \
	-keyout "$CERTS/ca.key" -out "$CERTS/ca.crt" \
	-subj "/O=SeniorCare/CN=SeniorCare-Demo-CA"

echo "==> Generating broker server certificate (SAN: $SAN)"
openssl req -nodes -newkey rsa:2048 \
	-keyout "$CERTS/server.key" -out "$CERTS/server.csr" \
	-subj "/O=SeniorCare/CN=care-broker"

openssl x509 -req -in "$CERTS/server.csr" \
	-CA "$CERTS/ca.crt" -CAkey "$CERTS/ca.key" -CAcreateserial \
	-days "$DAYS" -out "$CERTS/server.crt" \
	-extfile <(printf 'subjectAltName=%s\n' "$SAN")

rm -f "$CERTS/server.csr" "$CERTS/ca.srl"

echo "==> Generating Mosquitto password file (user: $USERNAME)"
if command -v mosquitto_passwd >/dev/null 2>&1; then
	mosquitto_passwd -c -b "$HERE/passwd" "$USERNAME" "$PASSWORD"
else
	echo "    mosquitto_passwd not found; create it inside the broker container:"
	echo "    docker run --rm -v \"$HERE\":/c eclipse-mosquitto:2 \\"
	echo "      mosquitto_passwd -c -b /c/passwd $USERNAME $PASSWORD"
fi

echo
echo "Done. Certs in $CERTS"
echo "Next: paste the contents of $CERTS/ca.crt into ../../src/certs/ca_cert.h"
