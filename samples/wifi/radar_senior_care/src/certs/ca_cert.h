/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 *
 * Broker CA certificate used to verify the MQTT broker when
 * CONFIG_RADAR_CARE_MQTT_TLS is enabled.
 *
 * REPLACE the placeholder below with YOUR broker's CA certificate (PEM).
 * For the bundled demo broker, generate one with:
 *
 *     server/broker/gen_certs.sh
 *
 * then paste the contents of server/broker/certs/ca.crt here. The trailing
 * NUL from the string literal is intentionally included in the credential
 * length (mbed TLS expects NUL-terminated PEM).
 */

#ifndef RADAR_CARE_CA_CERT_H_
#define RADAR_CARE_CA_CERT_H_

static const unsigned char ca_certificate[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIBmTCCAT+gAwIBAgIUPLACEHOLDER_REPLACE_WITH_YOUR_BROKER_CA_xxxxxxx\n"
	"PLACEHOLDER_CERTIFICATE_BODY_REPLACE_ME_WITH_REAL_PEM_CONTENTS_xxx\n"
	"-----END CERTIFICATE-----\n";

#endif /* RADAR_CARE_CA_CERT_H_ */
