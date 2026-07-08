#!/usr/bin/env bash
set -euo pipefail

MAIL_HOSTNAME="${MAIL_HOSTNAME:-mailhub.local}"
MAIL_ORIGIN_DOMAIN="${MAIL_ORIGIN_DOMAIN:-${MAIL_HOSTNAME#*.}}"
POSTFIX_LOG_FILE="${POSTFIX_LOG_FILE:-/dev/stdout}"

if [[ "${POSTFIX_LOG_FILE}" != "/dev/stdout" ]]; then
  mkdir -p "$(dirname "${POSTFIX_LOG_FILE}")"
  touch "${POSTFIX_LOG_FILE}"
  chmod 666 "${POSTFIX_LOG_FILE}"
  tail -n 0 -F "${POSTFIX_LOG_FILE}" &
fi

postconf -e "myhostname = ${MAIL_HOSTNAME}"
postconf -e "myorigin = ${MAIL_ORIGIN_DOMAIN}"
postconf -e "mydestination ="
postconf -e "inet_interfaces = all"
postconf -e "inet_protocols = ipv4"
postconf -e "mynetworks = 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
postconf -e "smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination"
postconf -e "smtp_tls_security_level = may"
postconf -e "smtp_tls_loglevel = 1"
postconf -e "smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt"
postconf -e "smtp_helo_name = ${MAIL_HOSTNAME}"
postconf -e "disable_vrfy_command = yes"
postconf -e "maximal_queue_lifetime = 2d"
postconf -e "bounce_queue_lifetime = 2d"
postconf -e "maillog_file = ${POSTFIX_LOG_FILE}"

newaliases || true
exec postfix start-fg
