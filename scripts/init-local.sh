#!/bin/sh
# Generate per-installation local credentials without replacing an existing .env.
set -eu
umask 077

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
env_file="$root/.env"
if [ -e "$env_file" ] || [ -L "$env_file" ]; then
    printf '%s\n' 'Existing .env preserved. Check that it contains all local settings.'
    exit 0
fi
if ! command -v openssl >/dev/null 2>&1; then
    printf '%s\n' 'OpenSSL is required to initialize local credentials.' >&2
    exit 1
fi
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/auth-local.XXXXXXXX")
env_tmp=$(mktemp "$root/.env.tmp.XXXXXXXX")
cleanup() { rm -rf -- "$work_dir"; rm -f -- "$env_tmp"; }
trap cleanup EXIT HUP INT TERM

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$work_dir/key.pem" >/dev/null 2>&1
openssl pkcs8 -topk8 -nocrypt -in "$work_dir/key.pem" -outform DER -out "$work_dir/private.der" >/dev/null 2>&1
openssl pkey -in "$work_dir/key.pem" -pubout -outform DER -out "$work_dir/public.der" >/dev/null 2>&1
private_key=$(openssl base64 -A -in "$work_dir/private.der")
public_key=$(openssl base64 -A -in "$work_dir/public.der")
db_password=$(openssl rand -hex 24)
otp_key=$(openssl rand -base64 32 | tr -d '\n')
outbox_key=$(openssl rand -base64 32 | tr -d '\n')
{
    printf '%s\n' '# Generated local development credentials. Do not commit or share.'
    printf 'DB_PASSWORD=%s\n' "$db_password"
    printf 'LOCAL_JWT_PRIVATE_KEY=%s\n' "$private_key"
    printf 'LOCAL_JWT_PUBLIC_KEY=%s\n' "$public_key"
    printf 'LOCAL_OTP_HMAC_KEY=%s\n' "$otp_key"
    printf 'LOCAL_OUTBOX_KEY=%s\n' "$outbox_key"
    printf '%s\n' '# Optional Google client audiences/presenters can be set here.'
} > "$env_tmp"
# Hard-link creation is atomic and refuses to overwrite an .env created concurrently.
if ! ln "$env_tmp" "$env_file" 2>/dev/null; then
    printf '%s\n' 'Could not create .env; an existing file was not replaced.' >&2
    exit 1
fi
printf '%s\n' 'Created local .env with generated credentials (mode 600).'
