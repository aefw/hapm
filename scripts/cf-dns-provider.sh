#!/usr/bin/env bash
# cf-dns-provider.sh — lego exec DNS provider untuk Cloudflare
#
# Menggantikan --dns cloudflare dengan kontrol propagasi yang lebih baik:
#   1. Buat TXT record via Cloudflare API
#   2. Poll Cloudflare DoH (HTTPS) sampai record terlihat
#   3. Return — lego (dengan --dns.disable-cp) langsung notify Let's Encrypt
#
# Dipanggil oleh lego dengan argumen:
#   $1 = action  : present | cleanup | timeout
#   $2 = domain  : FQDN TXT record, mis. _acme-challenge.dodols.com.
#   $3 = token   : ACME challenge token
#   $4 = keyAuth : key authorization string
#
# Env yang dibutuhkan:
#   CF_DNS_API_TOKEN         : Cloudflare API token
#   CF_PROPAGATION_MAX_WAIT  : detik maksimum tunggu propagasi (default: 300)
#   CF_PROPAGATION_INTERVAL  : interval polling dalam detik (default: 10)

set -uo pipefail

ACTION="${1:-}"
DOMAIN_RAW="${2:-}"
_TOKEN="${3:-}"
KEY_AUTH="${4:-}"

CF_API="https://api.cloudflare.com/client/v4"
CF_TOKEN="${CF_DNS_API_TOKEN:-}"
MAX_WAIT="${CF_PROPAGATION_MAX_WAIT:-300}"
INTERVAL="${CF_PROPAGATION_INTERVAL:-10}"

# Hapus trailing dot (lego mengirim FQDN dengan titik, mis. _acme-challenge.dodols.com.)
DOMAIN="${DOMAIN_RAW%.}"

log() { echo "[cf-dns-provider] $*" >&2; }
die() { log "ERROR: $*"; exit 1; }

# ── timeout: beri tahu lego berapa lama menunggu propagasi ───────────────────
if [ "$ACTION" = "timeout" ]; then
    echo "$MAX_WAIT"
    echo "$INTERVAL"
    exit 0
fi

[ -z "$CF_TOKEN" ] && die "CF_DNS_API_TOKEN tidak di-set"

log "Action: ${ACTION}, Domain: ${DOMAIN}"

# ── Hitung TXT value: base64url(sha256(keyAuth)) ─────────────────────────────
TXT_VALUE=$(printf '%s' "$KEY_AUTH" \
    | openssl dgst -sha256 -binary \
    | openssl base64 -A \
    | sed 's/+/-/g; s|/|_|g; s/=//g')

log "TXT value (prefix): ${TXT_VALUE:0:16}..."

# ── Cari zone Cloudflare untuk domain ini ────────────────────────────────────
# Ambil bagian setelah subdomain untuk mendapat base domain
get_zone_id() {
    local name="$1"
    # Hapus prefix _acme-challenge. jika ada
    name="${name#_acme-challenge.}"
    # Coba dari domain paling spesifik ke parent domain
    while true; do
        local resp zid
        resp=$(curl -s "${CF_API}/zones?name=${name}&status=active&per_page=1" \
            -H "Authorization: Bearer ${CF_TOKEN}" \
            -H "Content-Type: application/json" 2>/dev/null) || true
        zid=$(echo "$resp" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    r=d.get('result',[])
    if r: print(r[0]['id'])
except: pass
" 2>/dev/null) || true
        if [ -n "$zid" ]; then
            echo "$zid"
            return 0
        fi
        # Kalau tidak ketemu dan tidak ada titik lagi, berhenti
        if echo "$name" | grep -qv '\.'; then
            return 1
        fi
        # Naik satu level domain
        name="${name#*.}"
    done
    return 1
}

ZONE_ID=$(get_zone_id "$DOMAIN") || die "Tidak ditemukan zone Cloudflare untuk ${DOMAIN}"
log "Zone ID: ${ZONE_ID}"

# ── present: buat TXT record + tunggu propagasi via DoH ──────────────────────
if [ "$ACTION" = "present" ]; then
    log "Membuat TXT record ${DOMAIN}..."
    CREATE_RESP=$(curl -s -X POST "${CF_API}/zones/${ZONE_ID}/dns/records" \
        -H "Authorization: Bearer ${CF_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{\"type\":\"TXT\",\"name\":\"${DOMAIN}\",\"content\":\"${TXT_VALUE}\",\"ttl\":60}" \
        2>/dev/null)

    SUCCESS=$(echo "$CREATE_RESP" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    print('yes' if d.get('success') else 'no')
except: print('no')
" 2>/dev/null) || SUCCESS="no"

    if [ "$SUCCESS" != "yes" ]; then
        # Cek apakah sudah ada record (code 81057 = duplicate)
        ERRCODE=$(echo "$CREATE_RESP" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    errs=d.get('errors',[])
    if errs: print(errs[0].get('code',''))
except: pass
" 2>/dev/null) || ERRCODE=""

        if [ "$ERRCODE" = "81057" ]; then
            log "Record sudah ada (duplicate), lanjutkan..."
        else
            log "Cloudflare API response: ${CREATE_RESP}"
            die "Gagal membuat TXT record. Error code: ${ERRCODE:-unknown}"
        fi
    else
        RECORD_ID=$(echo "$CREATE_RESP" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    print(d.get('result',{}).get('id',''))
except: pass
" 2>/dev/null) || RECORD_ID=""
        log "TXT record dibuat, ID: ${RECORD_ID}"
    fi

    # Tunggu sampai terlihat via Cloudflare DoH (HTTPS, tidak kena firewall UDP)
    log "Menunggu propagasi DNS via Cloudflare DoH (maks ${MAX_WAIT}s)..."
    ELAPSED=0
    while [ "$ELAPSED" -lt "$MAX_WAIT" ]; do
        sleep "$INTERVAL"
        ELAPSED=$((ELAPSED + INTERVAL))

        DOH_RESP=$(curl -s \
            "https://cloudflare-dns.com/dns-query?name=${DOMAIN}&type=TXT" \
            -H "Accept: application/dns-json" \
            --max-time 15 \
            2>/dev/null) || { log "DoH query gagal, coba lagi..."; continue; }

        FOUND=$(echo "$DOH_RESP" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    answers=d.get('Answer',[])
    for a in answers:
        if a.get('type')==16:
            val=str(a.get('data','')).strip('\"').replace('\" \"','')
            if '${TXT_VALUE}' in val:
                print('yes')
                sys.exit(0)
except: pass
print('no')
" 2>/dev/null) || FOUND="no"

        if [ "$FOUND" = "yes" ]; then
            log "Record terlihat via DoH setelah ${ELAPSED}s"
            exit 0
        fi
        log "Belum terlihat via DoH (${ELAPSED}/${MAX_WAIT}s)..."
    done

    log "PERINGATAN: Propagasi timeout setelah ${MAX_WAIT}s, tetap lanjutkan"
    exit 0

# ── cleanup: hapus TXT record dari Cloudflare ────────────────────────────────
elif [ "$ACTION" = "cleanup" ]; then
    log "Menghapus TXT record ${DOMAIN}..."

    LIST_RESP=$(curl -s "${CF_API}/zones/${ZONE_ID}/dns/records?type=TXT&name=${DOMAIN}&per_page=100" \
        -H "Authorization: Bearer ${CF_TOKEN}" \
        2>/dev/null) || { log "Gagal list TXT records, skip cleanup"; exit 0; }

    RECORD_IDS=$(echo "$LIST_RESP" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    for r in d.get('result',[]):
        c=str(r.get('content','')).strip('\"')
        if c == '${TXT_VALUE}':
            print(r['id'])
except: pass
" 2>/dev/null) || RECORD_IDS=""

    if [ -z "$RECORD_IDS" ]; then
        log "Tidak ada TXT record yang cocok untuk dihapus"
        exit 0
    fi

    echo "$RECORD_IDS" | while IFS= read -r RID; do
        [ -z "$RID" ] && continue
        DEL_RESP=$(curl -s -X DELETE "${CF_API}/zones/${ZONE_ID}/dns/records/${RID}" \
            -H "Authorization: Bearer ${CF_TOKEN}" 2>/dev/null) || true
        log "Dihapus record ID: ${RID}"
    done
    exit 0

else
    die "Action tidak dikenal: ${ACTION}"
fi
