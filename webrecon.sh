#!/usr/bin/env bash
#
# webrecon.sh — Fast web-interface discovery & fingerprinting
#
# Given a target and a list of ports (or an nmap file), probes each port
# over HTTP and HTTPS, identifies which are web services, and fingerprints
# the technology behind them. Prints a readable report and can export JSON.
#
# Author : CyberAlp0  (https://cyberskii.com)
# License: MIT
#
set -uo pipefail

# ----------------------------------------------------------------------
# Defaults & globals
# ----------------------------------------------------------------------
VERSION="1.1.0"
TIMEOUT=6
CONCURRENCY=10
OUTPUT_JSON=""
QUIET=0
NO_COLOR=0
declare -a RESULTS_JSON=()

# ----------------------------------------------------------------------
# Colors (auto-disabled when piped or --no-color)
# ----------------------------------------------------------------------
setup_colors() {
  if [[ -t 1 && "$NO_COLOR" -eq 0 ]]; then
    C_RESET=$'\e[0m'; C_BOLD=$'\e[1m'
    C_GREEN=$'\e[32m'; C_RED=$'\e[31m'; C_YELLOW=$'\e[33m'
    C_BLUE=$'\e[34m'; C_CYAN=$'\e[36m'; C_DIM=$'\e[2m'
  else
    C_RESET=""; C_BOLD=""; C_GREEN=""; C_RED=""; C_YELLOW=""
    C_BLUE=""; C_CYAN=""; C_DIM=""
  fi
}

# ----------------------------------------------------------------------
# Usage
# ----------------------------------------------------------------------
usage() {
  cat <<EOF
${C_BOLD}webrecon.sh v$VERSION${C_RESET} — web-interface discovery & fingerprinting

${C_BOLD}USAGE${C_RESET}
  $0 -t <target> -p <ports>            [options]
  $0 -t <target> -n <nmap_output_file> [options]

${C_BOLD}REQUIRED${C_RESET}
  -t, --target <host>     Target IP or hostname
  -p, --ports  <list>     Comma-separated ports (e.g. 80,443,6600,8080)
      --or--
  -n, --nmap   <file>     Parse open ports from an nmap -oG / -oN output file

${C_BOLD}OPTIONS${C_RESET}
  -o, --output <file>     Write a JSON report to <file>
  -T, --timeout <secs>    Per-request timeout (default: $TIMEOUT)
  -q, --quiet             Only print confirmed web services
      --no-color          Disable colored output
  -h, --help              Show this help
  -V, --version           Show version

${C_BOLD}EXAMPLES${C_RESET}
  $0 -t 10.129.56.249 -p 80,443,6600,8080
  $0 -t target.htb -p 80,443 -o report.json
  $0 -t 10.10.10.10 -n scan.gnmap --quiet

${C_BOLD}NOTE${C_RESET}
  Authorized testing only. See README for the full workflow
  (nmap -> webrecon -> whatweb) and how it fits together.
EOF
}

# ----------------------------------------------------------------------
# Dependency check
# ----------------------------------------------------------------------
check_deps() {
  local missing=()
  for bin in curl grep sed; do
    command -v "$bin" >/dev/null 2>&1 || missing+=("$bin")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo "${C_RED}[!] Missing required tools: ${missing[*]}${C_RESET}" >&2
    echo "    Install them and try again (e.g. sudo apt install curl)." >&2
    exit 3
  fi
  # openssl is optional: without it we simply skip TLS certificate details
  HAVE_OPENSSL=0
  command -v openssl >/dev/null 2>&1 && HAVE_OPENSSL=1
}

# ----------------------------------------------------------------------
# Parse ports from an nmap output file (grepable or normal)
# ----------------------------------------------------------------------
parse_nmap() {
  local file="$1"
  [[ -f "$file" ]] || { echo "${C_RED}[!] nmap file not found: $file${C_RESET}" >&2; exit 2; }
  # matches "80/open" (grepable) and "80/tcp open" (normal) formats
  grep -oE '[0-9]+/(tcp )?open|[0-9]+/open' "$file" 2>/dev/null \
    | grep -oE '^[0-9]+' | sort -un | paste -sd,
}

# ----------------------------------------------------------------------
# JSON-escape a string (minimal, dependency-free)
# ----------------------------------------------------------------------
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
  s="${s//$'\n'/ }"; s="${s//$'\r'/}"; s="${s//$'\t'/ }"
  printf '%s' "$s"
}

# ----------------------------------------------------------------------
# Inspect the TLS certificate of an HTTPS service.
# Populates the TLS_* globals; leaves them empty if unavailable.
# ----------------------------------------------------------------------
inspect_tls() {
  local target="$1" port="$2"
  TLS_SUBJECT=""; TLS_ISSUER=""; TLS_SANS=""
  TLS_NOTBEFORE=""; TLS_NOTAFTER=""; TLS_EXPIRED=""

  [[ "$HAVE_OPENSSL" -eq 0 ]] && return 0

  local cert
  # -servername enables SNI; timeout guards against hangs on non-TLS ports
  cert=$(echo | timeout "$TIMEOUT" openssl s_client \
            -connect "${target}:${port}" -servername "$target" 2>/dev/null \
          | openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null)
  [[ -z "$cert" ]] && return 0

  TLS_SUBJECT=$(echo "$cert"  | sed -n 's/^subject=//p'   | sed 's/^ *//')
  TLS_ISSUER=$(echo "$cert"   | sed -n 's/^issuer=//p'    | sed 's/^ *//')
  TLS_NOTBEFORE=$(echo "$cert"| sed -n 's/^notBefore=//p')
  TLS_NOTAFTER=$(echo "$cert" | sed -n 's/^notAfter=//p')
  # SANs appear on the line after "X509v3 Subject Alternative Name:"
  TLS_SANS=$(echo "$cert" | grep -A1 -i 'Subject Alternative Name' \
             | tail -1 | sed 's/^ *//;s/DNS://g')

  # Determine expiry by comparing notAfter to now (epoch math)
  if [[ -n "$TLS_NOTAFTER" ]]; then
    local exp_epoch now_epoch
    exp_epoch=$(date -d "$TLS_NOTAFTER" +%s 2>/dev/null)
    now_epoch=$(date +%s)
    if [[ -n "$exp_epoch" ]]; then
      if [[ "$now_epoch" -gt "$exp_epoch" ]]; then
        TLS_EXPIRED="yes"
      else
        TLS_EXPIRED="no"
      fi
    fi
  fi
  return 0
}

# ----------------------------------------------------------------------
# Fingerprint one URL. Echoes a human block; appends a JSON object.
# ----------------------------------------------------------------------
probe_url() {
  local scheme="$1" target="$2" port="$3"
  local url="${scheme}://${target}:${port}"

  local code
  code=$(curl -s -k --max-time "$TIMEOUT" -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
  [[ "$code" == "000" || -z "$code" ]] && return 1   # not web on this scheme

  local headers body
  headers=$(curl -s -k --max-time "$TIMEOUT" -I "$url" 2>/dev/null)
  body=$(curl -s -k --max-time "$TIMEOUT" "$url" 2>/dev/null)

  local server powered location auth ctype title
  server=$(echo "$headers"  | grep -i '^Server:'           | cut -d' ' -f2- | tr -d '\r')
  powered=$(echo "$headers" | grep -i '^X-Powered-By:'     | cut -d' ' -f2- | tr -d '\r')
  location=$(echo "$headers"| grep -i '^Location:'         | cut -d' ' -f2- | tr -d '\r')
  auth=$(echo "$headers"    | grep -i '^WWW-Authenticate:' | cut -d' ' -f2- | tr -d '\r')
  ctype=$(echo "$headers"   | grep -i '^Content-Type:'     | cut -d' ' -f2- | tr -d '\r')
  title=$(echo "$body" | grep -ioP '(?<=<title>).*?(?=</title>)' | head -1 | tr -d '\r' | sed 's/^ *//;s/ *$//')

  # Technology guesses (extend this map freely)
  local tech="" hay="${server} ${powered} ${body}"
  grep -qi 'iis'                <<<"$hay" && tech+=" IIS"
  grep -qi 'apache'             <<<"$hay" && tech+=" Apache"
  grep -qi 'nginx'              <<<"$hay" && tech+=" nginx"
  grep -qi 'werkzeug\|flask'    <<<"$hay" && tech+=" Flask"
  grep -qi 'express'            <<<"$hay" && tech+=" Express"
  grep -qi 'wordpress'          <<<"$hay" && tech+=" WordPress"
  grep -qi 'joomla'             <<<"$hay" && tech+=" Joomla"
  grep -qi 'drupal'             <<<"$hay" && tech+=" Drupal"
  grep -qi 'tomcat'             <<<"$hay" && tech+=" Tomcat"
  grep -qi 'jenkins'            <<<"$hay" && tech+=" Jenkins"
  grep -qi 'grafana'            <<<"$hay" && tech+=" Grafana"
  grep -qi 'gitlab'             <<<"$hay" && tech+=" GitLab"
  grep -qi 'admin center'       <<<"$hay" && tech+=" Windows-Admin-Center"
  grep -qi 'asp\.net\|aspnet'   <<<"$hay" && tech+=" ASP.NET"
  grep -qi 'php'                <<<"$hay" && tech+=" PHP"
  [[ -z "$tech" ]] && tech=" (unknown)"
  tech="${tech# }"

  # ---- human-readable block ----
  local code_color="$C_GREEN"
  [[ "$code" =~ ^3 ]] && code_color="$C_CYAN"
  [[ "$code" =~ ^4 ]] && code_color="$C_YELLOW"
  [[ "$code" =~ ^5 ]] && code_color="$C_RED"

  # TLS certificate details (HTTPS only)
  TLS_SUBJECT=""; TLS_ISSUER=""; TLS_SANS=""; TLS_NOTAFTER=""; TLS_EXPIRED=""
  [[ "$scheme" == "https" ]] && inspect_tls "$target" "$port"

  echo ""
  echo "${C_GREEN}${C_BOLD}[+] WEB SERVICE${C_RESET}  ${C_BOLD}${url}${C_RESET}"
  echo "      Status        : ${code_color}${code}${C_RESET}"
  [[ -n "$server"   ]] && echo "      Server        : $server"
  [[ -n "$powered"  ]] && echo "      X-Powered-By  : $powered"
  [[ -n "$ctype"    ]] && echo "      Content-Type  : $ctype"
  [[ -n "$title"    ]] && echo "      Page title    : ${C_CYAN}${title}${C_RESET}"
  [[ -n "$location" ]] && echo "      Redirects to  : $location"
  [[ -n "$auth"     ]] && echo "      Auth required : ${C_YELLOW}${auth}${C_RESET}"
  echo "      Tech guess    : ${C_BOLD}${tech}${C_RESET}"
  if [[ "$scheme" == "https" && -n "$TLS_SUBJECT" ]]; then
    echo "      ${C_DIM}--- TLS certificate ---${C_RESET}"
    [[ -n "$TLS_SUBJECT"  ]] && echo "      Cert subject  : $TLS_SUBJECT"
    [[ -n "$TLS_ISSUER"   ]] && echo "      Cert issuer   : $TLS_ISSUER"
    [[ -n "$TLS_SANS"     ]] && echo "      Cert SANs     : ${C_CYAN}${TLS_SANS}${C_RESET}"
    [[ -n "$TLS_NOTAFTER" ]] && echo "      Cert expires  : $TLS_NOTAFTER"
    if [[ "$TLS_EXPIRED" == "yes" ]]; then
      echo "      Cert status   : ${C_RED}${C_BOLD}EXPIRED${C_RESET}"
    elif [[ "$TLS_EXPIRED" == "no" ]]; then
      echo "      Cert status   : ${C_GREEN}valid${C_RESET}"
    fi
  fi

  # ---- JSON object ----
  RESULTS_JSON+=("$(cat <<JSON
    {
      "url": "$(json_escape "$url")",
      "scheme": "$scheme",
      "port": $port,
      "status": "$code",
      "server": "$(json_escape "$server")",
      "powered_by": "$(json_escape "$powered")",
      "content_type": "$(json_escape "$ctype")",
      "title": "$(json_escape "$title")",
      "redirect": "$(json_escape "$location")",
      "auth": "$(json_escape "$auth")",
      "tech": "$(json_escape "$tech")",
      "tls": {
        "subject": "$(json_escape "$TLS_SUBJECT")",
        "issuer": "$(json_escape "$TLS_ISSUER")",
        "sans": "$(json_escape "$TLS_SANS")",
        "expires": "$(json_escape "$TLS_NOTAFTER")",
        "expired": "$(json_escape "$TLS_EXPIRED")"
      }
    }
JSON
)")
  return 0
}

# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
main() {
  local target="" ports="" nmap_file=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -t|--target)  target="$2"; shift 2 ;;
      -p|--ports)   ports="$2"; shift 2 ;;
      -n|--nmap)    nmap_file="$2"; shift 2 ;;
      -o|--output)  OUTPUT_JSON="$2"; shift 2 ;;
      -T|--timeout) TIMEOUT="$2"; shift 2 ;;
      -q|--quiet)   QUIET=1; shift ;;
      --no-color)   NO_COLOR=1; shift ;;
      -h|--help)    setup_colors; usage; exit 0 ;;
      -V|--version) echo "webrecon.sh v$VERSION"; exit 0 ;;
      *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
  done

  setup_colors
  check_deps

  [[ -z "$target" ]] && { echo "${C_RED}[!] No target (-t) given.${C_RESET}"; usage; exit 1; }
  [[ -n "$nmap_file" ]] && ports="$(parse_nmap "$nmap_file")"
  [[ -z "$ports" ]] && { echo "${C_RED}[!] No ports (-p or -n) given.${C_RESET}"; usage; exit 1; }

  if [[ "$QUIET" -eq 0 ]]; then
    echo "${C_BOLD}=========================================================${C_RESET}"
    echo "${C_BOLD} webrecon v$VERSION — $target${C_RESET}"
    echo " ${C_DIM}$(date)${C_RESET}"
    echo " Ports: $ports"
    echo "${C_BOLD}=========================================================${C_RESET}"
  fi

  local found=0
  IFS=',' read -ra PORT_ARR <<< "$ports"
  for port in "${PORT_ARR[@]}"; do
    port="$(echo "$port" | tr -d ' ')"
    [[ -z "$port" ]] && continue
    local hit=0
    for scheme in http https; do
      if probe_url "$scheme" "$target" "$port"; then hit=1; found=1; fi
    done
    if [[ "$hit" -eq 0 && "$QUIET" -eq 0 ]]; then
      echo ""
      echo "${C_DIM}[-] Port $port : no web interface (HTTP/HTTPS)${C_RESET}"
    fi
  done

  echo ""
  if [[ "$found" -eq 0 ]]; then
    echo "${C_YELLOW}[*] No web interfaces detected on the given ports.${C_RESET}"
  else
    echo "${C_GREEN}[*] Scan complete.${C_RESET} ${C_DIM}Deep-fingerprint any hit with: whatweb -a3 <url>${C_RESET}"
  fi

  # Write JSON if requested
  if [[ -n "$OUTPUT_JSON" ]]; then
    {
      echo "{"
      echo "  \"target\": \"$(json_escape "$target")\","
      echo "  \"scanned_at\": \"$(date -Iseconds)\","
      echo "  \"results\": ["
      local i
      for i in "${!RESULTS_JSON[@]}"; do
        printf '%s' "${RESULTS_JSON[$i]}"
        [[ $i -lt $((${#RESULTS_JSON[@]} - 1)) ]] && echo "," || echo ""
      done
      echo "  ]"
      echo "}"
    } > "$OUTPUT_JSON"
    echo "${C_CYAN}[*] JSON report written to $OUTPUT_JSON${C_RESET}"
  fi
}

main "$@"
