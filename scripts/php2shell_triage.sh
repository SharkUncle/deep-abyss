#!/usr/bin/env bash
#==============================================================================
# php2shell_triage.sh
#
# READ-ONLY forensic collection + triage of a Linux web server (PHP) that may
# have been exposed to PHP2Shell (CVE-2026-109618 / CVE-2026-109619).
#
# Phases:
#   0  Preparation, context, PHP version / patch status
#   1  Volatile data (processes, network, current persistence)
#   2  PHP2Shell-specific indicators (web logs, PHP errors, child processes of
#      PHP workers, auditd, journal)
#   3  Persistence and post-exploitation (webshells, recent files,
#      cron/systemd/SSH, package integrity)
#   4  Lateral movement / exfiltration (outbound connections, authentications,
#      secret files readable by the PHP process)
#   5  Timeline
#   6  Summary, report, SHA-256 manifest
#
# The script does not modify anything on the analysed system: it only writes
# to the output directory (-o). Preferably use external media or a mounted
# share, not the disk of the suspect server.
#
# IMPORTANT: if a compromise is possible, first take a VM snapshot including
# RAM, or a memory acquisition (LiME / AVML). This script does not do it.
# System binaries (ps, ss, find...) may be tampered with by a rootkit: if
# possible, run the script with trusted tools.
#
# Usage: sudo ./php2shell_triage.sh [options]
#   -s, --since YYYY-MM-DD   start of the analysis window (default: 2026-10-17)
#   -o, --out DIR            output directory
#   -w, --webroot DIR        web root (repeatable; otherwise auto-detected)
#   -l, --logdir DIR         additional log directory (repeatable)
#       --deep               webshell search on ALL PHP files
#                            (not only those modified since --since)
#       --skip-pkgverify     do not verify package integrity
#       --no-copy-logs       do not archive the raw logs
#       --archive            create a .tgz archive of the result
#   -h, --help
#==============================================================================

set -o pipefail
export LC_ALL=C
umask 077

SINCE="2026-10-17"
OUT=""
WEBROOTS=()
LOGDIRS=()
DEEP=0
SKIP_PKG=0
COPY_LOGS=1
ARCHIVE=0

usage() { sed -n '2,/^#====/p' "$0" | sed 's/^# \{0,1\}//' | head -n 52; }

while [ $# -gt 0 ]; do
  case "$1" in
    -s|--since)  [ -n "${2:-}" ] || { usage; exit 1; }; SINCE="$2"; shift 2;;
    -o|--out)    [ -n "${2:-}" ] || { usage; exit 1; }; OUT="$2"; shift 2;;
    -w|--webroot) [ -n "${2:-}" ] || { usage; exit 1; }; WEBROOTS+=("$2"); shift 2;;
    -l|--logdir) [ -n "${2:-}" ] || { usage; exit 1; }; LOGDIRS+=("$2"); shift 2;;
    --deep) DEEP=1; shift;;
    --skip-pkgverify) SKIP_PKG=1; shift;;
    --no-copy-logs) COPY_LOGS=0; shift;;
    --archive) ARCHIVE=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown option: $1" >&2; usage; exit 1;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "This script must be run as root (sudo)." >&2; exit 1; }

SINCE_ISO=$(date -d "$SINCE" +%F 2>/dev/null) || { echo "Invalid date: $SINCE" >&2; exit 1; }
TODAY=$(date +%F)
HOST=$(hostname -s 2>/dev/null || hostname)
[ -n "$OUT" ] || OUT="./php2shell_triage_${HOST}_$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT" || { echo "Cannot create $OUT" >&2; exit 1; }
OUT=$(cd "$OUT" && pwd)
: > "$OUT/FINDINGS.tsv"

# Reduce the impact on a production server (lowest I/O and CPU priority)
ionice -c3 -p $$ >/dev/null 2>&1
renice -n 10 -p $$ >/dev/null 2>&1

#------------------------------------------------------------------------------
# Common helpers
#------------------------------------------------------------------------------
log() { printf '[%s] %s\n' "$(date -u +%H:%M:%SZ)" "$*" | tee -a "$OUT/00_actions.log" >&2; }

# finding SEVERITY PHASE MESSAGE
#   HIGH = strong indicator of compromise, MED = needs investigation,
#   EXPO = exposure (vulnerable version), INFO = information
finding() {
  printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$OUT/FINDINGS.tsv"
  log "[$1] (phase $2) $3"
}

# Number of lines in a file (0 if missing or empty)
nlines() { if [ -s "$1" ]; then wc -l < "$1" | tr -d ' '; else echo 0; fi; }

# Read a log whatever its compression format
catlog() {
  local f
  for f in "$@"; do
    case "$f" in
      *.gz)  zcat -- "$f" 2>/dev/null;;
      *.bz2) bzcat -- "$f" 2>/dev/null;;
      *.xz)  xzcat -- "$f" 2>/dev/null;;
      *)     cat -- "$f" 2>/dev/null;;
    esac
  done
}

# Build a date regex covering every day from --since to today, for a given
# date format (used to filter logs by day)
build_date_regex() {
  local d="$SINCE_ISO" out=""
  while [ "$(date -d "$d" +%s)" -le "$(date -d "$TODAY" +%s)" ]; do
    out+="$(date -d "$d" "+$1")|"
    d=$(date -d "$d + 1 day" +%F)
  done
  echo "${out%|}"
}
DRE_WEB=$(build_date_regex '%d/%b/%Y')   # 17/Oct/2026  (nginx/Apache access logs)
DRE_SYS=$(build_date_regex '%b %e')      # Oct 17  /  Oct  7  (classic syslog)
DRE_ISO=$(build_date_regex '%F')         # 2026-10-17  (ISO timestamps)

# List PHP-like files under the web roots; extra arguments are passed to find
find_php_files() {
  find "${WEBROOTS[@]}" -xdev -type f \
    \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.phar' -o -iname '*.pht' \
       -o -iname '*.php[3-8]' -o -iname '*.inc' \) "$@"
}

# Webshell patterns (deliberately strict: false negatives are possible)
WS_RE='(eval|assert|create_function)[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode|\$_(GET|POST|REQUEST|COOKIE|SERVER))|(system|shell_exec|passthru|exec|popen|proc_open|pcntl_exec)[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE|SERVER)|base64_decode[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE)'

#==============================================================================
# PHASE 0: preparation
#==============================================================================
phase0() {
  log "== Phase 0: preparation (window: since $SINCE_ISO) =="
  local d="$OUT/00_context"; mkdir -p "$d"

  {
    echo "host          : $(hostname -f 2>/dev/null || hostname)"
    echo "date (UTC)    : $(date -u +%FT%TZ)"
    echo "time zone     : $(date +%Z) ($(date +%z))"
    echo "window        : since $SINCE_ISO"
    echo "kernel        : $(uname -a)"
    echo "uptime        : $(uptime)"
    echo "run by        : $(id)"
    echo "script SHA256 : $(sha256sum "$0" 2>/dev/null | awk '{print $1}')"
    echo; cat /etc/os-release 2>/dev/null
  } > "$d/contexte.txt"

  # Storage warning
  local wfs; wfs=$(df -P "$OUT" | awk 'NR==2{print $1" ("$6")"}')
  log "Output written to: $wfs. Prefer external media over the suspect server's own disk."

  # Accounts running the web workers
  WEBUSERS=$(ps -eo user:32=,comm= 2>/dev/null \
    | awk '$2 ~ /^(php|php-fpm|php-cgi|lsphp|apache2|httpd|nginx|frankenphp)/ && $1!="root"{print $1}' | sort -u)
  [ -n "$WEBUSERS" ] || WEBUSERS="www-data apache nginx www"
  echo "$WEBUSERS" > "$d/utilisateurs_web.txt"

  # Web roots: auto-detect from nginx/Apache configuration and usual locations,
  # then drop paths nested under another detected root
  if [ "${#WEBROOTS[@]}" -eq 0 ]; then
    local cand
    cand=$( {
      grep -rhiE '^[[:space:]]*root[[:space:]]+' /etc/nginx 2>/dev/null | awk '{gsub(";","",$2); print $2}'
      grep -rhiE '^[[:space:]]*DocumentRoot[[:space:]]+' /etc/apache2 /etc/httpd 2>/dev/null | awk '{gsub("\"","",$2); print $2}'
      ls -d /var/www /srv/www /usr/share/nginx/html /home/*/public_html /var/www/vhosts/*/httpdocs 2>/dev/null
    } | grep -E '^/' | sort -u )
    local keep="" p
    while IFS= read -r p; do
      [ -d "$p" ] || continue
      case "$p" in "$keep"/*) continue;; esac
      WEBROOTS+=("$p"); keep="$p"
    done <<< "$cand"
  fi
  printf '%s\n' "${WEBROOTS[@]}" > "$d/racines_web.txt"
  log "Web roots: ${WEBROOTS[*]:-(none detected, use -w)}"
  [ "${#WEBROOTS[@]}" -gt 0 ] || finding MED 0 "No web root detected: file-based checks will be incomplete (use -w)"

  # PHP versions and patch status
  local bins b v maj min pat need
  bins=$( {
    for n in php php-cli php-fpm php-cgi; do command -v "$n"; done
    ls /usr/sbin/php-fpm* /usr/bin/php[0-9]* /usr/local/bin/php /usr/local/sbin/php-fpm \
       /opt/remi/php*/root/usr/bin/php /opt/remi/php*/root/usr/sbin/php-fpm 2>/dev/null
  } 2>/dev/null | sort -u )
  # Fix backported by the distribution? (version numbers then stay "old")
  {
    command -v dpkg >/dev/null && dpkg -l 'php*' 2>/dev/null | grep '^ii'
    command -v rpm  >/dev/null && rpm -qa 'php*' 2>/dev/null
  } > "$d/paquets_php.txt"
  local sev_expo=EXPO note_bp=""
  if zgrep -sl 'CVE-2026-109618' /usr/share/doc/php*/changelog* >/dev/null 2>&1 \
     || { command -v rpm >/dev/null && rpm -q --changelog $(rpm -qa 'php*' 2>/dev/null) 2>/dev/null | grep -qm1 'CVE-2026-109618'; }; then
    sev_expo=INFO; note_bp=" [package changelog mentions CVE-2026-109618, fix probably backported: to be confirmed]"
    finding INFO 0 "PHP package changelog mentions CVE-2026-109618 (fix probably backported; also check CVE-2026-109619)"
  fi
  : > "$d/php_versions.txt"
  while IFS= read -r b; do
    [ -x "$b" ] || continue
    v=$("$b" -v 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    echo "$b -> ${v:-unknown}" >> "$d/php_versions.txt"
    [ -n "$v" ] || continue
    IFS=. read -r maj min pat <<< "$v"; pat=$((10#$pat))
    # First patched release per supported branch (published fixes of 21 Oct 2026)
    case "$maj.$min" in
      8.5) need=12;; 8.4) need=27;; 8.3) need=36;; 8.2) need=35;; *) need=0;;
    esac
    if [ "$need" -eq 0 ]; then
      if [ "$maj" -lt 8 ] || { [ "$maj" -eq 8 ] && [ "$min" -le 1 ]; }; then
        finding "$sev_expo" 0 "$b: PHP $v, branch without an official fix (migration required)$note_bp"
      else
        finding INFO 0 "$b: PHP $v, branch not recognised by this script, check the fix status"
      fi
    elif [ "$pat" -lt "$need" ]; then
      finding "$sev_expo" 0 "$b: PHP $v < $maj.$min.$need (vulnerable, unless the distribution backported the fix)$note_bp"
    else
      finding INFO 0 "$b: PHP $v >= $maj.$min.$need (fix present)"
    fi
  done <<< "$bins"

  # SAPIs in use (mod_php is the most exposed according to public analyses)
  {
    echo "--- running php-fpm / apache / nginx:"; ps -eo pid,user:20,comm | grep -E 'php|apache2|httpd|nginx|lsphp' | grep -v grep | head -50
    echo "--- apache php modules:"; (apachectl -M 2>/dev/null || apache2ctl -M 2>/dev/null || httpd -M 2>/dev/null) | grep -i php
    ls /etc/apache2/mods-enabled 2>/dev/null | grep -i php
  } > "$d/sapi.txt" 2>&1
  grep -qiE 'php[0-9._]*_module|libphp' "$d/sapi.txt" && \
    finding INFO 0 "mod_php detected (the most exposed SAPI according to public analyses)"
}

#==============================================================================
# PHASE 1: volatile data
#==============================================================================
phase1() {
  log "== Phase 1: volatile data =="
  local d="$OUT/01_volatile"; mkdir -p "$d"

  { date -u; uptime; who -a; echo; last -Faiw 2>/dev/null | head -300; } > "$d/sessions.txt" 2>&1
  ps -eo pid,ppid,user:32,lstart,etime,args --forest > "$d/ps_forest.txt" 2>&1
  ss -tunap > "$d/ss_all.txt" 2>&1
  lsof -nP > "$d/lsof.txt" 2>&1
  lsof -nP +L1 > "$d/lsof_fichiers_supprimes_ouverts.txt" 2>&1
  { ip -br a; ip r; ip neigh; } > "$d/reseau.txt" 2>&1
  { iptables-save; nft list ruleset; } > "$d/pare_feu.txt" 2>&1
  lsmod > "$d/lsmod.txt" 2>&1
  findmnt > "$d/montages.txt" 2>&1
  env > "$d/env_script.txt" 2>&1
  systemctl list-units --type=service,timer --all --no-pager > "$d/systemd_units.txt" 2>&1
  { cat /etc/ld.so.preload 2>/dev/null; echo "---"; cat /proc/sys/kernel/tainted; } > "$d/ld_preload_taint.txt" 2>&1

  # Crontabs of every user, system cron directories, at jobs
  { for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | sed "s/^/[$u] /"; done
    echo "--- /etc/cron* :"; ls -laR /etc/cron* /var/spool/cron 2>/dev/null
    echo "--- at :"; atq 2>/dev/null; } > "$d/cron.txt" 2>&1

  # Shell histories (copied as evidence)
  mkdir -p "$d/historiques"
  for f in /root/.bash_history /home/*/.bash_history /var/www/.bash_history; do
    [ -f "$f" ] && cp -p "$f" "$d/historiques/$(echo "$f" | tr '/' '_')" 2>/dev/null
  done

  # Processes whose executable is deleted / in a temp directory / memfd
  local p pid exe
  for p in /proc/[0-9]*; do
    pid=${p#/proc/}; exe=$(readlink "$p/exe" 2>/dev/null) || continue
    case "$exe" in
      *"(deleted)"*|/tmp/*|/var/tmp/*|/dev/shm/*|*memfd:*)
        echo "$pid $exe :: $(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)";;
    esac
  done > "$d/proc_exe_suspects.txt"
  [ -s "$d/proc_exe_suspects.txt" ] && \
    finding HIGH 1 "$(nlines "$d/proc_exe_suspects.txt") process(es) with a deleted executable / running from /tmp,/dev/shm / memfd (01_volatile/proc_exe_suspects.txt)"

  # PIDs visible in /proc but absent from ps (possible hiding; noisy, info only)
  diff <(ls /proc | grep -E '^[0-9]+$' | sort -n) <(ps -e -o pid= | tr -d ' ' | sort -n) \
    > "$d/pid_proc_vs_ps.txt" 2>&1

  [ -s /etc/ld.so.preload ] && finding HIGH 1 "/etc/ld.so.preload is not empty (userland rootkit technique)"
  awk -F: '$3==0 && $1!="root"{print}' /etc/passwd > "$d/uid0_non_root.txt"
  [ -s "$d/uid0_non_root.txt" ] && finding HIGH 1 "UID 0 account(s) other than root: $(cat "$d/uid0_non_root.txt" | cut -d: -f1 | tr '\n' ' ')"
  local taint; taint=$(cat /proc/sys/kernel/tainted 2>/dev/null)
  [ "${taint:-0}" != "0" ] && finding INFO 1 "Kernel 'tainted' = $taint (unsigned module or other cause; interpret manually)"
}

#==============================================================================
# PHASE 2: PHP2Shell indicators (logs, processes, auditd)
#==============================================================================
ACCESS=(); ERRLOGS=(); ALLLOGS=()

# Locate web access logs and error/PHP logs (nginx, Apache, Plesk vhosts, PHP-FPM...)
discover_logs() {
  local dir f
  for dir in /var/log/nginx /var/log/apache2 /var/log/apache /var/log/httpd /var/log/caddy \
             /var/log/php* /var/www/vhosts/*/logs /usr/local/apache*/logs "${LOGDIRS[@]}"; do
    [ -d "$dir" ] || continue
    while IFS= read -r -d '' f; do
      ALLLOGS+=("$f")
      case "${f##*/}" in
        *access*) ACCESS+=("$f");;
        *error*|*php*) ERRLOGS+=("$f");;
      esac
    done < <(find "$dir" -maxdepth 3 -type f \( -name '*.log' -o -name '*.log.*' -o -name '*_log' -o -name '*_log.*' \) -print0 2>/dev/null)
  done
  # PHP-FPM / PHP logs located directly in /var/log
  for f in /var/log/php*-fpm.log* /var/log/php-fpm*.log* /var/log/php_errors.log*; do
    [ -f "$f" ] && { ALLLOGS+=("$f"); ERRLOGS+=("$f"); }
  done
}

phase2() {
  log "== Phase 2: PHP2Shell-specific indicators =="
  local d="$OUT/02_indicateurs"; mkdir -p "$d"
  discover_logs
  log "Access logs: ${#ACCESS[@]}; error logs: ${#ERRLOGS[@]}"
  printf '%s\n' "${ALLLOGS[@]}" > "$d/liste_logs.txt"

  # Archive the raw logs (primary evidence)
  if [ "$COPY_LOGS" -eq 1 ] && [ "${#ALLLOGS[@]}" -gt 0 ]; then
    printf '%s\0' "${ALLLOGS[@]}" | tar --null -czf "$OUT/raw_logs.tgz" -T - 2>/dev/null
    log "Raw logs archived: raw_logs.tgz"
  fi

  # Time coverage of the access logs (first and last timestamp of each file)
  : > "$d/couverture_logs_acces.txt"
  local f
  for f in "${ACCESS[@]}"; do
    printf '%s\t' "$f" >> "$d/couverture_logs_acces.txt"
    catlog "$f" | awk 'NR==1{a=$4} {b=$4} END{print a" -> "b}' >> "$d/couverture_logs_acces.txt"
  done
  [ "${#ACCESS[@]}" -eq 0 ] && finding MED 2 "No web access log found (use -l): HTTP analysis skipped"

  # Assumes the "combined" log format: $1=IP, $4=time, $6=method, $7=URL, $9=status
  local A="$d/access_depuis_${SINCE_ISO}.log"
  if [ "${#ACCESS[@]}" -gt 0 ]; then
    catlog "${ACCESS[@]}" | grep -E "\[($DRE_WEB):" > "$A"
    finding INFO 2 "Access logs: $(nlines "$A") lines since $SINCE_ISO (check coverage: 02_indicateurs/couverture_logs_acces.txt)"

    # a) POST requests ending in 5xx (exploit setup phase; not systematic)
    awk '$6=="\"POST" && $9>=500' "$A" > "$d/http_post_5xx.txt"
    [ -s "$d/http_post_5xx.txt" ] && finding INFO 2 "$(nlines "$d/http_post_5xx.txt") POST request(s) ending in 5xx (02_indicateurs/http_post_5xx.txt)"
    awk '$9>=500{print substr($4,2,14)}' "$A" | sort | uniq -c > "$d/http_5xx_par_heure.txt"
    awk '$6=="\"POST" && $9>=500{print $1}' "$A" | sort | uniq -c | sort -rn | head -50 > "$d/http_top_ip_post_5xx.txt"

    # b) User-Agents of publicly reported exploitation tools
    grep -iE 'php2shell|php2shell-scan|php2shell-verify|php2shell-poc' "$A" > "$d/http_ua_ioc.txt"
    [ -s "$d/http_ua_ioc.txt" ] && finding MED 2 "$(nlines "$d/http_ua_ioc.txt") request(s) with a known PHP2Shell tool User-Agent (attempts; correlate with phase 3)"

    # c) upload_progress markers in logged URLs / headers
    grep -iE 'PHP_SESSION_UPLOAD_PROGRESS|upload_progress' "$A" > "$d/http_upload_progress.txt"
    [ -s "$d/http_upload_progress.txt" ] && finding MED 2 "upload_progress markers in access logs (02_indicateurs/http_upload_progress.txt)"

    # d) PHP files executed from data directories (likely webshell)
    grep -E '/(uploads?|cache|tmp|temp|media|files|images?|assets)/[^ "?]*\.(php[0-9]?|phtml|phar|pht)' "$A" \
      | awk '$9==200' > "$d/http_php_dans_repertoires_donnees_200.txt"
    [ -s "$d/http_php_dans_repertoires_donnees_200.txt" ] && \
      finding HIGH 2 "$(nlines "$d/http_php_dans_repertoires_donnees_200.txt") request(s) returning 200 for .php files in uploads/cache/tmp/media (likely webshell)"

    # e) Most POSTed PHP URLs (webshells = few URLs, many POSTs)
    awk '$6=="\"POST" && $7 ~ /\.(php|phtml|phar)/{split($7,u,"?"); print u[1]}' "$A" \
      | sort | uniq -c | sort -rn | head -50 > "$d/http_top_urls_post_php.txt"

    # Timestamped extract of suspicious requests, reused in the timeline
    { cat "$d/http_ua_ioc.txt" "$d/http_upload_progress.txt" "$d/http_post_5xx.txt" \
          "$d/http_php_dans_repertoires_donnees_200.txt"; } 2>/dev/null | sort -u > "$d/evenements_http_suspects.txt"
  fi

  # PHP errors / worker crashes (counts per file, then matching lines since --since)
  : > "$d/php_erreurs.txt"
  local c
  for f in "${ERRLOGS[@]}"; do
    c=$(catlog "$f" | grep -ciE 'Allowed memory size|out of memory|exited on signal|SIGSEGV|segfault|zend_mm|illegal session|upload_progress')
    [ "${c:-0}" -gt 0 ] && echo "$c $f" >> "$d/php_erreurs.txt"
  done
  [ "${#ERRLOGS[@]}" -gt 0 ] && catlog "${ERRLOGS[@]}" \
    | grep -iE 'Allowed memory size|out of memory|exited on signal|SIGSEGV|segfault|zend_mm|illegal session|upload_progress' \
    | grep -E "($DRE_ISO|$DRE_SYS|$DRE_WEB)" | head -5000 > "$d/php_erreurs_lignes_depuis_since.txt"
  [ -s "$d/php_erreurs.txt" ] && finding INFO 2 "Memory errors / PHP crashes in error logs (02_indicateurs/php_erreurs.txt): sign of an attempt, not proof of success"

  # System journal and kernel messages
  if command -v journalctl >/dev/null; then
    journalctl --no-pager --since "$SINCE_ISO" -u 'php*fpm*' -u 'apache2' -u 'httpd' -u 'nginx' 2>/dev/null \
      | grep -iE 'SIGSEGV|SIGABRT|exited on signal|out of memory|segfault' > "$d/journal_workers.txt"
    journalctl --no-pager --since "$SINCE_ISO" -k 2>/dev/null | grep -iE 'segfault|oom|out of memory' > "$d/journal_noyau.txt"
  fi
  dmesg -T 2>/dev/null | grep -iE 'segfault|out of memory|oom-kill' > "$d/dmesg_segfault_oom.txt"
  local nseg; nseg=$(cat "$d/journal_workers.txt" "$d/journal_noyau.txt" "$d/dmesg_segfault_oom.txt" 2>/dev/null | wc -l | tr -d ' ')
  [ "${nseg:-0}" -gt 0 ] && finding MED 2 "$nseg crash/segfault/OOM line(s) (web workers or kernel) since $SINCE_ISO"

  # --- Most reliable signal: abnormal child processes of PHP/web workers.
  # Build a pid -> parent map from ps and flag shells, downloaders and
  # interpreters whose parent is a PHP or web server process.
  ps -eo pid=,ppid=,user:32=,comm= | awk '
    {c[$1]=$4; pp[$1]=$2; u[$1]=$3}
    END{for (p in c){ par=c[pp[p]];
      if (par ~ /^(php|php-fpm|php-cgi|php[0-9.-]+|lsphp|apache2|httpd|nginx|frankenphp)/ &&
          c[p] ~ /^(sh|bash|dash|zsh|ash|busybox|curl|wget|nc|ncat|netcat|socat|python[0-9.]*|perl|ruby|telnet|openssl|php)$/)
        print p, pp[p], u[p], par, c[p]}}' > "$d/enfants_suspects_instantane.txt"
  if [ -s "$d/enfants_suspects_instantane.txt" ]; then
    while read -r pid ppid usr par com; do
      echo "$pid $usr parent=$par($ppid) :: $(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null)"
    done < "$d/enfants_suspects_instantane.txt" > "$d/enfants_suspects_detail.txt"
    finding HIGH 2 "Suspicious child process of a running web worker (02_indicateurs/enfants_suspects_detail.txt)"
  fi

  # All processes of the web accounts that are not web workers (manual review)
  local u
  for u in $WEBUSERS; do
    id "$u" >/dev/null 2>&1 && ps -u "$u" -o pid,ppid,lstart,args 2>/dev/null | grep -vE 'php-fpm|apache2|httpd|nginx' | sed "s/^/[$u] /"
  done > "$d/processus_comptes_web_hors_workers.txt"

  # Execution history through auditd, if available (ausearch -ts expects MM/DD/YYYY)
  if command -v ausearch >/dev/null; then
    local tsd; tsd=$(date -d "$SINCE_ISO" +%m/%d/%Y)
    : > "$d/auditd_execve_comptes_web.txt"
    for u in $WEBUSERS; do
      ausearch -m SYSCALL -sc execve -ts "$tsd" -ui "$u" -i 2>/dev/null >> "$d/auditd_execve_comptes_web.txt"
    done
    grep -E 'exe=/(usr/)?(s?bin|local/bin)/(sh|bash|dash|curl|wget|nc|ncat|socat|python[0-9.]*|perl|ruby)' \
      "$d/auditd_execve_comptes_web.txt" > "$d/auditd_execve_suspects.txt"
    [ -s "$d/auditd_execve_suspects.txt" ] && \
      finding HIGH 2 "auditd: execve of a shell/downloader by a web account since $SINCE_ISO (02_indicateurs/auditd_execve_suspects.txt)"
  else
    finding INFO 2 "auditd not available: no process execution history (use the EDR if present, e.g. php-fpm/apache2 parents)"
  fi
}

#==============================================================================
# PHASE 3: persistence and post-exploitation
#==============================================================================
phase3() {
  log "== Phase 3: persistence and post-exploitation =="
  local d="$OUT/03_persistance"; mkdir -p "$d"
  local u

  if [ "${#WEBROOTS[@]}" -gt 0 ]; then
    # Files modified since --since under the web roots
    find "${WEBROOTS[@]}" -xdev -type f -newermt "$SINCE_ISO" \
      -printf '%TY-%Tm-%Td %TH:%TM:%TS\t%u:%g\t%m\t%s\t%p\n' 2>/dev/null | sort > "$d/web_fichiers_modifies.txt"
    find_php_files -newermt "$SINCE_ISO" \
      -printf '%TY-%Tm-%Td %TH:%TM:%TS\t%u:%g\t%m\t%s\t%p\n' 2>/dev/null | sort > "$d/web_php_modifies.txt"
    finding INFO 3 "$(nlines "$d/web_php_modifies.txt") PHP file(s) modified since $SINCE_ISO (rule out legitimate deployments)"

    # PHP files in data directories (almost never legitimate)
    find_php_files \( -path '*upload*' -o -path '*/cache/*' -o -path '*/tmp/*' -o -path '*/media/*' -o -path '*/files/*' \) \
      -printf '%TY-%Tm-%Td %TH:%TM\t%u:%g\t%m\t%p\n' 2>/dev/null | sort > "$d/web_php_dans_repertoires_donnees.txt"
    [ -s "$d/web_php_dans_repertoires_donnees.txt" ] && \
      finding MED 3 "$(nlines "$d/web_php_dans_repertoires_donnees.txt") PHP file(s) in data directories (uploads/cache/tmp/media/files)"

    # Webshell pattern search (recent files only, or everything with --deep)
    if [ "$DEEP" -eq 1 ]; then
      find_php_files -print0 2>/dev/null | xargs -0 -r grep -IlE "$WS_RE" > "$d/webshell_motifs.txt" 2>/dev/null
    else
      find_php_files -newermt "$SINCE_ISO" -print0 2>/dev/null | xargs -0 -r grep -IlE "$WS_RE" > "$d/webshell_motifs.txt" 2>/dev/null
    fi
    if [ -s "$d/webshell_motifs.txt" ]; then
      xargs -a "$d/webshell_motifs.txt" -d '\n' -r sha256sum > "$d/webshell_motifs_sha256.txt" 2>/dev/null
      finding HIGH 3 "$(nlines "$d/webshell_motifs.txt") PHP file(s) matching a webshell pattern (03_persistance/webshell_motifs.txt; validate manually)"
    fi

    # PHP configuration overrides (persistence through auto_prepend_file, etc.);
    # commented-out lines are ignored
    grep -rnIE 'auto_prepend_file|auto_append_file|allow_url_include|disable_functions[[:space:]]*=[[:space:]]*$' \
      "${WEBROOTS[@]}" /etc/php* /etc/apache2 /etc/httpd /etc/nginx 2>/dev/null \
      | grep -vE '^[^:]*:[0-9]+:[[:space:]]*[;#]' > "$d/php_surcharges_config.txt"
    find "${WEBROOTS[@]}" -xdev \( -name '.user.ini' -o -name '.htaccess' -o -name 'php.ini' \) -newermt "$SINCE_ISO" \
      -printf '%TY-%Tm-%Td %TH:%TM\t%u\t%p\n' 2>/dev/null > "$d/php_ini_htaccess_modifies.txt"
    [ -s "$d/php_ini_htaccess_modifies.txt" ] && \
      finding MED 3 "$(nlines "$d/php_ini_htaccess_modifies.txt") .user.ini/.htaccess/php.ini file(s) modified since $SINCE_ISO"
    grep -E 'auto_(prepend|append)_file' "$d/php_surcharges_config.txt" | grep -E '\.user\.ini|\.htaccess' > "$d/php_prepend_dans_surcharges_locales.txt"
    [ -s "$d/php_prepend_dans_surcharges_locales.txt" ] && \
      finding HIGH 3 "auto_prepend_file/auto_append_file set in .user.ini or .htaccess (03_persistance/php_prepend_dans_surcharges_locales.txt)"
  fi

  # Recent temporary files; flag ELF binaries and scripts by their file type
  find /tmp /var/tmp /dev/shm -xdev -type f -newermt "$SINCE_ISO" -ls 2>/dev/null > "$d/tmp_recents.txt"
  if command -v file >/dev/null && [ -s "$d/tmp_recents.txt" ]; then
    awk '{print $NF}' "$d/tmp_recents.txt" | xargs -r -d '\n' file 2>/dev/null | awk -F': ' '{t=$NF} t ~ /ELF|script|PHP/' > "$d/tmp_executables_ou_scripts.txt"
    [ -s "$d/tmp_executables_ou_scripts.txt" ] && \
      finding HIGH 3 "Recent ELF binaries or scripts in /tmp, /var/tmp, /dev/shm (03_persistance/tmp_executables_ou_scripts.txt)"
  fi

  # Files owned by web accounts outside the web roots and expected locations
  : > "$d/fichiers_comptes_web_hors_webroot.txt"
  local excl=( ! -path '/proc/*' ! -path '/sys/*' ! -path '/var/log/*' ! -path '/var/cache/*' \
               ! -path '/var/lib/php/*' ! -path '/run/*' ! -path '/tmp/systemd-private-*' )
  for r in "${WEBROOTS[@]}"; do excl+=( ! -path "$r/*" ); done
  for u in $WEBUSERS; do
    id "$u" >/dev/null 2>&1 || continue
    find / -xdev -user "$u" -type f -newermt "$SINCE_ISO" "${excl[@]}" \
      -printf '%TY-%Tm-%Td %TH:%TM\t%u\t%m\t%p\n' 2>/dev/null >> "$d/fichiers_comptes_web_hors_webroot.txt"
  done
  [ -s "$d/fichiers_comptes_web_hors_webroot.txt" ] && \
    finding MED 3 "$(nlines "$d/fichiers_comptes_web_hors_webroot.txt") recent file(s) owned by a web account outside the web roots"

  # Recent SUID / SGID binaries
  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -newermt "$SINCE_ISO" \
    -printf '%TY-%Tm-%Td %TH:%TM\t%u\t%m\t%p\n' 2>/dev/null > "$d/suid_sgid_recents.txt"
  [ -s "$d/suid_sgid_recents.txt" ] && finding HIGH 3 "SUID/SGID binaries created or modified since $SINCE_ISO (03_persistance/suid_sgid_recents.txt)"

  # Persistence: cron, systemd, SSH, sudoers, /etc
  find /etc/cron* /var/spool/cron /etc/systemd /usr/lib/systemd /lib/systemd /etc/init.d /etc/rc.local /etc/profile.d \
    -type f -newermt "$SINCE_ISO" -printf '%TY-%Tm-%Td %TH:%TM\t%u\t%p\n' 2>/dev/null > "$d/persistance_cron_systemd_recents.txt"
  [ -s "$d/persistance_cron_systemd_recents.txt" ] && \
    finding MED 3 "$(nlines "$d/persistance_cron_systemd_recents.txt") cron/systemd/init file(s) modified since $SINCE_ISO"
  find /root/.ssh /home/*/.ssh /var/www/.ssh -type f -newermt "$SINCE_ISO" \
    -printf '%TY-%Tm-%Td %TH:%TM\t%u\t%p\n' 2>/dev/null > "$d/ssh_recents.txt"
  [ -s "$d/ssh_recents.txt" ] && finding HIGH 3 ".ssh files modified since $SINCE_ISO (authorized keys added?) (03_persistance/ssh_recents.txt)"
  find /etc -xdev -type f -newermt "$SINCE_ISO" -printf '%TY-%Tm-%Td %TH:%TM\t%u\t%p\n' 2>/dev/null > "$d/etc_recents.txt"
  for f in /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/sudoers.d/*; do
    [ -e "$f" ] && stat -c '%y %n' "$f"
  done > "$d/comptes_sudoers_mtime.txt" 2>/dev/null
  lastlog 2>/dev/null | grep -v 'Never logged in' > "$d/lastlog.txt"

  # Package integrity (modified system binaries); configuration files, flagged
  # " c ", are excluded because they legitimately differ
  if [ "$SKIP_PKG" -eq 0 ]; then
    if command -v dpkg >/dev/null; then
      timeout 900 dpkg --verify > "$d/pkg_verify.txt" 2>&1
      grep -E '^..5' "$d/pkg_verify.txt" | grep -E ' /(usr/)?(s?bin|lib|lib64)/' | grep -vE ' c /' > "$d/pkg_verify_binaires_modifies.txt"
    elif command -v rpm >/dev/null; then
      timeout 900 rpm -Va > "$d/pkg_verify.txt" 2>&1
      grep -E '^..5' "$d/pkg_verify.txt" | grep -E ' /(usr/)?(s?bin|lib|lib64)/' | grep -vE ' c /' > "$d/pkg_verify_binaires_modifies.txt"
    fi
    [ -s "$d/pkg_verify_binaires_modifies.txt" ] && \
      finding MED 3 "$(nlines "$d/pkg_verify_binaires_modifies.txt") system binary(ies) whose hash differs from the package (03_persistance/pkg_verify_binaires_modifies.txt)"
  fi
}

#==============================================================================
# PHASE 4: lateral movement / exfiltration
#==============================================================================
phase4() {
  log "== Phase 4: lateral movement and exfiltration =="
  local d="$OUT/04_lateral"; mkdir -p "$d"

  # Established connections whose local port is not a listening port
  # (i.e. outbound connections), then split by owning process
  local lp
  lp=$(ss -Hltn 2>/dev/null | awk '{n=split($4,a,":"); print a[n]}' | sort -u | tr '\n' '|' | sed 's/|$//')
  ss -Hntp state established 2>/dev/null \
    | awk -v lp="^(${lp})$" '{n=split($3,a,":"); if (a[n] !~ lp) print}' > "$d/connexions_sortantes.txt"
  grep -E '"(sh|bash|dash|zsh|nc|ncat|netcat|socat|python[0-9.]*|perl|ruby|curl|wget)"' "$d/connexions_sortantes.txt" > "$d/connexions_sortantes_shells.txt"
  [ -s "$d/connexions_sortantes_shells.txt" ] && \
    finding HIGH 4 "Outbound connection established by a shell/interpreter (possible reverse shell) (04_lateral/connexions_sortantes_shells.txt)"
  grep -E '"(php[^"]*|apache2|httpd|nginx|lsphp)"' "$d/connexions_sortantes.txt" > "$d/connexions_sortantes_workers_web.txt"
  [ -s "$d/connexions_sortantes_workers_web.txt" ] && \
    finding MED 4 "Outbound connections established from web workers (compare with the baseline: legitimate APIs, databases, SMTP) (04_lateral/connexions_sortantes_workers_web.txt)"

  # Authentications since --since (auth.log / secure, plus journald for sshd)
  : > "$d/auth_depuis_since.txt"
  local f
  for f in /var/log/auth.log* /var/log/secure*; do
    [ -f "$f" ] && catlog "$f" | grep -E "^($DRE_SYS|$DRE_ISO)" \
      | grep -E 'sshd.*(Accepted|Failed|Invalid)|sudo:|useradd|usermod|groupadd|passwd\[' >> "$d/auth_depuis_since.txt"
  done
  command -v journalctl >/dev/null && journalctl --no-pager --since "$SINCE_ISO" -u ssh -u sshd 2>/dev/null \
    | grep -E 'Accepted|Failed|Invalid' >> "$d/auth_depuis_since.txt"
  grep -h 'Accepted' "$d/auth_depuis_since.txt" | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' \
    | sort | uniq -c | sort -rn > "$d/ssh_accepted_par_ip.txt"
  grep -hE 'useradd|usermod|groupadd|new user' "$d/auth_depuis_since.txt" > "$d/creation_comptes.txt"
  [ -s "$d/creation_comptes.txt" ] && finding MED 4 "Account creation/modification since $SINCE_ISO (04_lateral/creation_comptes.txt)"

  # Secret files readable by the PHP process (contents are NOT collected)
  if [ "${#WEBROOTS[@]}" -gt 0 ]; then
    find "${WEBROOTS[@]}" -xdev -maxdepth 6 -type f \
      \( -name wp-config.php -o -name '.env' -o -name '.env.*' -o -name configuration.php -o -name settings.php \
         -o -name config.inc.php -o -name parameters.yml -o -name env.php -o -name database.php \) \
      -printf '%u:%g\t%m\t%TY-%Tm-%Td\t%p\n' 2>/dev/null > "$d/fichiers_secrets_liste.txt"
    [ -s "$d/fichiers_secrets_liste.txt" ] && \
      finding INFO 4 "$(nlines "$d/fichiers_secrets_liste.txt") configuration file(s) holding secrets readable by PHP (contents not collected): rotate them if exposure is confirmed, since the PHP2Shell memory leak leaves no webshell"
  fi
}

#==============================================================================
# PHASE 5: timeline
#==============================================================================
phase5() {
  log "== Phase 5: timeline =="
  local d="$OUT/05_timeline"; mkdir -p "$d"
  # File-based timeline (mtime and ctime) over the usual attacker locations
  local roots=( /etc /tmp /var/tmp /dev/shm /root /home /opt /usr/local /usr/bin /usr/sbin /var/spool/cron "${WEBROOTS[@]}" )
  local existing=() r
  for r in "${roots[@]}"; do [ -e "$r" ] && existing+=("$r"); done
  { printf 'mtime\tctime\tuser\tgroup\tmode\tsize\tpath\n'
    find "${existing[@]}" -xdev -type f \( -newermt "$SINCE_ISO" -o -newerct "$SINCE_ISO" \) \
      -printf '%T+\t%C+\t%u\t%g\t%m\t%s\t%p\n' 2>/dev/null | sort
  } > "$d/timeline_fichiers.tsv"
  [ -s "$OUT/02_indicateurs/evenements_http_suspects.txt" ] && \
    cp "$OUT/02_indicateurs/evenements_http_suspects.txt" "$d/evenements_http_suspects.txt"
  log "Timeline: $(nlines "$d/timeline_fichiers.tsv") files (cross-check with HTTP events and error logs)."
  log "For a full timeline from a disk image: fls -r -m / | mactime, or Plaso (log2timeline.py)."
}

#==============================================================================
# PHASE 6: summary
#==============================================================================
phase6() {
  log "== Phase 6: summary =="
  local R="$OUT/RAPPORT.txt" h m e i
  # Count findings per severity
  h=$(awk -F'\t' '$1=="HIGH"' "$OUT/FINDINGS.tsv" | wc -l | tr -d ' ')
  m=$(awk -F'\t' '$1=="MED"'  "$OUT/FINDINGS.tsv" | wc -l | tr -d ' ')
  e=$(awk -F'\t' '$1=="EXPO"' "$OUT/FINDINGS.tsv" | wc -l | tr -d ' ')
  i=$(awk -F'\t' '$1=="INFO"' "$OUT/FINDINGS.tsv" | wc -l | tr -d ' ')
  {
    echo "PHP2SHELL TRIAGE REPORT (CVE-2026-109618 / CVE-2026-109619)"
    echo "Host: $HOST   Generated (UTC): $(date -u +%FT%TZ)   Window: since $SINCE_ISO"
    echo
    echo "Findings: HIGH=$h  MED=$m  EXPO=$e  INFO=$i"
    echo
    # Heuristic verdict: driven by the highest severity found
    if [ "$h" -gt 0 ]; then
      echo "VERDICT: STRONG INDICATORS OF COMPROMISE."
      echo "  Isolate the server at network level (without powering it off), preserve RAM and disk,"
      echo "  do not clean in place, rebuild from a clean image, rotate all secrets readable by PHP"
      echo "  and hunt for the same indicators elsewhere."
    elif [ "$m" -gt 0 ]; then
      echo "VERDICT: ITEMS TO INVESTIGATE (no direct proof of compromise)."
      echo "  Correlate the MED findings with each other and with the timeline (05_timeline)."
    else
      echo "VERDICT: NO INDICATOR FOUND BY THIS TRIAGE."
      echo "  This does not prove the absence of compromise (see limitations below)."
    fi
    [ "$e" -gt 0 ] && echo "  Exposure: a vulnerable PHP version is present. Update it, then keep the analysis results."
    echo
    echo "--- Findings (severity / phase / message) ---"
    sort -t$'\t' -k1,1 "$OUT/FINDINGS.tsv" | awk -F'\t' '{printf "[%s] phase %s: %s\n",$1,$2,$3}'
    echo
    echo "--- Limitations ---"
    echo " * A successful exploitation can return a normal HTTP 200 and leave nothing in application logs."
    echo " * Standard web logs do not contain the body of multipart requests."
    echo " * A PHP worker memory leak (secrets, sessions) leaves no file trace:"
    echo "   if the server stayed exposed and unpatched, rotating secrets is justified even without an indicator."
    echo " * A webshell planted before the fix survives the PHP update."
    echo " * Log coverage must reach back to the analysed window: 02_indicateurs/couverture_logs_acces.txt."
    echo " * If a rootkit is possible, the commands used by this script may be tampered with: analyse an offline disk image."
    echo " * Webshell patterns are strict: no result does not mean no webshell. Use --deep and YARA."
    echo " * MED/INFO findings are noisy (deployments, legitimate tasks): validate them one by one."
    echo
    echo "--- Contents ---"
    (cd "$OUT" && ls -1)
  } > "$R"

  # Integrity manifest (last write into the directory, so log before building it)
  log "SHA-256 manifest: $OUT/SHA256SUMS"
  (cd "$OUT" && find . -type f ! -name SHA256SUMS -print0 | xargs -0 sha256sum > SHA256SUMS) 2>/dev/null

  if [ "$ARCHIVE" -eq 1 ]; then
    tar -czf "$OUT.tgz" -C "$(dirname "$OUT")" "$(basename "$OUT")" && sha256sum "$OUT.tgz" > "$OUT.tgz.sha256"
    log "Archive: $OUT.tgz"
  fi

  # Print the report header (verdict and counters) on the terminal
  echo >&2
  sed -n '1,/^--- Findings/p' "$R" | head -n -1 >&2
  echo "Full report: $R" >&2
}

#------------------------------------------------------------------------------
# Main
#------------------------------------------------------------------------------
log "Starting: host=$HOST, window=$SINCE_ISO, output=$OUT"
phase0
phase1
phase2
phase3
phase4
phase5
phase6
