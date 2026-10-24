#!/usr/bin/env bash
#===============================================================================
#   kondo's port scanner 0.1
#
#   TCP connect scanner. Parallel, timeout-bounded, with banner grabbing.
#   Backend: nc when present (real connect timeout), bash /dev/tcp otherwise.
#
#   Usage:  ./kondo.sh -t 10.0.0.1 -p 1-1024 -j 200
#           ./kondo.sh -t 192.168.1.0/24 -p common -b
#===============================================================================

if [ -z "${BASH_VERSION:-}" ]; then exec bash "$0" "$@"; fi
set -o pipefail
trap '' PIPE

VERSION="0.1"
PROG="$(basename "$0")"

if [ -t 1 ]; then
  R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'
  BOLD=$'\e[1m'; DIM=$'\e[2m'; N=$'\e[0m'
else
  R=; G=; Y=; C=; BOLD=; DIM=; N=
fi

TARGETS=()
PORTSPEC="common"
JOBS=100
TIMEOUT=1
BANNER=1
SHOW_ALL=0
OUTMODE="table"
QUIET=0
BACKEND=""
PORTLIST=""
RESULTS=""

die()  { printf '%s[!]%s %s\n' "$R" "$N" "$*" >&2; exit 1; }
warn() { printf '%s[~]%s %s\n' "$Y" "$N" "$*" >&2; }
info() { printf '%s[*]%s %s\n' "$C" "$N" "$*" >&2; }
ok()   { printf '%s[+]%s %s\n' "$G" "$N" "$*" >&2; }

usage() {
  cat <<EOF
kondo's port scanner $VERSION

USAGE
  bash "${PROG}" -t <target> [-p <spec>] [options]

OPTIONS
  -t, --target <host|ip|cidr>   target (repeatable, comma-separated ok)
  -p, --ports <spec>            ports (default: common)
                                22  22,80,443  1-1024  1-1024,3306
                                presets: common top100 web db all
  -j, --jobs <n>                parallel workers           (default: 100)
  -w, --timeout <sec>           per-port connect timeout   (default: 1)
  -b, --banner                  grab service banners       (default: on)
      --no-banner               skip banner grabbing
  -a, --all                     also list closed ports
  -q, --quiet                   print only open port numbers
      --csv                     comma separated output
  -V, --version                 version
  -h, --help                    this help

EXAMPLES
  bash "${PROG}" -t 10.0.0.1 -p 1-1024 -j 200
  bash "${PROG}" -t 192.168.1.0/24 -p common
  bash "${PROG}" -t example.com -p web,db -b
  bash "${PROG}" -t 10.0.0.5 -p 1-65535 -j 300 -w 1 -q

NOTE
  TCP connect scan only — no raw sockets, so no root required.
EOF
}

isnum() { case "$1" in ''|*[!0-9]*) return 1 ;; esac; return 0; }

#-------------------------------------------------------------------------------
# Args
#-------------------------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    -t|--target) [ -n "${2:-}" ] || die "-t needs a target"; TARGETS+=("$2"); shift 2 ;;
    -p|--ports)  [ -n "${2:-}" ] || die "-p needs a spec"; PORTSPEC="$2"; shift 2 ;;
    -j|--jobs)   [ -n "${2:-}" ] || die "-j needs a number"; JOBS="$2"; shift 2 ;;
    -w|--timeout) [ -n "${2:-}" ] || die "-w needs seconds"; TIMEOUT="$2"; shift 2 ;;
    -b|--banner) BANNER=1; shift ;;
    --no-banner) BANNER=0; shift ;;
    -a|--all)    SHOW_ALL=1; shift ;;
    -q|--quiet)  QUIET=1; shift ;;
    --csv)       OUTMODE="csv"; shift ;;
    -V|--version) echo "$PROG $VERSION"; exit 0 ;;
    -h|--help)   usage; exit 0 ;;
    -*)          die "unknown option: $1 (try -h)" ;;
    *)           TARGETS+=("$1"); shift ;;
  esac
done

[ "${#TARGETS[@]}" -gt 0 ] || { usage; echo; die "no target given"; }
isnum "$JOBS" || die "-j must be a number"
[ "$JOBS" -ge 1 ] || die "-j must be >= 1"
isnum "$TIMEOUT" || die "-w must be a number"
[ "$TIMEOUT" -ge 1 ] || TIMEOUT=1

#-------------------------------------------------------------------------------
# Backend detection
#-------------------------------------------------------------------------------
NCARGS=()
if command -v nc >/dev/null 2>&1; then
  BACKEND="nc"
  if nc -h 2>&1 | grep -q -- '-G'; then
    NCARGS=(-G "$TIMEOUT" -w "$TIMEOUT" -z)
  else
    NCARGS=(-w "$TIMEOUT" -z)
  fi
else
  BACKEND="devtcp"
  warn "nc not found — using bash /dev/tcp (no connect timeout)"
fi

#-------------------------------------------------------------------------------
# Service names
#-------------------------------------------------------------------------------
svc_name() {
  case "$1" in
    20|21) echo ftp ;; 22) echo ssh ;; 23) echo telnet ;; 25) echo smtp ;;
    53) echo domain ;; 67|68) echo dhcp ;; 69) echo tftp ;; 79) echo finger ;;
    80|8000|8080|8081|8888) echo http ;; 88) echo kerberos ;;
    110) echo pop3 ;; 111) echo rpcbind ;; 123) echo ntp ;; 135) echo msrpc ;;
    137|138|139) echo netbios ;; 143) echo imap ;; 161|162) echo snmp ;;
    389) echo ldap ;; 443|8443) echo https ;; 445) echo microsoft-ds ;;
    465) echo smtps ;; 500) echo isakmp ;; 512|513|514) echo r-services ;;
    587) echo submission ;; 623) echo ipmi ;; 631) echo ipp ;; 636) echo ldaps ;;
    873) echo rsync ;; 902) echo vmware ;; 993) echo imaps ;; 995) echo pop3s ;;
    1080) echo socks ;; 1099) echo rmi ;; 1194) echo openvpn ;;
    1433) echo ms-sql ;; 1521) echo oracle ;; 1723) echo pptp ;;
    2049) echo nfs ;; 2181) echo zookeeper ;; 2375|2376) echo docker ;;
    3000) echo http-alt ;; 3128) echo squid ;; 3260) echo iscsi ;;
    3306) echo mysql ;; 3389) echo ms-wbt-server ;; 4444) echo krb524 ;;
    5000) echo upnp ;; 5432) echo postgresql ;; 5555) echo adb ;;
    5601) echo kibana ;; 5672) echo amqp ;; 5900|5901) echo vnc ;;
    5984) echo couchdb ;; 6000) echo x11 ;; 6379) echo redis ;;
    7001) echo weblogic ;; 8008) echo http-alt ;; 8086) echo influxdb ;;
    8161) echo activemq ;; 8443) echo https-alt ;; 9000) echo cslistener ;;
    9090) echo websm ;; 9092) echo kafka ;; 9200|9300) echo elasticsearch ;;
    9418) echo git ;; 10000) echo webmin ;; 11211) echo memcached ;;
    15672) echo rabbitmq-mgmt ;; 27017|27018) echo mongod ;;
    50000) echo db2 ;; 61616) echo activemq ;;
    *) echo unknown ;;
  esac
}

guess_banner() {
  case "$1" in
    SSH-*|*OpenSSH*)        echo ssh ;;
    HTTP/*|*Server:*|*nginx*|*Apache*|*lighttpd*) echo http ;;
    *SMTP*|*Postfix*|*Exim*) echo smtp ;;
    *FTP*|*vsftpd*|*ProFTPD*) echo ftp ;;
    *MySQL*|*mariadb*)      echo mysql ;;
    *PostgreSQL*)           echo postgresql ;;
    *MongoDB*)              echo mongod ;;
    *Redis*|*-ERR*)         echo redis ;;
    *memcached*)            echo memcached ;;
    *VNC*|*RFB*)            echo vnc ;;
    *SMB*|*Windows*)        echo microsoft-ds ;;
    *Docker*)               echo docker ;;
    *Elastic*)              echo elasticsearch ;;
    *)                      echo "" ;;
  esac
}

sanitize() {
  local s="$1"
  s=$(printf '%s' "$s" | LC_ALL=C tr -cd '[:print:]')
  s=$(printf '%s' "$s" | tr -s ' ')
  s="${s# }"; s="${s% }"
  printf '%s' "${s:0:60}"
}

#-------------------------------------------------------------------------------
# Host / port expansion
#-------------------------------------------------------------------------------
ip2int() { local IFS=.; set -- $1; echo $(( ($1<<24) + ($2<<16) + ($3<<8) + $4 )); }
int2ip() { local n="$1"; echo "$(( (n>>24)&255 )).$(( (n>>16)&255 )).$(( (n>>8)&255 )).$(( n&255 ))"; }

expand_hosts() {
  local t="$1" part
  local IFS=','
  for part in $t; do
    case "$part" in
      */*)
        local net="${part%/*}" bits="${part#*/}"
        isnum "$bits" || { echo "$part"; continue; }
        [ "$bits" -le 32 ] || { echo "$part"; continue; }
        local ip; ip=$(ip2int "$net") || { echo "$part"; continue; }
        local mask=$(( bits == 0 ? 0 : (0xFFFFFFFF << (32-bits)) & 0xFFFFFFFF ))
        local network=$(( ip & mask ))
        local bcast=$(( network | (~mask & 0xFFFFFFFF) ))
        if [ "$bits" -ge 31 ]; then
          local h="$network"
          while [ "$h" -le "$bcast" ]; do int2ip "$h"; h=$((h+1)); done
        else
          local h=$((network+1))
          while [ "$h" -lt "$bcast" ]; do int2ip "$h"; h=$((h+1)); done
        fi
        ;;
      *) echo "$part" ;;
    esac
  done
}

range() {
  local a="$1" b="$2" p
  if command -v seq >/dev/null 2>&1; then
    seq "$a" "$b"
  else
    p="$a"; while [ "$p" -le "$b" ]; do echo "$p"; p=$((p+1)); done
  fi
}

expand_ports() {
  local spec="$1"
  case "$spec" in
    common) spec="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080" ;;
    web)    spec="80,443,591,3000,5000,8000,8008,8080,8081,8443,8888,9000,9090" ;;
    db)     spec="1433,1521,3306,5432,5984,6379,9200,11211,27017" ;;
    top100) spec="1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,464,465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000,1001,1002,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,1081,1082,1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,1094,1095,1096,1097,1098,1099,1100,1101,1102,1103,1104,1105,1106,1107,1108,1109,1110,1111,1112,1113,1114,1115,1116,1117,1118,1119,1120,1121,1122,1123,1124,1125,1126,1127,1128,1129,1130,1131,1132,1137,1138,1141,1145,1147,1148,1149,1151,1152,1154,1163,1164,1165,1166,1169,1174,1175,1183,1185,1186,1187,1192,1198,1199,1201,1213,1216,1217,1218,1233,1234,1236,1244,1247,1248,1259,1271,1272,1277,1287,1296,1300,1301,1309,1310,1311,1322,1328,1334,1352,1417,1433,1434,1443,1455,1461,1494,1500,1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687,1688,1700,1717,1718,1719,1720,1721,1723,1755,1761,1782,1783,1801,1805,1812,1839,1840,1862,1863,1875,1900,1914,1935,1947,1971,1972,1974,1984,1998,1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010,2013,2020,2021,2022,2030,2033,2034,2035,2038,2040,2041,2042,2043,2044,2045,2046,2047,2048,2049,2065,2068,2099,2100,2103,2105,2106,2107,2111,2119,2121,2126,2135,2144,2160,2161,2170,2179,2190,2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381,2382,2383,2393,2399,2401,2492,2500,2522,2525,2557,2601,2602,2604,2605,2607,2608,2638,2701,2702,2710,2717,2718,2725,2800,2809,2811,2869,2875,2909,2910,2920,2967,2968,2998,3000,3001,3003,3005,3006,3007,3011,3013,3017,3030,3031,3052,3071,3077,3080,3089,3119,3128,3141,3168,3211,3221,3260,3261,3268,3269,3283,3300,3301,3306,3322,3323,3324,3325,3333,3351,3367,3369,3370,3371,3372,3389,3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689,3690,3703,3737,3766,3784,3800,3801,3809,3814,3826,3827,3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000,4001,4002,4003,4004,4005,4006,4045,4111,4125,4126,4129,4224,4242,4279,4321,4333,4343,4443,4444,4445,4446,4449,4550,4567,4662,4848,4899,4900,4998,5000,5001,5002,5003,5004,5009,5030,5033,5050,5051,5054,5060,5061,5080,5087,5100,5101,5102,5120,5190,5191,5192,5193,5194,5200,5221,5222,5225,5226,5269,5280,5298,5357,5405,5414,5431,5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678,5679,5718,5730,5800,5801,5802,5810,5811,5815,5822,5825,5850,5859,5862,5877,5900,5901,5902,5903,5904,5906,5907,5910,5911,5912,5915,5922,5925,5950,5952,5959,5960,5961,5962,5963,5987,5988,5989,5998,5999,6000,6001,6002,6003,6004,6005,6006,6007,6009,6025,6059,6100,6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6544,6550,6565,6566,6567,6580,6646,6666,6667,6668,6669,6689,6692,6699,6779,6788,6792,6839,6881,6901,6969,7000,7001,7002,7004,7007,7019,7025,7070,7100,7106,7200,7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777,7778,7800,7911,7920,7921,7937,7938,7999,8000,8001,8002,8007,8008,8009,8010,8011,8021,8022,8031,8042,8045,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8093,8099,8100,8180,8181,8192,8193,8194,8200,8222,8254,8290,8291,8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651,8652,8654,8701,8800,8873,8880,8888,8899,8994,9000,9001,9002,9003,9009,9010,9011,9040,9050,9071,9080,9081,9090,9091,9099,9100,9101,9102,9103,9110,9111,9200,9207,9222,9255,9278,9280,9290,9415,9418,9443,9500,9535,9575,9593,9594,9595,9618,9666,9876,9877,9878,9898,9900,9917,9929,9943,9944,9968,9998,9999,10000,10001,10002,10003,10004,10009,10010,10012,10024,10025,10082,10180,10215,10243,10566,10616,10617,10621,10626,10628,10629,10778,11110,11111,11967,12000,12174,12265,12345,13456,13722,13782,13783,14000,14238,14441,14442,15000,15002,15003,15004,15660,15742,16000,16001,16012,16016,16018,16080,16113,16992,16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221,20222,20828,21571,22939,23502,24444,24800,25734,25735,26214,27000,27352,27353,27355,27356,27715,28201,30000,30718,30951,31038,31337,32768,32769,32770,32771,32772,32773,32774,32775,32776,32777,32778,32779,32780,32781,32782,32783,32784,32785,33354,33899,34571,34572,34573,35500,38292,40193,40911,41511,42510,44176,44442,44443,44501,45100,48080,49152,49153,49154,49155,49156,49157,49158,49159,49160,49161,49163,49165,49167,49175,49176,49400,49999,50000,50001,50002,50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055,55056,55555,55600,56737,56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389" ;;
    all)    spec="1-65535" ;;
  esac

  local IFS=',' part a b
  for part in $spec; do
    case "$part" in
      *-*)
        a="${part%-*}"; b="${part#*-}"
        isnum "$a" && isnum "$b" || { warn "bad range: $part"; continue; }
        [ "$a" -ge 1 ] && [ "$b" -le 65535 ] && [ "$a" -le "$b" ] || { warn "bad range: $part"; continue; }
        range "$a" "$b"
        ;;
      *)
        isnum "$part" || { warn "bad port: $part"; continue; }
        [ "$part" -ge 1 ] && [ "$part" -le 65535 ] || { warn "bad port: $part"; continue; }
        echo "$part"
        ;;
    esac
  done
}

#-------------------------------------------------------------------------------
# Connect test
#-------------------------------------------------------------------------------
connect_test() {
  local host="$1" port="$2"
  if [ "$BACKEND" = "nc" ]; then
    nc "${NCARGS[@]}" "$host" "$port" >/dev/null 2>&1
    return $?
  fi
  ( exec 3<>/dev/tcp/"$host"/"$port" ) 2>/dev/null
  return $?
}

grab_banner() {
  local host="$1" port="$2" b="" line=""

  exec 4<>/dev/tcp/"$host"/"$port" 2>/dev/null || { printf ''; return; }

  read -t 1 -u 4 line 2>/dev/null; b="$line"

  if [ -z "$b" ]; then
    printf '\r\n' >&4 2>/dev/null
    read -t 1 -u 4 line 2>/dev/null; b="$line"
  fi

  if [ -z "$b" ]; then
    case "$port" in
      80|81|88|591|3000|5000|8000|8008|8080|8081|8088|8888|9000|9090)
        printf 'HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: kondo/%s\r\n\r\n' "$host" "$VERSION" >&4 2>/dev/null
        while read -t 1 -u 4 line 2>/dev/null; do
          case "$line" in
            HTTP/*|Server:*|server:*) b="$line"; break ;;
          esac
          [ -z "$line" ] && break
        done
        ;;
    esac
  fi

  exec 4>&- 2>/dev/null
  sanitize "$b"
}

#-------------------------------------------------------------------------------
# Single port
#-------------------------------------------------------------------------------
scan_one() {
  local host="$1" port="$2"

  if ! connect_test "$host" "$port"; then
    [ "$SHOW_ALL" -eq 1 ] && printf '%s|closed||\n' "$port" >> "$RESULTS"
    return 0
  fi

  local svc banner=""
  if [ "$BANNER" -eq 1 ]; then banner=$(grab_banner "$host" "$port"); fi
  svc=$(svc_name "$port")
  if [ -n "$banner" ] && [ "$svc" = "unknown" ]; then
    local g; g=$(guess_banner "$banner"); [ -n "$g" ] && svc="$g"
  fi

  printf '%s|open|%s|%s\n' "$port" "$svc" "$banner" >> "$RESULTS"
}

#-------------------------------------------------------------------------------
# Run
#-------------------------------------------------------------------------------
resolve() {
  local h="$1"
  case "$h" in
    *[!0-9.]*) : ;;   # looks like a name
    *) echo "$h"; return ;;
  esac
  if command -v getent >/dev/null 2>&1; then
    local r; r=$(getent hosts "$h" 2>/dev/null | awk '{print $1; exit}')
    [ -n "$r" ] && { echo "$r"; return; }
  fi
  if command -v dscacheutil >/dev/null 2>&1; then
    local r; r=$(dscacheutil -q host -a name "$h" 2>/dev/null | awk '/^ip_address/{print $2; exit}')
    [ -n "$r" ] && { echo "$r"; return; }
  fi
  echo "$h"
}

TMPD=$(mktemp -d) || die "cannot create temp dir"
trap 'rm -rf "$TMPD"; exit 1' INT
PORTLIST="$TMPD/ports"
RESULTS="$TMPD/results"
: > "$RESULTS"

expand_ports "$PORTSPEC" > "$PORTLIST"
TOTAL=$(wc -l < "$PORTLIST" | tr -d ' ')
[ "$TOTAL" -gt 0 ] || die "no valid ports in spec: $PORTSPEC"

HOSTS=()
for t in "${TARGETS[@]}"; do
  while read -r h; do [ -n "$h" ] && HOSTS+=("$h"); done < <(expand_hosts "$t")
done
[ "${#HOSTS[@]}" -gt 0 ] || die "no valid targets"

[ "$QUIET" -eq 0 ] && {
  info "kondo's port scanner $VERSION"
  info "backend: $BACKEND   jobs: $JOBS   timeout: ${TIMEOUT}s   banner: $BANNER"
  info "targets: ${#HOSTS[@]}   ports/host: $TOTAL"
}

GRAND_OPEN=0
GSTART=$(date +%s)

for HOST in "${HOSTS[@]}"; do
  IP=$(resolve "$HOST")
  : > "$RESULTS"
  DONE=0
  WAVE=0
  WAVES=$(( (TOTAL + JOBS - 1) / JOBS ))

  if [ "$QUIET" -eq 0 ] && [ "${#HOSTS[@]}" -gt 1 ]; then
    printf '\n%s=== %s%s\n' "$BOLD" "$IP" "$N" >&2
  fi

  while read -r PORT; do
    [ -n "$PORT" ] || continue
    scan_one "$IP" "$PORT" &
    DONE=$((DONE+1))
    if [ $(( DONE % JOBS )) -eq 0 ]; then
      wait
      WAVE=$((WAVE+1))
      if [ "$QUIET" -eq 0 ] && [ -t 2 ]; then
        printf '\r%s[*]%s %s  %d/%d ports  (%d/%d waves)   ' \
          "$C" "$N" "$IP" "$DONE" "$TOTAL" "$WAVE" "$WAVES" >&2
      fi
    fi
  done < "$PORTLIST"
  wait

  [ "$QUIET" -eq 0 ] && [ -t 2 ] && printf '\r%s\r' "$(printf '%*s' 70 '')" >&2

  # ---- output ---------------------------------------------------------------
  OPEN=$(grep -c '|open|' "$RESULTS" 2>/dev/null | tr -d ' ')
  [ -n "$OPEN" ] || OPEN=0
  GRAND_OPEN=$((GRAND_OPEN + OPEN))

  if [ "$OUTMODE" = "csv" ]; then
    sort -t'|' -k1,1 -n "$RESULTS" | while IFS='|' read -r p s sv b; do
      printf '%s,%s,%s,%s\n' "$IP" "$p" "$s" "$sv" "$b"
    done
  elif [ "$QUIET" -eq 1 ]; then
    if [ "${#HOSTS[@]}" -gt 1 ]; then
      grep '|open|' "$RESULTS" | sort -t'|' -k1,1 -n | cut -d'|' -f1 | while read -r p; do
        printf '%s:%s\n' "$IP" "$p"
      done
    else
      grep '|open|' "$RESULTS" | sort -t'|' -k1,1 -n | cut -d'|' -f1
    fi
  else
    printf '\n%sPORT      STATE   SERVICE              BANNER%s\n' "$BOLD" "$N"
    printf '%s' "$DIM"; printf '%.0s-' $(seq 1 70); printf '%s\n' "$N"
    sort -t'|' -k1,1 -n "$RESULTS" | while IFS='|' read -r p s sv b; do
      if [ "$s" = "open" ]; then col="$G"; else col="$DIM"; fi
      printf '%s%-9s%s %-7s %-20s %s%s%s\n' \
        "$col" "$p/tcp" "$N" "$s" "$sv" "$DIM" "$b" "$N"
    done
    ok "$OPEN open / $TOTAL scanned on $IP"
  fi
done

GEL=$(( $(date +%s) - GSTART ))
[ "$QUIET" -eq 0 ] && ok "total: $GRAND_OPEN open across ${#HOSTS[@]} host(s) in ${GEL}s"
rm -rf "$TMPD"
exit 0