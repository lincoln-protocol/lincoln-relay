#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# One-command installer for a Lincoln relay on a Linux server.
#
#   curl -fsSL https://raw.githubusercontent.com/lincoln-protocol/lincoln-relay/main/install.sh | sudo bash -s -- --pools <id,id,...> --domain <host>
#
# It builds the relay image from source, stages the public release from
# Lincoln-protocol-core, creates the relay key on this server, writes the
# config and starts the relay read-only behind Caddy (automatic HTTPS).
# Signing starts only after the relay address holds ETH for gas:
#
#   lincoln-relay signing on
#
# The relay key never leaves this server. Back up <dir>/secrets.
set -Eeuo pipefail

RELAY_REPO=${LINCOLN_RELAY_REPO:-https://github.com/lincoln-protocol/lincoln-relay.git}
CORE_REPO=${LINCOLN_CORE_REPO:-https://github.com/lincoln-protocol/Lincoln-protocol-core.git}
# Exact sources this installer builds. Each checkout is verified against the full commit and the
# install stops on any mismatch. RELAY_COMMIT is the release's source commit; the release tag sits
# on the next commit, which only writes this pin.
RELAY_COMMIT=2561b4f2676bce3328781cfe1f0a91b21f881644
CORE_TAG=v0.1.0-rc.3
CORE_COMMIT=b2febe03c0604c1f0dbeeed393f2157f48f3dc1c
MAINNET_RPC=https://rpc.mainnet.chain.robinhood.com/
MIRROR_URL=https://lincolnprotocol.com/asp/
POINTS_SEASON=season-1
REGISTER_URL=https://app.lincolnprotocol.com/relay
# RelayStakeRegistryV2 on Robinhood Chain mainnet (block 95221645); the relay key signs its consent for it.
REGISTRY=0xfF986c58e467De9862BF97a1c2782D4b263C8307
# Public deployer of the pools. The frozen rc3 release leaves it null, and the relay's
# release check only needs a well-formed address; it does not enter any verified source.
MAINNET_DEPLOYER=0x36437b878415EdA1a24186CF79AFffBc9ecEd298
NODE_IMAGE=node:24.22.0-bookworm-slim@sha256:a5f4366e834695d5f363b920c104953a535d3a9864d1bdf74566a0ebe01daee5
CADDY_IMAGE=caddy:2.10.0-alpine@sha256:ae4458638da8e1a91aafffb231c5f8778e964bca650c8a8cb23a7e8ac557aa3c
APP_UID=10001

POOLS=
DOMAIN=
OWNER=
DIR=/opt/lincoln-relay
REF=
RPC_URL_FILE=
EMAIL=
TLS=auto
BUDGET_ETH=0.1
MAX_FEE_GWEI=0.1
RESERVE_ETH=0.001
YES=0

usage(){ cat <<'EOF'
Usage: install.sh --pools <id,id,...> --domain <host> [options]

  --pools <id,...>       pools this relay serves, comma-separated, e.g. lincoln,eth,usdg (one stake covers them all);
                         --pool <id> is the same with one pool. The first pool answers at https://<host>/v3/...,
                         every pool at https://<host>/<id>/v3/...
  --domain <host>        public DNS name pointing at this server; the relay endpoint is https://<host>
  --owner <0x…>          wallet that will register and stake for this relay (signs the relay's consent for it)
  --dir <path>           install directory (default /opt/lincoln-relay)
  --rpc-url-file <path>  file holding your own https RPC URL for Robinhood Chain (required on first install:
                         the public RPC rate-limits the startup sync of chain history)
  --email <address>      contact for the Let's Encrypt account (optional)
  --budget-eth <n>       total gas the relay may spend before it stops (default 0.1)
  --max-fee-gwei <n>     highest max fee per gas it signs (default 0.1)
  --reserve-eth <n>      ETH it always leaves in the wallet (default 0.001)
  --ref <git ref>        build another lincoln-relay version instead of the pinned release commit
                         (unpinned; for testing only)
  --tls <auto|internal>  internal uses a local CA, for testing only (default auto)
  --yes                  do not ask before installing Docker
EOF
}
say(){ printf '\033[1m==>\033[0m %s\n' "$*"; }
warn(){ printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die(){ printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
trap 'die "failed at line $LINENO: $BASH_COMMAND"' ERR

while [ $# -gt 0 ]; do
  case "$1" in
    --pool|--pools) POOLS=${POOLS:+$POOLS,}${2:-}; shift 2;;
    --domain) DOMAIN=${2:-}; shift 2;;
    --owner) OWNER=${2:-}; shift 2;;
    --dir) DIR=${2:-}; shift 2;;
    --rpc-url-file) RPC_URL_FILE=${2:-}; shift 2;;
    --email) EMAIL=${2:-}; shift 2;;
    --budget-eth) BUDGET_ETH=${2:-}; shift 2;;
    --max-fee-gwei) MAX_FEE_GWEI=${2:-}; shift 2;;
    --reserve-eth) RESERVE_ETH=${2:-}; shift 2;;
    --ref) REF=${2:-}; shift 2;;
    --tls) TLS=${2:-}; shift 2;;
    --yes|-y) YES=1; shift;;
    -h|--help) usage; exit 0;;
    *) usage >&2; die "unknown option: $1";;
  esac
done

IFS=, read -r -a POOL_LIST <<<"$POOLS"
[ ${#POOL_LIST[@]} -ge 1 ] && [ ${#POOL_LIST[@]} -le 32 ] || { usage >&2; die "--pools is required (e.g. lincoln or lincoln,eth,usdg)"; }
for p in "${POOL_LIST[@]}"; do [[ $p =~ ^[a-z][a-z0-9_-]{0,63}$ ]] || { usage >&2; die "invalid pool id '$p'"; }; done
[ "$(printf '%s\n' "${POOL_LIST[@]}" | sort -u | wc -l)" -eq ${#POOL_LIST[@]} ] || die "--pools lists a pool twice"
POOL=${POOL_LIST[0]}; POOLS=$(IFS=,; echo "${POOL_LIST[*]}"); POOL_COUNT=${#POOL_LIST[@]}
# One container, one listener per pool: 8797, 8798, ... inside; 19897, 19898, ... on this host's loopback.
ROLE=api; [ "$POOL_COUNT" -gt 1 ] && ROLE=apis
[[ $DOMAIN =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] || { usage >&2; die "--domain must be a lowercase DNS name, e.g. relay.example.com"; }
[[ -z $OWNER || $OWNER =~ ^0x[0-9a-fA-F]{40}$ ]] || die "--owner must be a 0x address"
[[ $DIR == /* ]] || die "--dir must be an absolute path"
[[ $TLS == auto || $TLS == internal ]] || die "--tls must be auto or internal"
[[ -z $EMAIL || $EMAIL =~ ^[^[:space:]@]+@[^[:space:]@]+$ ]] || die "--email is not an address"
for v in "$BUDGET_ETH" "$MAX_FEE_GWEI" "$RESERVE_ETH"; do [[ $v =~ ^[0-9]+(\.[0-9]+)?$ ]] || die "amounts must be decimal numbers: $v"; done
[ "$(id -u)" -eq 0 ] || die "run as root (pipe to 'sudo bash')"
if [ -n "$RPC_URL_FILE" ]; then
  [ -f "$RPC_URL_FILE" ] || die "--rpc-url-file $RPC_URL_FILE does not exist"
  grep -Eq '^https://[^[:space:]#]+$' "$RPC_URL_FILE" || die "--rpc-url-file must hold one https:// URL"
elif [ ! -f "$DIR/secrets/rpc-url" ]; then
  usage >&2; die "--rpc-url-file is required on first install: the public RPC rate-limits the relay's startup sync"
fi
[ "$(uname -s)" = Linux ] || die "Linux only"

# Decimal string -> integer string scaled by 10^decimals, without floating point.
to_units(){ local v=$1 d=$2 int frac; int=${v%%.*}; frac=; [[ $v == *.* ]] && frac=${v#*.}
  [ ${#frac} -le "$d" ] || die "too many decimals in $v"
  while [ ${#frac} -lt "$d" ]; do frac+="0"; done
  local out; out=$(printf '%s%s' "$int" "$frac" | sed 's/^0*//'); echo "${out:-0}"; }
BUDGET_WEI=$(to_units "$BUDGET_ETH" 18); MAX_FEE_WEI=$(to_units "$MAX_FEE_GWEI" 9); RESERVE_WEI=$(to_units "$RESERVE_ETH" 18)
[ "$BUDGET_WEI" != 0 ] && [ "$MAX_FEE_WEI" != 0 ] || die "--budget-eth and --max-fee-gwei must be above 0"

# 1. Docker
if ! command -v docker >/dev/null 2>&1; then
  if [ $YES -ne 1 ]; then
    [ -r /dev/tty ] || die "Docker is missing; rerun with --yes to install it from get.docker.com"
    printf 'Docker is not installed. Install it now from https://get.docker.com? [y/N] '; read -r answer </dev/tty
    [[ $answer =~ ^[Yy] ]] || die "Docker is required"
  fi
  say "Installing Docker"
  curl -fsSL https://get.docker.com | sh
fi
docker compose version >/dev/null 2>&1 || die "the Docker Compose plugin is missing (apt-get install docker-compose-plugin)"
command -v git >/dev/null 2>&1 || { say "Installing git"; (apt-get update -qq && apt-get install -y -qq git) >/dev/null || die "install git first"; }
mem_kb=$(awk '/MemTotal/{print $2}' /proc/meminfo); [ "$mem_kb" -ge 3500000 ] || warn "less than 4 GB of RAM; the release check at startup may run out of memory"

# 2. Code: lincoln-relay and the public release in Lincoln-protocol-core
install -d -m 0755 "$DIR"
fetch(){ local url=$1 dest=$2 ref=$3
  if [ -d "$dest/.git" ]; then git -C "$dest" fetch -q --tags origin; else git clone -q "$url" "$dest"; fi
  # A branch name resolves to the freshly fetched remote branch; a tag or commit resolves as is.
  git -C "$dest" checkout -q --detach "origin/$ref" 2>/dev/null || git -C "$dest" checkout -q --detach "$ref"; }
# Check out exactly this commit, or stop.
fetch_pinned(){ local url=$1 dest=$2 commit=$3 head
  [[ $commit =~ ^[0-9a-f]{40}$ ]] || die "invalid pinned commit '$commit'"
  fetch "$url" "$dest" "$commit"
  head=$(git -C "$dest" rev-parse HEAD)
  [ "$head" = "$commit" ] || die "$url checked out $head, expected $commit; not installing"; }
if [ -n "$REF" ]; then
  warn "--ref $REF builds an unpinned lincoln-relay version"
  say "Fetching lincoln-relay ($REF)"; fetch "$RELAY_REPO" "$DIR/src" "$REF"
else
  say "Fetching lincoln-relay ($RELAY_COMMIT)"; fetch_pinned "$RELAY_REPO" "$DIR/src" "$RELAY_COMMIT"
fi
COMMIT=$(git -C "$DIR/src" rev-parse --short=12 HEAD)
say "Fetching Lincoln-protocol-core ($CORE_TAG, $CORE_COMMIT)"; fetch_pinned "$CORE_REPO" "$DIR/core" "$CORE_COMMIT"

FEES=$DIR/src/config/mainnet-fees
for p in "${POOL_LIST[@]}"; do [ -f "$FEES/service-fees-$p.json" ] || die "unknown pool '$p'; choose from: $(ls "$FEES" | sed -n 's/^service-fees-\(.*\)\.json$/\1/p' | tr '\n' ' ')"; done

say "Building the relay image (lincoln-relay:$COMMIT)"
IMAGE=lincoln-relay:$COMMIT
docker build -q -f "$DIR/src/docker/mainnet/runtime.Dockerfile" -t "$IMAGE" "$DIR/src" >/dev/null
IMAGE_ID=$(docker image inspect -f '{{.Id}}' "$IMAGE")

RELEASE=$DIR/release-$CORE_TAG
if [ ! -f "$RELEASE/mainnet-public-inputs.json" ]; then
  say "Staging the public release (contracts, proving keys); this downloads npm packages once"
  rm -rf "$RELEASE"
  docker run --rm -v "$DIR/core/releases/rc3:/from" -v "$DIR/src:/relay:ro" -v "$DIR:/out" "$NODE_IMAGE" sh -ec \
    "cd /from && npm ci --ignore-scripts --no-audit --no-fund --loglevel=error && node /relay/docker/mainnet/stage-public-release.mjs /out/$(basename "$RELEASE") --from /from --include-fees"
  chown -R root:root "$RELEASE"
fi
# The relay's release check needs a deployer address, which the frozen rc3 config leaves null.
docker run --rm -v "$RELEASE/config:/c" "$NODE_IMAGE" node -e \
  'const fs=require("fs"),f="/c/phase2-mainnet.json",c=JSON.parse(fs.readFileSync(f));if(!c.deployer.address){c.deployer.address=process.argv[1];fs.writeFileSync(f,JSON.stringify(c,null,2)+"\n");}' "$MAINNET_DEPLOYER"

# 3. Relay key, created on this server and readable only by the relay user
SECRETS=$DIR/secrets
install -d -m 0700 -o $APP_UID -g $APP_UID "$SECRETS"
if [ ! -f "$SECRETS/relay.keystore.json" ]; then
  say "Creating the relay key"
  ( umask 077; head -c 32 /dev/urandom | base64 | tr -d '\n=+/' > "$SECRETS/relay.password" )
  chown $APP_UID:$APP_UID "$SECRETS/relay.password"; chmod 0600 "$SECRETS/relay.password"
  docker run --rm --user $APP_UID:$APP_UID --entrypoint sh -v "$SECRETS:/k" "$IMAGE" -ec \
    'cast wallet new /k --unsafe-password "$(cat /k/relay.password)" >/dev/null && f=$(ls /k | grep -v -e relay.password -e relay.keystore.json | head -1) && mv "/k/$f" /k/relay.keystore.json && chmod 0600 /k/relay.keystore.json'
fi
ADDRESS=$(docker run --rm --user $APP_UID:$APP_UID --entrypoint sh -v "$SECRETS:/k:ro" "$IMAGE" -ec \
  'cast wallet address --keystore /k/relay.keystore.json --password-file /k/relay.password')
[[ $ADDRESS =~ ^0x[0-9a-fA-F]{40}$ ]] || die "could not read the relay address"

# 4. Config: deployed profile with this relay, runtime.json, fee policies
CONFIG=$DIR/config
rm -rf "$CONFIG.new"; install -d -m 0755 "$CONFIG.new"
cp "$FEES"/*.json "$CONFIG.new/"
chown $APP_UID "$CONFIG.new"
docker run --rm --user $APP_UID:$APP_UID -v "$DIR/src/scripts/set-relayer.mjs:/app/scripts/set-relayer.mjs:ro" \
  -v "$DIR/src/config/mainnet-deployed.json:/in.json:ro" -v "$CONFIG.new:/out" "$IMAGE" \
  node /app/scripts/set-relayer.mjs "$ADDRESS" /out/mainnet-deployed.json /in.json >/dev/null
docker run --rm -i --user $APP_UID:$APP_UID -v "$CONFIG.new:/out" "$IMAGE" node --input-type=module - \
  "$POOLS" "$ADDRESS" "$DOMAIN" "$BUDGET_WEI" "$MAX_FEE_WEI" "$RESERVE_WEI" <<'EOF'
import fs from 'node:fs';
const [pools,address,domain,budgetWei,maxFeePerGasWei,reserveWei]=process.argv.slice(2);
const poolIds=pools.split(',');
const deployed=JSON.parse(fs.readFileSync('/out/mainnet-deployed.json','utf8'));
for(const id of poolIds)if(!deployed.profiles[id])throw new Error(`pool ${id} is not in the deployed profile`);
const profile=deployed.profiles[poolIds[0]];
const providers=new Set(poolIds.map(id=>deployed.profiles[id].registry.provider.toLowerCase()));
if(providers.size!==1)throw new Error('the listed pools do not share one association-set provider');
const runtime={schema:'lincoln-mainnet-container/v1',chainId:4663,rpcUrl:'https://rpc.mainnet.chain.robinhood.com/',
  governanceSafe:'0x9CF17a6E3c75D200f58283A165C442a8A3994555',profileFile:'mainnet-deployed.json',poolIds,
  relay:{address,enabled:true,budgetWei,maxFeePerGasWei,reserveWei,maxGas:'5000000'},
  // The official provider publishes the association set; this relay only reads it from the mirror.
  asp:{address:profile.registry.provider,enabled:false,budgetWei:null,maxFeePerGasWei:null,reserveWei:null,maxGas:'500000'},
  // Same publication policy as the official relay, so the mirrored publisher heartbeat validates.
  publisher:{policy:'all-current-notes',originScreening:false,intervalSeconds:5,
    publication:{lifetimeSeconds:604800,renewalWindowSeconds:86400,minPublishIntervalSeconds:15,confirmations:2,maxCommitments:10000}},
  network:{allowedHosts:[domain,'127.0.0.1','localhost'],allowedOrigins:[]},
  serviceFeesFile:Object.fromEntries(poolIds.map(id=>[id,`service-fees-${id}.json`])),feeArtifactsFile:'fee-adapters-production.json'};
fs.writeFileSync('/out/runtime.json',JSON.stringify(runtime,null,2)+'\n');
EOF
chown -R root:root "$CONFIG.new"; chmod 0644 "$CONFIG.new"/*.json
docker run --rm -v "$CONFIG.new:/run/config/mainnet:ro" "$IMAGE" node --input-type=module -e \
  "const m=await import('/app/docker/mainnet/start.mjs'),fs=await import('node:fs'),read=f=>JSON.parse(fs.readFileSync('/run/config/mainnet/'+f,'utf8')),c=read('runtime.json');
   for(const id of c.poolIds)m.planMainnetRuntime(c,{role:'api',poolId:id,signingFlag:'1'});m.validateMainnetProfiles(read(c.profileFile),c);" \
  || die "runtime.json failed the relay's own checks"
rm -rf "$CONFIG.old"; [ -d "$CONFIG" ] && mv "$CONFIG" "$CONFIG.old"; mv "$CONFIG.new" "$CONFIG"

STATE=$DIR/state
install -d -m 0700 -o $APP_UID -g $APP_UID "$STATE"
RPC_MOUNT=
if [ -n "$RPC_URL_FILE" ]; then
  [ -f "$RPC_URL_FILE" ] || die "--rpc-url-file $RPC_URL_FILE does not exist"
  install -m 0600 -o $APP_UID -g $APP_UID "$RPC_URL_FILE" "$SECRETS/rpc-url"
fi
[ -f "$SECRETS/rpc-url" ] || die "no RPC URL file; pass --rpc-url-file"
[ -f "$SECRETS/rpc-url" ] && RPC_MOUNT="      - {type: bind, source: \"$SECRETS/rpc-url\", target: /run/secrets/mainnet-rpc-url, read_only: true, bind: {create_host_path: false}}"

# 5. Compose: the repository files plus local overrides for Caddy, restarts and signing
cat > "$DIR/.env" <<EOF
LINCOLN_MAINNET_IMAGE=$IMAGE_ID
LINCOLN_MAINNET_PUBLIC_RELEASE=$RELEASE
LINCOLN_MAINNET_CONFIG_DIR=$CONFIG
LINCOLN_MAINNET_STATE_DIR=$STATE
LINCOLN_MAINNET_POOL_ID=$POOL
EOF
cat > "$DIR/compose.local.yaml" <<EOF
# Written by install.sh. Read-only relay behind Caddy.
services:
  api:
    restart: unless-stopped
    # This compose project runs exactly one API container on this state directory, so a lock
    # left by a crashed or killed run is stale when the container starts. Without this, one
    # crash would keep the relay down until someone removed the locks by hand.
    command: ["sh", "-ec", "find /app/.phase1-private/phase2-mainnet -name .service.lock -type f -delete; exec node /app/docker/mainnet/start.mjs $ROLE $POOL"]
$( [ "$POOL_COUNT" -gt 1 ] && printf '    ports: ["127.0.0.1:19898-%s:8798-%s"]\n' "$((19897+POOL_COUNT-1))" "$((8797+POOL_COUNT-1))" )
    environment:
      PHASE2_MAINNET_ASSOCIATION_SET_MIRROR_URL: "$MIRROR_URL"
      PHASE2_MAINNET_PUBLISHER_STATUS_MIRROR_URL: "$MIRROR_URL"
$( [ -n "$RPC_MOUNT" ] && printf '    volumes:\n%s\n' "$RPC_MOUNT" )
  caddy:
    image: $CADDY_IMAGE
    restart: unless-stopped
    depends_on: [api]
    ports: ["80:80", "443:443"]
    volumes:
      - $DIR/Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy-data:/data
      - caddy-config:/config
    networks: [mainnet]
volumes:
  caddy-data: {}
  caddy-config: {}
EOF
cat > "$DIR/compose.signing.local.yaml" <<EOF
# Written by install.sh. Adds the relay key and points receipts.
services:
  api:
    environment:
      LINCOLN_MAINNET_SIGNING_ENABLED: "1"
      PHASE2_MAINNET_POINTS_SEASON: "$POINTS_SEASON"
    volumes:
      - {type: bind, source: "$SECRETS/relay.keystore.json", target: /run/secrets/mainnet-relay.keystore.json, read_only: true, bind: {create_host_path: false}}
      - {type: bind, source: "$SECRETS/relay.password", target: /run/secrets/mainnet-relay.password, read_only: true, bind: {create_host_path: false}}
EOF
# https://<host>/<pool>/... reaches that pool's listener; https://<host>/... the first pool, as a single-pool relay.
{ echo "{"; [ -n "$EMAIL" ] && echo "  email $EMAIL"; [ "$TLS" = internal ] && echo "  local_certs"; echo "}"
  echo "$DOMAIN {"; echo "  encode gzip"
  # The app's relay picker reads this list once instead of probing every pool.
  echo "  handle /pools {"; echo "    header Content-Type application/json"; echo "    respond \`{\"pools\":[$(printf '"%s",' "${POOL_LIST[@]}" | sed 's/,$//')]}\` 200"; echo "  }"
  i=0; for p in "${POOL_LIST[@]}"; do echo "  handle_path /$p/* {"; echo "    reverse_proxy api:$((8797+i))"; echo "  }"; i=$((i+1)); done
  echo "  handle {"; echo "    reverse_proxy api:8797"; echo "  }"; echo "}"; } > "$DIR/Caddyfile"

# 6. Control script
POOLS_SPACED=${POOLS//,/ }
cat > /usr/local/bin/lincoln-relay <<EOF
#!/usr/bin/env bash
# Written by install.sh for $DIR.
set -euo pipefail
cd "$DIR"
base=(docker compose --env-file .env -f src/docker/mainnet/compose.yaml -f compose.local.yaml)
sign=(-f compose.signing.local.yaml)
mode(){ [ -f signing.on ] && echo signing || echo read-only; }
compose(){ if [ "\$(mode)" = signing ]; then "\${base[@]}" "\${sign[@]}" "\$@"; else "\${base[@]}" "\$@"; fi; }
case "\${1:-status}" in
  up) compose up -d api caddy;;
  restart) compose up -d --force-recreate api && compose up -d caddy;;
  down) compose down;;
  logs) compose logs -f --tail=200 api;;
  address) echo "$ADDRESS";;
  consent)
    # EIP-712 RelayConsent(relay, owner, nonce) for RelayStakeRegistryV2, signed by the relay key on this server.
    owner=\${2:-}; registry=\${3:-$REGISTRY}
    [[ \$owner =~ ^0x[0-9a-fA-F]{40}\$ && \$registry =~ ^0x[0-9a-fA-F]{40}\$ ]] || { echo "usage: lincoln-relay consent <owner 0x…> [registry 0x…]" >&2; exit 2; }
    docker run --rm --user $APP_UID:$APP_UID --entrypoint sh -v "$SECRETS:/k:ro" "$IMAGE_ID" -ec \
      'n=\$(cast call "\$1" "nonces(address)(uint256)" "\$2" --rpc-url "\$4" | cut -d" " -f1)
       cast wallet sign --keystore /k/relay.keystore.json --password-file /k/relay.password --data "{\"types\":{\"EIP712Domain\":[{\"name\":\"name\",\"type\":\"string\"},{\"name\":\"version\",\"type\":\"string\"},{\"name\":\"chainId\",\"type\":\"uint256\"},{\"name\":\"verifyingContract\",\"type\":\"address\"}],\"RelayConsent\":[{\"name\":\"relay\",\"type\":\"address\"},{\"name\":\"owner\",\"type\":\"address\"},{\"name\":\"nonce\",\"type\":\"uint256\"}]},\"primaryType\":\"RelayConsent\",\"domain\":{\"name\":\"Lincoln Relay Stake Registry\",\"version\":\"2\",\"chainId\":4663,\"verifyingContract\":\"\$1\"},\"message\":{\"relay\":\"\$2\",\"owner\":\"\$3\",\"nonce\":\"\$n\"}}"' \
      sh "\$registry" "$ADDRESS" "\$owner" "$MAINNET_RPC";;
  health) for p in $POOLS_SPACED; do printf '%s: ' "\$p"; curl -fsS --max-time 10 "https://$DOMAIN/\$p/readyz"$( [ "$TLS" = internal ] && echo ' -k' ) || true; echo; done;;
  signing)
    case "\${2:-}" in
      on) docker run --rm --entrypoint sh "$IMAGE_ID" -ec \
            'b=\$(cast balance $ADDRESS --rpc-url $MAINNET_RPC); node -e "process.exit(BigInt(process.argv[1])>BigInt(process.argv[2])?0:1)" "\$b" $RESERVE_WEI' \
            || { echo "fund $ADDRESS with ETH on Robinhood Chain first (it must hold more than the $RESERVE_ETH ETH reserve)" >&2; exit 1; }
          touch signing.on; compose up -d api caddy;;
      off) rm -f signing.on; compose up -d api caddy;;
      *) echo "usage: lincoln-relay signing on|off" >&2; exit 2;;
    esac;;
  status) echo "relay $ADDRESS, pools $POOLS, https://$DOMAIN, mode \$(mode)"; compose ps;;
  *) echo "usage: lincoln-relay [status|up|restart|down|logs|health|address|consent <owner>|signing on|signing off]" >&2; exit 2;;
esac
EOF
chmod 0755 /usr/local/bin/lincoln-relay

# 7. Start read-only, wait for the release check, then report
say "Starting the relay read-only (the first start verifies the release and syncs chain history; allow up to 30 minutes)"
# Recreate the API so a changed config or release is always loaded.
/usr/local/bin/lincoln-relay restart >/dev/null
ok=0
for _ in $(seq 1 360); do
  if curl -fsS --max-time 5 http://127.0.0.1:19897/livez >/dev/null 2>&1; then ok=1; break; fi
  sleep 5
done
[ $ok -eq 1 ] || die "the relay did not come up; see: lincoln-relay logs"
ready=$(curl -sS --max-time 10 -H "Host: $DOMAIN" http://127.0.0.1:19897/readyz || true)
CONSENT=
if [ -n "$OWNER" ] && [ -n "$REGISTRY" ]; then CONSENT=$(/usr/local/bin/lincoln-relay consent "$OWNER") || warn "could not sign the consent; run: lincoln-relay consent $OWNER"; fi
cat <<EOF

Lincoln relay installed ($COMMIT, pools $POOLS)
  endpoint       https://$DOMAIN$( [ "$POOL_COUNT" -gt 1 ] && printf '  (per pool: https://%s/<pool>/v3/...)' "$DOMAIN" )
  relay address  $ADDRESS
$( if [ -n "$CONSENT" ]; then printf '  consent        %s  (owner %s)' "$CONSENT" "$OWNER"; else printf '  consent        not signed yet (see step 3)'; fi )
  readiness      $ready

Next:
  1. Back up $SECRETS (relay key and password). It is the only copy.
  2. Send ETH for gas to $ADDRESS on Robinhood Chain, then run: lincoln-relay signing on
  3. Register at $REGISTER_URL from your owner wallet with relayer $ADDRESS, endpoint https://$DOMAIN$( [ -n "$CONSENT" ] && echo " and the consent above" ).
     The stake comes from the owner wallet; the relay key never holds LINCOLN.$( [ -z "$CONSENT" ] && printf '\n     Consent for your owner wallet: lincoln-relay consent <owner 0x…>' )
  Check it any time with: lincoln-relay health
EOF
