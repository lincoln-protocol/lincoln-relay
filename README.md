# Lincoln Relay

Relay service for the [Lincoln](https://docs.lincolnprotocol.com/token/tokenomics) privacy pools on Robinhood Chain (chainId 4663).

A relay receives a proof that a user generated in their own wallet, checks it against the chain, and submits the transaction from the relay's address so the user never has to fund a public wallet. The pools bind `processor`, `recipient`, `feeRecipient`, `fee` and the amounts into the proof, so a relay cannot redirect funds, change the fee, or replay a proof under a different address. The worst a relay can do is refuse or delay a job; the user then proves again for another relay.

- Operator guide: https://docs.lincolnprotocol.com/token/relay-operators
- Contracts, circuits and the public release: [Lincoln-protocol-core](https://github.com/lincoln-protocol/Lincoln-protocol-core)

## What is in this repository

| Path | Content |
| --- | --- |
| `src/` | The relay service: proof and job validation, the shared nonce and gas ledger, association-set loading, fee quotes, points receipts |
| `docker/mainnet/` | Runtime image, Compose files, the public-release stager and the image-content audit |
| `config/mainnet-deployed.json` | Public deployment profile of all 15 pools, with `relayer` left empty for you to fill |
| `scripts/` | `set-relayer.mjs` writes your relay address into the profile; `check.mjs` is an offline self-check |

There are no keys, wallets, RPC credentials or private state in this repository. Proving keys and contract artifacts are public release inputs that you stage from `Lincoln-protocol-core`; they are mounted read-only and never built into the image.

## Install with one command

On a Linux server (4 GB of RAM or more, ports 80 and 443 open) with a DNS name pointing at it:

```sh
echo 'https://your-rpc-provider.example/v2/KEY' > rpc-url    # your own Robinhood Chain RPC
curl -fsSLo install.sh https://raw.githubusercontent.com/lincoln-protocol/lincoln-relay/c0c88ee9cf8d815e5e43e470fd3fcf11d72d0056/install.sh
echo '31b186d103eb4981536b4791c1b5bb675c85b2b713bd5011c7d45473fe8fb5fb  install.sh' | sha256sum -c - && \
  sudo bash install.sh --pools lincoln,eth --domain relay.example.com --owner 0xYourOwnerWallet --rpc-url-file rpc-url
```

`--pools` takes any of the 15 pools, comma-separated; one relay key, one endpoint and one stake cover all of them. Each pool
answers at `https://<domain>/<pool>/v3/...`; the first listed pool also answers at `https://<domain>/v3/...`, so a
single-pool relay (`--pool lincoln`) looks exactly as before.

This is the installer of [v0.1.0-rc.2](https://github.com/lincoln-protocol/lincoln-relay/releases/tag/v0.1.0-rc.2). Download it by commit, never from `main`, and read it before you run it as root. Newer releases list their own commit and checksum.

The installer:
- installs Docker if it is missing (it asks first);
- builds the relay image from the exact lincoln-relay commit pinned in the script, and stops if the checkout differs;
- stages the public release from `Lincoln-protocol-core` `v0.1.0-rc.3`, pinned by its full commit in the same way;
- pulls the Node, Foundry and Caddy images by digest;
- creates the relay key on the server and prints its address;
- writes the config;
- starts the relay read-only behind Caddy, which obtains the TLS certificate for `https://<domain>`.

The first start verifies the release and syncs chain history, which takes 10 to 30 minutes. A private RPC is required because the public one rate-limits that sync.

Then:
1. Back up `/opt/lincoln-relay/secrets`. It holds the only copy of the relay key.
2. Send ETH for gas to the relay address, then run `lincoln-relay signing on`.
3. Register at https://app.lincolnprotocol.com/relay from your owner wallet with the relay address, the endpoint, and the consent the installer printed (`lincoln-relay consent <owner>` signs a new one).

`lincoln-relay status | health | logs | address | signing on|off | up | down` manages it afterwards. Running a newer release's installer updates the code and keeps the key, state and RPC file.

## Run a relay by hand

Requirements: Docker, Node 24, an EOA for the relay with ETH for gas, and a keystore for it made with `cast wallet import`.

```sh
npm ci --ignore-scripts
npm run check                      # offline: modules load, image allowlist, profiles parse

# 1. Image
docker build -f docker/mainnet/runtime.Dockerfile -t lincoln-relay:reviewed .

# 2. Public release (contract artifacts, final proving keys, sources) from Lincoln-protocol-core
git clone https://github.com/lincoln-protocol/Lincoln-protocol-core
(cd Lincoln-protocol-core/releases/rc3 && npm ci --ignore-scripts)
node docker/mainnet/stage-public-release.mjs /abs/mainnet-public-release   # run with releases/rc3 as the working directory's repo root; see below
# rc3 leaves config/phase2-mainnet.json deployer.address null; set it to the pool deployer 0x36437b878415EdA1a24186CF79AFffBc9ecEd298

# 3. Config: profile with your relay address, plus runtime.json
mkdir /abs/mainnet-config
node scripts/set-relayer.mjs 0xYourRelay /abs/mainnet-config/mainnet-deployed.json
cp docker/mainnet/runtime.example.json /abs/mainnet-config/runtime.json   # set relay.address, poolIds, budgets
```

`stage-public-release.mjs` reads `config/`, `artifacts/`, `protocol/`, the Powers of Tau file under `vendor/` and the pinned compiler packages from the repository it runs in, and exports a finite, hash-checked set. Copy it into `Lincoln-protocol-core/releases/rc3/docker/mainnet/` and run it from there, or run it from a checkout that contains that release. The relay re-verifies every input at startup: it recompiles the contracts, checks the final proving keys and verification keys, and compares runtime code hashes on chain.

Then start the API for one pool:

```sh
export LINCOLN_MAINNET_IMAGE=lincoln-relay:reviewed
export LINCOLN_MAINNET_PUBLIC_RELEASE=/abs/mainnet-public-release
export LINCOLN_MAINNET_CONFIG_DIR=/abs/mainnet-config
export LINCOLN_MAINNET_STATE_DIR=/abs/mainnet-state          # empty, owned by 10001:10001, mode 0700, backed up
export LINCOLN_MAINNET_POOL_ID=lincoln
docker compose -f docker/mainnet/compose.yaml up -d api                                         # read-only first
docker compose -f docker/mainnet/compose.yaml -f docker/mainnet/compose.signing.yaml up -d api  # then signing
```

Signing stays off until `runtime.json` sets `relay.enabled`, a gas budget, a maximum fee per gas and a reserve, and the signing Compose file mounts your keystore and password file.

## Environment

| Variable | Purpose |
| --- | --- |
| `PHASE2_MAINNET_ASSOCIATION_SET_FILE` / `PHASE2_MAINNET_ASSOCIATION_SET_MIRROR_URL` | Association set. Third-party relays point `FILE` at any path and fetch from the public mirror `https://lincolnprotocol.com/asp/` (the trailing slash is required); root and digest are recomputed against the chain, so the mirror is untrusted transport |
| `PHASE2_MAINNET_RPC_FILE` | Optional file holding a private RPC URL (mode 0600). Without it the official public RPC is used |
| `PHASE2_MAINNET_POINTS_SEASON` | Enables points receipts: after a job confirms, your keystore signs an EIP-712 receipt for the user's claim address. Use `season-1` |
| `PHASE2_MAINNET_POINTS_URL` | Optional points service URL to forward receipts to. There is no public points service yet: leave it unset, and `GET /v3/jobs/{id}` keeps the signed receipt (`pointsReceipt`, `pointsStatus`) for later submission |
| `PHASE2_MAINNET_SERVICE_FEES_FILE` | Your fee policy. Swaps must use a fee adapter and match its rate |

## Staking

Listing a relay for discovery, points and the 20% relay share requires a stake of 5,000,000 LINCOLN in `RelayStakeRegistryV2` at `0xfF986c58e467De9862BF97a1c2782D4b263C8307` (from block 95221645), with a 14-day unbonding period and no slashing. A cold owner wallet (it may be a Safe) stakes, controls the listing and receives every withdrawal; the relay server key has no staking powers. It only signs a one-time EIP-712 consent to be listed under that owner: `lincoln-relay consent <owner>` prints it, and the installer prints it for `--owner`. If the server key leaks, the owner rotates the listing to a new key with `rotateRelayer`. Do not stake in the retired first deployment `0x1429f7BAA41baee9d6C7989DBdDc4C6344c8204B`. Running a relay does not need the stake: the pools accept any processor.

Points count only fees the treasury Safe receives. A fee your relay keeps for itself earns no points for you or your users, and the relay signs no receipt for it (`pointsStatus: no-fee`). Your relay share is 20% of the points of the treasury-received fees in the jobs you process, in practice the 30 bps adapter fee on swaps. Only the relay that processed a fee can sign its receipt.

## API

`GET /v3/config`, `GET /healthz`, `GET /v3/state`, `GET /v3/association-set`, `POST /v3/fees`, `POST /v3/quote`, `POST /v3/jobs`, `GET /v3/jobs/{id}`. `POST /v3/jobs` accepts an optional `points: {claimant, referrer}`; it is not part of the relayed transaction.

## License

The source files in this repository are licensed under Apache-2.0 (see each file's SPDX header and [LICENSE](LICENSE)). Runtime dependencies keep their own licenses; notably SnarkJS is GPL-3.0 and OpenZeppelin Contracts is MIT. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
