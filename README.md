# Lincoln Relay

Relay service for the [Lincoln](https://docs.lincolnprotocol.com/token/tokenomics) privacy pools on Robinhood Chain (chainId 4663).

A relay receives a proof that a user generated in their own wallet, checks it against the chain, and submits the transaction from the relay's address so the user never has to fund a public wallet. The pools bind `processor`, `recipient`, `feeRecipient`, `fee` and the amounts into the proof, so a relay cannot redirect funds, change the fee, or replay a proof under a different address. The worst a relay can do is refuse or delay a job; the user then proves again for another relay.

- Operator guide: https://docs.lincolnprotocol.com/token/relay-operators
- Contracts, circuits and the public release: [Lincoln-protocol-core](https://github.com/LincolnProtocol-com/Lincoln-protocol-core)

## What is in this repository

| Path | Content |
| --- | --- |
| `src/` | The relay service: proof and job validation, the shared nonce and gas ledger, association-set loading, fee quotes, points receipts |
| `docker/mainnet/` | Runtime image, Compose files, the public-release stager and the image-content audit |
| `config/mainnet-deployed.json` | Public deployment profile of all 15 pools, with `relayer` left empty for you to fill |
| `scripts/` | `set-relayer.mjs` writes your relay address into the profile; `check.mjs` is an offline self-check |

There are no keys, wallets, RPC credentials or private state in this repository. Proving keys and contract artifacts are public release inputs that you stage from `Lincoln-protocol-core`; they are mounted read-only and never built into the image.

## Run a relay

Requirements: Docker, Node 24, an EOA for the relay with ETH for gas, and a keystore for it made with `cast wallet import`.

```sh
npm ci --ignore-scripts
npm run check                      # offline: modules load, image allowlist, profiles parse

# 1. Image
docker build -f docker/mainnet/runtime.Dockerfile -t lincoln-relay:reviewed .

# 2. Public release (contract artifacts, final proving keys, sources) from Lincoln-protocol-core
git clone https://github.com/LincolnProtocol-com/Lincoln-protocol-core
(cd Lincoln-protocol-core/releases/rc3 && npm ci --ignore-scripts)
node docker/mainnet/stage-public-release.mjs /abs/mainnet-public-release   # run with releases/rc3 as the working directory's repo root; see below

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
| `PHASE2_MAINNET_ASSOCIATION_SET_FILE` / `PHASE2_MAINNET_ASSOCIATION_SET_MIRROR_URL` | Association set. Third-party relays point `FILE` at any path and fetch from the public mirror; root and digest are recomputed against the chain, so the mirror is untrusted transport |
| `PHASE2_MAINNET_RPC_FILE` | Optional file holding a private RPC URL (mode 0600). Without it the official public RPC is used |
| `PHASE2_MAINNET_POINTS_SEASON` | Enables points receipts: after a job confirms, your keystore signs an EIP-712 receipt for the user's claim address |
| `PHASE2_MAINNET_POINTS_URL` | Optional points service URL to forward receipts to |
| `PHASE2_MAINNET_SERVICE_FEES_FILE` | Your fee policy. Swaps must use a fee adapter and match its rate |

## Staking

Listing a relay for discovery, points and the 20% relay share requires a stake of 5,000,000 LINCOLN in the relay stake registry, with a 14-day unbonding period and no slashing. The registry address is announced separately. Running a relay does not need the stake: the pools accept any processor.

Points count only fees the treasury Safe receives. A fee your relay keeps for itself earns no points for you or your users, and the relay signs no receipt for it (`pointsStatus: no-fee`). Your relay share is 20% of the points of the treasury-received fees in the jobs you process, in practice the 30 bps adapter fee on swaps. Only the relay that processed a fee can sign its receipt.

## API

`GET /v3/config`, `GET /healthz`, `GET /v3/state`, `GET /v3/association-set`, `POST /v3/fees`, `POST /v3/quote`, `POST /v3/jobs`, `GET /v3/jobs/{id}`. `POST /v3/jobs` accepts an optional `points: {claimant, referrer}`; it is not part of the relayed transaction.

## License

The source files in this repository are licensed under Apache-2.0 (see each file's SPDX header and [LICENSE](LICENSE)). Runtime dependencies keep their own licenses; notably SnarkJS is GPL-3.0 and OpenZeppelin Contracts is MIT. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
