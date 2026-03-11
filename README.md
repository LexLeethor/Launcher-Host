# CBGames Launcher Host

Standalone launcher host service for the CBGames Offline Launcher.

## Features

- Serves shared host files through `/api/manifest`.
- Supports launcher OTC uploads through `PUT /api/client-upload?otc=CODE`.
- Browser dashboard supports admin sign-in and bundle management.
- Manage bundles from the web UI (upload, rename, share/private, delete).
- Change the admin username/password from the web UI.
- The launcher can be downloaded from the host (mirrors the latest GitHub release).

## Requirements

- Node.js 18+

## Run

```bash
npm run start
```

or:

```bash
node host.mjs
```

## CLI options

```bash
node host.mjs --host 0.0.0.0 --port 8941 --store ./.cbgames-launcher-host
```

## Host terminal commands

- `help`
- `status`
- `urls`
- `import <path.zip> [bundle|zip] [shared|private]`
- `list`
- `share <id> <shared|private>`
- `delete <id>`
- `otc [minutes]`
- `clear-otc`
- `exit` / `quit`

## Web UI admin

- After sign-in you can upload, rename, share/private, delete bundles, and change credentials.

## Launcher download

- The host mirrors the latest GitHub release and serves it at `/download/launcher`.
