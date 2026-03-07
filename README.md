# CBGames Launcher Host

Standalone launcher host service for the CBGames Offline Launcher.

## Features

- Serves shared host files through `/api/manifest`.
- Supports launcher OTC uploads through `PUT /api/client-upload?otc=CODE`.
- Browser dashboard is read-only.
- Host-only management (share/delete) is done from terminal commands.

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

