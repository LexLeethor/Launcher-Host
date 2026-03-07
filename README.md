# CBGames LAN Host

Standalone LAN host service for the CBGames Offline Launcher.

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
node lan-host.mjs
```

## CLI options

```bash
node lan-host.mjs --host 0.0.0.0 --port 8941 --store ./.cbgames-lan-host
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

## Publish as its own GitHub repo

From this folder:

```bash
git init
git add .
git commit -m "Initial CBGames LAN Host"
# with GitHub CLI
gh repo create cbgames-lan-host --public --source=. --remote=origin --push
```

If you do not use GitHub CLI, create the repo in GitHub first, then:

```bash
git remote add origin <your-repo-url>
git branch -M main
git push -u origin main
```
