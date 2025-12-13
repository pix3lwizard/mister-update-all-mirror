# MiSTer Update_All Bunny Mirror

This repository contains a standalone mirroring script that keeps a Bunny.net
Storage Zone in sync with the MiSTer `Update_All` ecosystem.

It:

1. Downloads `databases.py` from the upstream
   [`theypsilon/Update_All_MiSTer`](https://github.com/theypsilon/Update_All_MiSTer)
   project.
2. Discovers every database in `AllDBs` that has a `db_url`.
3. Parses each database (`db.json` / `db.json.zip`) to find the GitHub
   repositories and commit hashes they reference.
4. Mirrors those repositories to a Bunny Storage Zone, under paths that include
   the commit SHA:
   ```text
   {owner}/{repo}/{ref}/...
   ```
5. Rewrites each database to point at the Bunny mirror and uploads the
   rewritten DB to a `mirror-1`-compatible location:
   ```text
   {owner}/{repo}/{branch}/db.json[.zip]
   ```
6. Rotates old commits so that only the most recent 2–3 refs are kept per repo
   in Bunny Storage, as recommended by theypsilon.

> This repo is **not** a replacement for `Update_All`. It only hosts the
> mirroring logic. The actual updater still lives in
> [`theypsilon/Update_All_MiSTer`](https://github.com/theypsilon/Update_All_MiSTer).

## Layout

- `src/mirror.py` – main mirroring script.
- `.github/workflows/mirror.yml` – GitHub Actions workflow that runs the
  mirror on a schedule or manually.

## Requirements

- Bunny.net Storage Zone (e.g. `mister-update`)
- Python 3.12 on GitHub Actions (`ubuntu-latest` runner)

## Configuration

Configure these GitHub secrets:

- `BUNNY_STORAGE_ZONE` – Storage Zone name.
- `BUNNY_ACCESS_KEY` – API password for the Storage Zone.
- `BUNNY_STORAGE_HOST` – Hostname, e.g. `la.storage.bunnycdn.com`.
- `MIRROR_BASE_URL` – Public HTTP base, e.g. `https://mister-update.b-cdn.net`.
- `GITHUB_TOKEN` – optional PAT for higher GitHub API rate limits.

## How it works

1. Fetch `databases.py` from `theypsilon/Update_All_MiSTer`.
2. Discover DBs and extract `(owner, repo, ref)` tuples from their URLs.
3. Mirror each GitHub commit to Bunny under `{owner}/{repo}/{ref}/...`.
4. Write a `.mirrored.json` marker so already‑mirrored commits are skipped.
5. Rotate old refs so only the newest 2–3 remain.
6. Rewrite DB URLs to point at the mirror and upload the mirrored DBs in a
   layout compatible with theypsilon’s `mirror-1` branch.

## License

Licensed under the GNU General Public License v3.0 (GPLv3).
See [`LICENSE`](LICENSE) for details.
