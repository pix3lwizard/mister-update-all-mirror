# Development

## Running locally

```bash
export BUNNY_STORAGE_ZONE="mister-update"
export BUNNY_ACCESS_KEY="your-api-key"
export BUNNY_STORAGE_HOST="la.storage.bunnycdn.com"
export MIRROR_BASE_URL="https://mister-update.b-cdn.net"
export GITHUB_TOKEN="optional-token"
python src/mirror.py
```

Be careful: this performs real uploads.

For a dry run, you can add logic in `mirror.py` keyed off an environment
variable such as `DRY_RUN=1` and short‑circuit the upload helpers.

## Notes

- All DB definitions come from `theypsilon/Update_All_MiSTer`.
- The script tries to be explicit and easy to audit.
- If upstream changes the structure of the DBs, `mirror.py` may need tweaks
  to keep discovering `(owner, repo, ref)` correctly.
