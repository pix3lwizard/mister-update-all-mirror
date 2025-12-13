# MiSTer Update_All Bunny Mirror

Unofficial mirror of the [Update_All_MiSTer](https://github.com/theypsilon/Update_All_MiSTer) databases, hosted on [Bunny.net](https://bunny.net/) and kept in sync via GitHub Actions.

This repository does **not** replace Update All. Instead, it provides a fast, CDN-backed mirror for the databases and files that Update All uses, so MiSTer users can pull from a closer, more reliable source.

> **Status:** Experimental and community-maintained. This is not an official MiSTer or Update All project.

---

## What this project does

At a high level:

1. **Reads the "source of truth" database list** from Theypsilon’s `databases.py` in the Update_All_MiSTer repo.
2. **Identifies the exact GitHub commits** referenced by each database (via `base_files_url`, `linux`, `zips`, etc).
3. **Downloads those commit snapshots** from GitHub as zipballs.
4. **Uploads their contents to Bunny Storage** under a path that includes the commit SHA:
   ```text
   /<owner>/<repo>/<commit-sha>/...
