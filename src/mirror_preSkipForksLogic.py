# src/mirror.py
import io
import json
import os
import re
import zipfile
import types
import importlib.util
from urllib.parse import urlparse
from pathlib import PurePosixPath
from datetime import datetime
import time
import tempfile
import mimetypes

import requests

# Upstream "source of truth" for DB definitions
UPSTREAM_DATABASES_URL = (
    "https://raw.githubusercontent.com/theypsilon/Update_All_MiSTer/"
    "master/src/update_all/databases.py"
)

# GitHub zipball template for mirroring specific commits
GITHUB_ZIPBALL_TEMPLATE = "https://api.github.com/repos/{owner}/{repo}/zipball/{ref}"

# Bunny + mirror configuration (provided via GitHub Actions env)
BUNNY_STORAGE_ZONE = os.environ["BUNNY_STORAGE_ZONE"]
BUNNY_ACCESS_KEY = os.environ["BUNNY_ACCESS_KEY"]
BUNNY_STORAGE_HOST = os.environ.get("BUNNY_STORAGE_HOST", "storage.bunnycdn.com")
MIRROR_BASE_URL = os.environ["MIRROR_BASE_URL"].rstrip("/")

# External payload mirroring toggles
MIRROR_GITHUB_RELEASE_ASSETS = os.environ.get("MIRROR_GITHUB_RELEASE_ASSETS", "1") == "1"
MIRROR_ARCHIVE_ORG = os.environ.get("MIRROR_ARCHIVE_ORG", "0") == "1"



def http_get(url, **kwargs):
    print(f"[GET] {url}")
    resp = requests.get(url, timeout=60, **kwargs)
    resp.raise_for_status()
    return resp


def http_put_to_bunny(dest_path, data, content_type=None, max_retries=3):
    """
    Upload a single object to Bunny Storage.

    - Retries a few times on transient network issues (timeouts, connection resets).
    - Skips 400 Bad Request objects (Bunny hates some filenames) but keeps going.
    - Raises on "hard" HTTP errors (5xx, 403, etc.).
    """
    dest = str(dest_path).lstrip("/")
    url = f"https://{BUNNY_STORAGE_HOST}/{BUNNY_STORAGE_ZONE}/{dest}"
    print(f"[PUT] {url}")

    headers = {"AccessKey": BUNNY_ACCESS_KEY}
    if content_type:
        headers["Content-Type"] = content_type

    for attempt in range(1, max_retries + 1):
        try:
            # Slightly more generous timeout than before
            resp = requests.put(url, data=data, headers=headers, timeout=120)
        except (requests.exceptions.ReadTimeout,
                requests.exceptions.ConnectTimeout,
                requests.exceptions.ConnectionError) as e:
            print(
                f"[WARN] PUT attempt {attempt}/{max_retries} to Bunny timed out "
                f"or failed for {url}: {e}"
            )
            if attempt == max_retries:
                print(
                    "[WARN] Giving up on this object for now; "
                    "it can be retried on a later run."
                )
                return None
            # brief backoff before retrying
            time.sleep(2 * attempt)
            continue
        except requests.exceptions.RequestException as e:
            # Some other non-HTTP request problem; log and skip this one file
            print(f"[ERROR] RequestException talking to Bunny for {url}: {e!r}")
            return None

        # Got a response, now handle status codes
        if resp.status_code == 400:
            msg = (resp.text or "")[:200]
            print(
                f"[WARN] Bunny 400 Bad Request for {url}: {msg!r} – "
                "skipping this object"
            )
            return None

        if not resp.ok:
            msg = (resp.text or "")[:200]
            print(
                f"[ERROR] Bunny responded with {resp.status_code} for {url}: "
                f"{msg!r}"
            )
            # For 401/403/5xx, still raise so we notice real config problems
            resp.raise_for_status()

        # Success
        return resp


def list_bunny_directory(path):
    """
    List files in a Bunny Storage directory.
    Returns a list of objects (dicts with ObjectName, IsDirectory, LastChanged, etc.),
    or [] if the directory doesn't exist.
    """
    dir_path = str(PurePosixPath(path)).lstrip("/")
    url = f"https://{BUNNY_STORAGE_HOST}/{BUNNY_STORAGE_ZONE}/{dir_path}"
    print(f"[LIST] {url}")
    headers = {"AccessKey": BUNNY_ACCESS_KEY}
    resp = requests.get(url, headers=headers, timeout=60)

    if resp.status_code == 404:
        return []

    resp.raise_for_status()
    try:
        return resp.json()
    except Exception:
        return []


def bunny_object_exists(path):
    """
    Return True if a given object exists in Bunny Storage, False if 404.

    If Bunny rejects the HEAD (401/403/etc), we log a warning and
    assume the object does NOT exist so the mirror can proceed.
    """
    obj = str(path).lstrip("/")
    url = f"https://{BUNNY_STORAGE_HOST}/{BUNNY_STORAGE_ZONE}/{obj}"
    headers = {"AccessKey": BUNNY_ACCESS_KEY}

    print(f"[HEAD] {url}")
    resp = requests.head(url, headers=headers, timeout=30)

    if resp.status_code == 404:
        return False

    if resp.status_code in (401, 403):
        msg = (resp.text or "")[:200]
        print(
            f"[WARN] Bunny HEAD {url} returned {resp.status_code}; "
            f"treating as 'not mirrored yet'. Response: {msg!r}"
        )
        return False

    resp.raise_for_status()
    return True


def delete_bunny_path(path):
    """
    Delete a file or "directory" path in Bunny Storage.
    """
    obj = str(path).lstrip("/")
    url = f"https://{BUNNY_STORAGE_HOST}/{BUNNY_STORAGE_ZONE}/{obj}"
    print(f"[DELETE] {url}")
    headers = {"AccessKey": BUNNY_ACCESS_KEY}
    resp = requests.delete(url, headers=headers, timeout=60)
    if resp.status_code not in (200, 204, 404):
        resp.raise_for_status()


def load_upstream_databases_module():
    """
    Fetch theypsilon's databases.py and exec it into a module object.
    We trust this code (same trust as running update_all itself).
    """
    resp = http_get(UPSTREAM_DATABASES_URL)
    source = resp.text

    spec = importlib.util.spec_from_loader("upstream_databases", loader=None)
    mod = types.ModuleType(spec.name)
    exec(source, mod.__dict__)
    return mod


def iter_all_db_entries(upstream_mod):
    """
    Iterate over (name, db) from AllDBs.* where db has a db_url.
    """
    all_dbs_cls = upstream_mod.AllDBs
    for attr in dir(all_dbs_cls):
        if attr.startswith("_"):
            continue
        db = getattr(all_dbs_cls, attr)
        if hasattr(db, "db_url"):
            yield attr, db


def download_db_json(db_url):
    """
    Download a DB from db_url.
    Returns (db_json_dict, original_bytes, is_zipped).
    """
    resp = http_get(db_url)
    content = resp.content

    if db_url.endswith(".zip") or db_url.endswith(".json.zip"):
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            # assume single json file inside
            inner_name = [n for n in zf.namelist() if n.endswith(".json")][0]
            data = zf.read(inner_name)
            return json.loads(data.decode("utf-8")), content, True
    else:
        return json.loads(resp.text), content, False


def parse_raw_github_base(url):
    """
    Given something like:
      https://raw.githubusercontent.com/MiSTer-devel/Distribution_MiSTer/8323352e.../some/path/
    return (owner, repo, ref).

    Returns None if the value is not a string or not a raw.githubusercontent.com URL.
    """
    if not url or not isinstance(url, str):
        return None

    p = urlparse(url)
    if "raw.githubusercontent.com" not in p.netloc:
        return None

    parts = [x for x in p.path.split("/") if x]
    if len(parts) < 3:
        return None

    owner, repo, ref = parts[0], parts[1], parts[2]
    return owner, repo, ref



def parse_github_release_asset(url):
    """
    Match GitHub release asset URLs:
      https://github.com/<owner>/<repo>/releases/download/<tag>/<asset...>

    Returns (owner, repo, relpath_under_repo) or None.
    """
    if not url or not isinstance(url, str):
        return None
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        return None
    if p.netloc not in ("github.com", "www.github.com"):
        return None
    parts = [x for x in p.path.split("/") if x]
    if len(parts) < 6:
        return None
    owner, repo = parts[0], parts[1]
    if parts[2:4] != ["releases", "download"]:
        return None
    # keep the rest exactly (download/<tag>/<asset...>)
    rel = "/".join(parts[2:])
    return owner, repo, rel


def parse_archive_org_download(url):
    """
    Match archive.org download URLs:
      https://archive.org/download/<identifier>/<file...>

    Returns relpath under /download/... or None.
    """
    if not url or not isinstance(url, str):
        return None
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        return None
    if not p.netloc.endswith("archive.org"):
        return None
    parts = [x for x in p.path.split("/") if x]
    if len(parts) < 2:
        return None
    if parts[0] != "download":
        return None
    rel = "/".join(parts)  # download/<identifier>/...
    return rel


def guess_content_type_from_path(path_str):
    ct, _ = mimetypes.guess_type(path_str)
    return ct or "application/octet-stream"


def http_put_file_to_bunny(dest_path, file_path, content_type=None, max_retries=3):
    """
    Stream a local file to Bunny without loading it all into RAM.
    """
    dest = str(dest_path).lstrip("/")
    url = f"https://{BUNNY_STORAGE_HOST}/{BUNNY_STORAGE_ZONE}/{dest}"
    print(f"[PUT-FILE] {url}")

    headers = {"AccessKey": BUNNY_ACCESS_KEY}
    if content_type:
        headers["Content-Type"] = content_type

    for attempt in range(1, max_retries + 1):
        try:
            with open(file_path, "rb") as f:
                resp = requests.put(url, data=f, headers=headers, timeout=600)
        except (requests.exceptions.ReadTimeout,
                requests.exceptions.ConnectTimeout,
                requests.exceptions.ConnectionError) as e:
            print(f"[WARN] PUT-FILE attempt {attempt}/{max_retries} failed: {e!r}")
            if attempt < max_retries:
                time.sleep(2 ** attempt)
                continue
            raise

        if resp.status_code == 400:
            msg = (resp.text or "")[:200]
            print(f"[WARN] Bunny 400 Bad Request for {url}: {msg!r} – skipping")
            return None

        if not resp.ok:
            msg = (resp.text or "")[:200]
            print(f"[ERROR] Bunny responded with {resp.status_code} for {url}: {msg!r}")
            resp.raise_for_status()

        return resp


def iter_http_urls(obj):
    """
    Recursively yield http(s) URLs from nested JSON structures.
    """
    if isinstance(obj, str):
        if obj.startswith("http://") or obj.startswith("https://"):
            yield obj
        return
    if isinstance(obj, list):
        for v in obj:
            yield from iter_http_urls(v)
        return
    if isinstance(obj, dict):
        for v in obj.values():
            yield from iter_http_urls(v)
        return


def mirror_external_url(url):
    """
    Mirror non-raw payload URLs that appear in DBs.

    - GitHub release assets are mirrored under /<owner>/<repo>/<releases/download/...>
    - archive.org downloads (optional) are mirrored under /_ext/archive.org/<download/...>
    """
    if not url or not isinstance(url, str):
        return

    # Avoid loops if a DB is already rewritten
    if url.startswith(MIRROR_BASE_URL + "/"):
        return

    rel_release = parse_github_release_asset(url) if MIRROR_GITHUB_RELEASE_ASSETS else None
    if rel_release:
        owner, repo, rel = rel_release
        dest_path = PurePosixPath(owner) / repo / rel
        if bunny_object_exists(dest_path):
            return
        print(f"[EXT] Mirroring GitHub release asset {url} -> {dest_path}")
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = tmp.name
        try:
            with requests.get(url, stream=True, allow_redirects=True, timeout=300) as r:
                r.raise_for_status()
                with open(tmp_path, "wb") as out:
                    for chunk in r.iter_content(chunk_size=1024 * 1024):
                        if chunk:
                            out.write(chunk)
            http_put_file_to_bunny(dest_path, tmp_path, content_type=guess_content_type_from_path(str(dest_path)))
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        return

    rel_arch = parse_archive_org_download(url) if MIRROR_ARCHIVE_ORG else None
    if rel_arch:
        dest_path = PurePosixPath("_ext") / "archive.org" / rel_arch
        if bunny_object_exists(dest_path):
            return
        print(f"[EXT] Mirroring archive.org asset {url} -> {dest_path}")
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = tmp.name
        try:
            with requests.get(url, stream=True, allow_redirects=True, timeout=600) as r:
                r.raise_for_status()
                with open(tmp_path, "wb") as out:
                    for chunk in r.iter_content(chunk_size=1024 * 1024):
                        if chunk:
                            out.write(chunk)
            http_put_file_to_bunny(dest_path, tmp_path, content_type=guess_content_type_from_path(str(dest_path)))
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        return


def collect_external_assets_from_db(db_json):
    """
    Return a set of external URLs (GitHub release assets, archive.org optionally)
    that should be mirrored.
    """
    urls = set()
    for u in iter_http_urls(db_json):
        if u.startswith(MIRROR_BASE_URL + "/"):
            continue
        if MIRROR_GITHUB_RELEASE_ASSETS and parse_github_release_asset(u):
            urls.add(u)
        elif MIRROR_ARCHIVE_ORG and parse_archive_org_download(u):
            urls.add(u)
    return urls



def collect_commits_from_db(db_json):
    """
    Collect all (owner, repo, ref) tuples referenced by a DB JSON.
    """
    commits = set()

    # 1. base_files_url
    base_files_url = db_json.get("base_files_url", "")
    parsed = parse_raw_github_base(base_files_url)
    if parsed:
        commits.add(parsed)

    # 2. linux (Distribution MiSTer)
    linux_url = db_json.get("linux")
    parsed = parse_raw_github_base(linux_url) if linux_url else None
    if parsed:
        commits.add(parsed)

    # 3. zips[*].summary_file / contents_file
    for zip_entry in db_json.get("zips", []):
        if not isinstance(zip_entry, dict):
            continue
        for key in ("summary_file", "contents_file"):
            url = zip_entry.get(key)
            parsed = parse_raw_github_base(url) if url else None
            if parsed:
                commits.add(parsed)

    # 4. First file url (list-style DBs) or per-file url (dict-style DBs, e.g. update_all_mister)
    files_val = db_json.get("files", [])
    if isinstance(files_val, list):
        files = [f for f in files_val if isinstance(f, dict)]
        # Optimization: most list-style DBs point to a single commit, so the first is enough.
        if not commits and files:
            first = files[0]
            url = first.get("url") or first.get("file") or ""
            parsed = parse_raw_github_base(url)
            if parsed:
                commits.add(parsed)
    elif isinstance(files_val, dict):
        # update_all_mister-style:
        #   "files": { "path": { ..., "url": "https://raw.githubusercontent.com/..." }, ... }
        # Collect all commit refs we can find.
        for meta in files_val.values():
            if not isinstance(meta, dict):
                continue
            url = meta.get("url") or meta.get("file") or ""
            parsed = parse_raw_github_base(url)
            if parsed:
                commits.add(parsed)

    return commits


def mirror_repo_commit(owner, repo, ref):
    """
    Download the zipball of (owner, repo, ref), unpack, upload to Bunny under:
      /owner/repo/ref/<files...>

    Uses a .mirrored.json marker under that ref directory to avoid re-uploading
    the same commit on subsequent runs.
    """
    base_dir = PurePosixPath(owner) / repo / ref
    marker_path = base_dir / ".mirrored.json"

    # If we've already mirrored this commit once, skip it
    if bunny_object_exists(marker_path):
        print(f"[SKIP] {owner}/{repo}@{ref} already mirrored (marker present)")
        return

    zip_url = GITHUB_ZIPBALL_TEMPLATE.format(owner=owner, repo=repo, ref=ref)
    headers = {}
    gh_token = os.environ.get("GITHUB_TOKEN", "").strip()
    if gh_token:
        headers["Authorization"] = f"token {gh_token}"

    resp = http_get(zip_url, headers=headers)
    zdata = io.BytesIO(resp.content)

    with zipfile.ZipFile(zdata) as zf:
        # zipball has a single top-level directory like owner-repo-<hash>/
        for name in zf.namelist():
            if name.endswith("/"):
                continue
            data = zf.read(name)
            parts = name.split("/", 1)
            if len(parts) == 1:
                rel_path = parts[0]
            else:
                rel_path = parts[1]
            dest_path = base_dir / rel_path
            http_put_to_bunny(dest_path, data)

    # If we reached here, uploads completed for this commit.
    marker = {
        "owner": owner,
        "repo": repo,
        "ref": ref,
        "mirrored_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }
    http_put_to_bunny(
        marker_path,
        json.dumps(marker, indent=2).encode("utf-8"),
        content_type="application/json",
    )
    print(f"[MARK] wrote {marker_path} for {owner}/{repo}@{ref}")


def rewrite_db_urls(db_json, commits_for_db):
    """
    Return a new DB JSON where:
    - base_files_url and any raw.githubusercontent.com URLs pointing to
      known (owner,repo,ref) are rewritten to your mirror.
    """

    def rewrite_url(url):
        if not url:
            return url
        parsed = parse_raw_github_base(url)
        if not parsed:
            return url
        owner, repo, ref = parsed
        if (owner, repo, ref) not in commits_for_db:
            return url
        # Build mirror prefix; keep the relative path after /ref/
        p = urlparse(url)
        parts = [x for x in p.path.split("/") if x]
        # parts[0]=owner, [1]=repo, [2]=ref
        rel_parts = parts[3:]  # after ref
        rel_path = "/".join(rel_parts)
        return f"{MIRROR_BASE_URL}/{owner}/{repo}/{ref}/{rel_path}"

    new_db = json.loads(json.dumps(db_json))  # deep copy

    # base_files_url: keep trailing slash structure
    bf = new_db.get("base_files_url")
    if bf:
        parsed = parse_raw_github_base(bf)
        if parsed:
            owner, repo, ref = parsed
            new_db["base_files_url"] = f"{MIRROR_BASE_URL}/{owner}/{repo}/{ref}/"

    # linux
    if "linux" in new_db:
        new_db["linux"] = rewrite_url(new_db["linux"])

    # zips
    for zip_entry in new_db.get("zips", []):
        if not isinstance(zip_entry, dict):
            continue
        if "summary_file" in zip_entry:
            zip_entry["summary_file"] = rewrite_url(zip_entry["summary_file"])
        if "contents_file" in zip_entry:
            zip_entry["contents_file"] = rewrite_url(zip_entry["contents_file"])

    # files: handle both list-of-dicts and dict-of-filenames variants
    files_val = new_db.get("files")

    # Case 1: some DBs use a list of objects like {"url": "...", ...}
    if isinstance(files_val, list):
        for f in files_val:
            if isinstance(f, dict) and "url" in f:
                f["url"] = rewrite_url(f["url"])

    # Case 2: Distribution_MiSTer style:
    #   "files": { "path/filename": { "hash": ..., "size": ..., "tags": [...] }, ... }
    # No direct URLs here; they’re resolved via base_files_url, which we already rewrite.
    elif isinstance(files_val, dict):
        # Some DBs (e.g. update_all_mister) use:
        #   "files": { "path/filename": { ..., "url": "https://raw.githubusercontent.com/..." }, ... }
        # Rewrite any embedded URLs we find.
        for _, meta in files_val.items():
            if isinstance(meta, dict) and "url" in meta:
                meta["url"] = rewrite_url(meta["url"])

    return new_db


def bunny_db_mirror_path_for_db_url(db_url):
    """
    Map an original db_url to a path in Bunny Storage.

    GitHub raw URLs:
      https://raw.githubusercontent.com/MiSTer-devel/Distribution_MiSTer/main/db.json.zip
    -> MiSTer-devel/Distribution_MiSTer/main/db.json.zip

    Other hosts (e.g. Aitor's):
      https://www.aitorgomez.net/static/mistermain/db.json.zip
    -> www.aitorgomez.net/static/mistermain/db.json.zip
    """
    p = urlparse(db_url)
    parts = [x for x in p.path.split("/") if x]

    # GitHub raw case: mirror the repo structure
    if "raw.githubusercontent.com" in p.netloc:
        if len(parts) < 4:
            raise ValueError(f"Unexpected db_url path: {db_url}")
        owner, repo, branch = parts[0], parts[1], parts[2]
        rel_path = PurePosixPath(*parts[3:])
        return str(PurePosixPath(owner) / repo / branch / rel_path)

    # Generic fallback: host + full path
    host = p.netloc
    return str(PurePosixPath(host, *parts))


def prune_old_commits(owner, repo, keep=3):
    """
    Look under /owner/repo/ and delete commit directories older than `keep`.
    We treat each directory at that level as a ref/commit name.

    Uses Bunny's LastChanged field so we keep the most recently touched refs.
    """
    base_path = PurePosixPath(owner) / repo
    entries = list_bunny_directory(base_path)
    if not entries:
        print(f"[PRUNE] No entries under {base_path}, nothing to prune.")
        return

    # Collect (full_path, ref, last_changed) for directory entries
    dirs = []
    for e in entries:
        if not e.get("IsDirectory"):
            continue

        name = e.get("ObjectName", "")
        # Expect something like "MiSTer-devel/Distribution_MiSTer/<ref>/"
        parts = [x for x in name.split("/") if x]
        if len(parts) != 3:
            continue

        ref = parts[2]
        # Only prune real git commit SHAs. Keep branch-ish directories like main/master/db.
        if not re.fullmatch(r"[0-9a-f]{40}", ref):
            continue

        last_changed = e.get("LastChanged") or ""
        dirs.append((name, ref, last_changed))

    if len(dirs) <= keep:
        print(f"[PRUNE] {len(dirs)} refs under {base_path}, <= keep={keep}; nothing to prune.")
        return

    # Sort newest first by LastChanged (ISO 8601 sorts lexicographically ok)
    dirs_sorted = sorted(dirs, key=lambda x: x[2], reverse=True)

    # Keep the newest `keep`, prune the rest
    to_keep = dirs_sorted[:keep]
    to_delete = dirs_sorted[keep:]

    print(
        f"[PRUNE] {len(dirs)} refs under {base_path}; "
        f"keeping {len(to_keep)}, deleting {len(to_delete)} (keep={keep})"
    )

    for full_name, ref, last_changed in to_delete:
        print(f"[PRUNE] Deleting old ref {ref} (LastChanged={last_changed}) at {full_name}")
        delete_bunny_path(full_name)


def main():
    print(f"Using Bunny host: {BUNNY_STORAGE_HOST}")
    print(f"Using Bunny zone: {BUNNY_STORAGE_ZONE}")

    upstream = load_upstream_databases_module()

    # Discover all DB entries from upstream
    all_entries = [name for name, _ in iter_all_db_entries(upstream)]
    print("AllDBs entries:", all_entries)

    # Build a filter that targets any DB whose name looks like Distribution_MiSTer
    #db_filter = {n.lower() for n in all_entries if "distribution" in n.lower()}
    #print("Using db_filter:", db_filter)
    # For tighter testing, you could temporarily do:
    # db_filter = {"distribution_mister"}

    # No filter: process *all* DBs from AllDBs
    db_filter = None
    print("Using db_filter:", db_filter)
    # For tighter testing, you could temporarily do:
    # db_filter = {"distribution_mister"}


    for name, db in iter_all_db_entries(upstream):
        if db_filter and name.lower() not in db_filter:
            continue

        db_url = db.db_url
        print(f"\n=== Processing DB {name}: {db_url} ===")
        try:
            db_json, original_bytes, is_zipped = download_db_json(db_url)
        except Exception as e:
            print(f"Failed to download DB for {name}: {e}")
            continue

        commits = collect_commits_from_db(db_json)

        # Upload the DB entrypoint regardless. Some DBs don't reference raw GitHub commits
        # (e.g. Names DBs), or they reference non-raw URLs (e.g. archive.org, GitHub releases).
        # In those cases we still want the DB file to exist on the mirror, even if we can't
        # mirror the referenced payloads.
        dest_path = bunny_db_mirror_path_for_db_url(db_url)

        if not commits:
            print(f"No commits discovered for {name}; uploading DB file as-is (no URL rewrite, no repo mirroring).")
            http_put_to_bunny(dest_path, original_bytes, content_type="application/octet-stream")
            continue

        print(f"Commits to mirror for {name}: {commits}")

        # Mirror all commits for this DB
        for (owner, repo, ref) in commits:
            mirror_repo_commit(owner, repo, ref)
            prune_old_commits(owner, repo, keep=3)

        # Mirror any non-raw payload URLs referenced by this DB (GitHub release assets, etc.)
        external_urls = collect_external_assets_from_db(db_json)
        for u in sorted(external_urls):
            mirror_external_url(u)

        # Rewrite DB to point at the mirror
        new_db_json = rewrite_db_urls(db_json, commits)

        # Serialize & zip if the original was zipped
        if is_zipped:
            buf = io.BytesIO()
            with zipfile.ZipFile(
                buf, mode="w", compression=zipfile.ZIP_DEFLATED
            ) as zf:
                zf.writestr("db.json", json.dumps(new_db_json, separators=(",", ":")))
            new_bytes = buf.getvalue()
            filename = "db.json.zip"
        else:
            new_bytes = json.dumps(new_db_json, indent=2).encode("utf-8")
            filename = "db.json"

        # Upload mirrored DB to Bunny under a stable layout
        http_put_to_bunny(dest_path, new_bytes, content_type="application/octet-stream")

        # Also upload a small metadata file for debugging
        meta = {
            "name": name,
            "source_db_url": db_url,
            "mirrored_commits": sorted(
                {f"{o}/{r}/{ref}" for (o, r, ref) in commits}
            ),
        }
        meta_path = str(PurePosixPath(dest_path).with_suffix(".meta.json"))
        http_put_to_bunny(
            meta_path,
            json.dumps(meta, indent=2).encode("utf-8"),
            content_type="application/json",
        )


if __name__ == "__main__":
    main()
