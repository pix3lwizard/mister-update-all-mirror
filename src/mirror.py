# src/mirror.py
"""
Stellar mirror for Update_All_MiSTer -> Bunny Storage.

Key improvements vs naive per-file PUT loop:
- Extract zipball to disk and upload with a thread pool (fast for many tiny files)
- Reuse HTTP connections via per-thread requests.Session (keep-alive + pooling)
- Throttled logging (avoids Actions log bottlenecks)
- Marker file prevents re-mirroring the same commit
- Safer marker behavior: only written when uploads succeed (skips 400s)
- Keeps DB URL paths intact (fixes /db/, /releases/ path drops)

This script mirrors *GitHub repo commits* referenced by theypsilon's databases.py
and publishes mirrored DB entrypoints that point to MIRROR_BASE_URL.

Env vars (core):
  BUNNY_STORAGE_ZONE (required)
  BUNNY_ACCESS_KEY   (required)
  BUNNY_STORAGE_HOST (optional, e.g. la.storage.bunnycdn.com)
  MIRROR_BASE_URL    (required, e.g. https://uam-mirror.mysticalrealm.org)
  GITHUB_TOKEN       (optional but strongly recommended)

Env vars (performance):
  UPLOAD_WORKERS      (default 32)
  UPLOAD_IN_FLIGHT    (default workers*8)
  UPLOAD_LOG_EVERY    (default 500)
  VERBOSE_HTTP        (default 0)

Env vars (selection):
  SKIP_DISTRIBUTION_MISTER_FORKS (default 1)
  SKIP_ALLDBS_ATTRS  (default "", comma-separated)
  KEEP_COMMITS       (default 3)

Env vars (optional; implemented but default OFF):
  MIRROR_GITHUB_RELEASE_ASSETS (default 0)
  MIRROR_ARCHIVE_ORG          (default 0)  # recommended OFF unless you have rights
"""
from __future__ import annotations

import io
import json
import os
import re
import time
import zipfile
import sys
import types
import threading
import tempfile
import importlib.util
from datetime import datetime
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ----------------------------
# Config
# ----------------------------
BUNNY_STORAGE_ZONE = os.environ["BUNNY_STORAGE_ZONE"]
BUNNY_ACCESS_KEY = os.environ["BUNNY_ACCESS_KEY"]
BUNNY_STORAGE_HOST = os.environ.get("BUNNY_STORAGE_HOST", "storage.bunnycdn.com")
MIRROR_BASE_URL = os.environ["MIRROR_BASE_URL"].rstrip("/")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()

UPLOAD_WORKERS = int(os.environ.get("UPLOAD_WORKERS", "32"))
UPLOAD_IN_FLIGHT = int(os.environ.get("UPLOAD_IN_FLIGHT", str(max(UPLOAD_WORKERS * 8, 128))))
UPLOAD_LOG_EVERY = int(os.environ.get("UPLOAD_LOG_EVERY", "500"))
VERBOSE_HTTP = os.environ.get("VERBOSE_HTTP", "0") == "1"

KEEP_COMMITS = int(os.environ.get("KEEP_COMMITS", "3"))

# Optional skipping for big/slow DBs (useful for early testing)
SKIP_DISTRIBUTION_MISTER_FORKS = os.environ.get("SKIP_DISTRIBUTION_MISTER_FORKS", "1") == "1"
SKIP_ALLDBS_ATTRS = {x.strip() for x in os.environ.get("SKIP_ALLDBS_ATTRS", "").split(",") if x.strip()}

# These two Distribution MiSTer forks are the heavy hitters José suggested skipping for now:
_DISTRIBUTION_FORK_ATTRS = {
    "MISTER_DB9_DISTRIBUTION_MISTER",
    "MISTER_AITORGOMEZ_DISTRIBUTION_MISTER",
}

MIRROR_GITHUB_RELEASE_ASSETS = os.environ.get("MIRROR_GITHUB_RELEASE_ASSETS", "0") == "1"
MIRROR_ARCHIVE_ORG = os.environ.get("MIRROR_ARCHIVE_ORG", "0") == "1"

UPSTREAM_DATABASES_URL = (
    "https://raw.githubusercontent.com/theypsilon/Update_All_MiSTer/"
    "master/src/update_all/databases.py"
)

GITHUB_ZIPBALL_TEMPLATE = "https://api.github.com/repos/{owner}/{repo}/zipball/{ref}"


# ----------------------------
# HTTP sessions (fast + pooled)
# ----------------------------
_thread_local = threading.local()

def _build_session() -> requests.Session:
    s = requests.Session()
    retries = Retry(
        total=6,
        connect=6,
        read=6,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "HEAD", "PUT", "DELETE"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(
        max_retries=retries,
        pool_connections=max(UPLOAD_WORKERS * 2, 64),
        pool_maxsize=max(UPLOAD_WORKERS * 2, 64),
    )
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s

def session() -> requests.Session:
    s = getattr(_thread_local, "session", None)
    if s is None:
        s = _build_session()
        _thread_local.session = s
    return s


def _log(msg: str) -> None:
    print(msg, flush=True)


# ----------------------------
# Bunny Storage helpers
# ----------------------------
def _bunny_url(dest_path: str | PurePosixPath) -> str:
    # IMPORTANT: URL-encode object path so spaces/# and other characters are valid in HTTP requests.
    # Keep "/" unescaped so directory structure remains intact.
    dest = quote(str(dest_path).lstrip("/"), safe="/")
    return f"https://{BUNNY_STORAGE_HOST}/{BUNNY_STORAGE_ZONE}/{dest}"

def bunny_object_exists(path: str | PurePosixPath) -> bool:
    url = _bunny_url(path)
    headers = {"AccessKey": BUNNY_ACCESS_KEY}

    # Try HEAD first (fast when it works)
    try:
        resp = session().head(url, headers=headers, timeout=30)
        if resp.status_code == 404:
            return False
        if resp.status_code in (200, 204):
            return True
        # If HEAD is denied/unsupported, fall through to Range-GET probe
    except Exception:
        pass

    # Fallback: tiny Range GET (works like “does it exist?” without downloading the file)
    try:
        resp2 = session().get(
            url,
            headers={**headers, "Range": "bytes=0-0"},
            stream=True,
            timeout=30,
        )
        if resp2.status_code == 404:
            return False
        if resp2.status_code in (200, 206):
            return True
        resp2.raise_for_status()
        return True
    except Exception as e:
        _log(f"[WARN] Bunny probe failed for {url}; assuming not mirrored. {e}")
        return False
    finally:
        try:
            resp2.close()
        except Exception:
            pass

def list_bunny_directory(path: str | PurePosixPath) -> list[dict]:
    url = _bunny_url(PurePosixPath(path))
    headers = {"AccessKey": BUNNY_ACCESS_KEY}
    if VERBOSE_HTTP:
        _log(f"[LIST] {url}")
    resp = session().get(url, headers=headers, timeout=60)
    if resp.status_code == 404:
        return []
    resp.raise_for_status()
    try:
        return resp.json()
    except Exception:
        return []

def delete_bunny_path(path: str | PurePosixPath) -> None:
    url = _bunny_url(path)
    headers = {"AccessKey": BUNNY_ACCESS_KEY}
    if VERBOSE_HTTP:
        _log(f"[DELETE] {url}")
    resp = session().delete(url, headers=headers, timeout=60)
    if resp.status_code not in (200, 204, 404):
        resp.raise_for_status()

def put_bytes_to_bunny(dest_path: str | PurePosixPath, data: bytes, content_type: str | None = None) -> bool:
    url = _bunny_url(dest_path)
    headers = {"AccessKey": BUNNY_ACCESS_KEY}
    if content_type:
        headers["Content-Type"] = content_type

    if VERBOSE_HTTP:
        _log(f"[PUT] {url}")
    resp = session().put(url, data=data, headers=headers, timeout=180)
    if resp.status_code == 400:
        _log(f"[WARN] Bunny 400 for {url} (bad name?) skipping object.")
        return True
    if not resp.ok:
        msg = (resp.text or "")[:200]
        _log(f"[ERROR] Bunny PUT {resp.status_code} for {url}: {msg!r}")
        return False
    return True

def put_file_to_bunny(dest_path: str | PurePosixPath, file_path: Path, content_type: str | None = None) -> bool:
    url = _bunny_url(dest_path)
    headers = {"AccessKey": BUNNY_ACCESS_KEY}
    if content_type:
        headers["Content-Type"] = content_type

    if VERBOSE_HTTP:
        _log(f"[PUT] {url}")
    try:
        with file_path.open("rb") as f:
            resp = session().put(url, data=f, headers=headers, timeout=180)
    except requests.exceptions.RequestException as e:
        _log(f"[ERROR] PUT exception for {url}: {e!r}")
        return False

    if resp.status_code == 400:
        _log(f"[WARN] Bunny 400 for {url} (bad name?) skipping object.")
        return True
    if not resp.ok:
        msg = (resp.text or "")[:200]
        _log(f"[ERROR] Bunny PUT {resp.status_code} for {url}: {msg!r}")
        return False
    return True


# ----------------------------
# Upstream loading & DB parsing
# ----------------------------
def http_get(url: str, headers: dict | None = None, stream: bool = False, timeout: int = 120) -> requests.Response:
    if VERBOSE_HTTP:
        _log(f"[GET] {url}")
    resp = session().get(url, headers=headers, stream=stream, timeout=timeout)
    resp.raise_for_status()
    return resp

def load_upstream_databases_module():
    resp = http_get(UPSTREAM_DATABASES_URL)
    source = resp.text

    name = "upstream_databases"
    spec = importlib.util.spec_from_loader(name, loader=None)
    mod = types.ModuleType(name)
    mod.__spec__ = spec
    mod.__file__ = UPSTREAM_DATABASES_URL

    sys.modules[name] = mod          # IMPORTANT: register before exec
    exec(source, mod.__dict__)

    return mod

def iter_all_db_entries(upstream_mod):
    all_dbs_cls = upstream_mod.AllDBs
    for attr in dir(all_dbs_cls):
        if attr.startswith("_"):
            continue
        if attr in SKIP_ALLDBS_ATTRS:
            _log(f"[SKIP] AllDBs.{attr} disabled via SKIP_ALLDBS_ATTRS")
            continue
        if SKIP_DISTRIBUTION_MISTER_FORKS and attr in _DISTRIBUTION_FORK_ATTRS:
            _log(f"[SKIP] AllDBs.{attr} (distribution_mister fork) disabled")
            continue
        db = getattr(all_dbs_cls, attr)
        if hasattr(db, "db_url"):
            yield attr, db

def download_db_json(db_url: str):
    resp = http_get(db_url, timeout=180)
    original_bytes = resp.content
    is_zipped = db_url.endswith(".zip")
    if is_zipped:
        with zipfile.ZipFile(io.BytesIO(original_bytes)) as zf:
            # Most DB zips contain db.json, but some forks use a different inner name (e.g. dbencc.json).
            names = [n for n in zf.namelist() if n and not n.endswith("/") and n.lower().endswith(".json")]
            if not names:
                raise RuntimeError(f"No .json found inside {db_url}")

            # Prefer any path ending in /db.json (or db.json at root).
            inner = next((n for n in names if n.replace("\\", "/").endswith("db.json")), None)

            # Otherwise prefer the name matching the zip basename (e.g. dbencc.json.zip -> dbencc.json).
            if inner is None:
                zip_base = Path(urlparse(db_url).path).name
                expected = zip_base[:-4] if zip_base.lower().endswith(".zip") else zip_base
                inner = next((n for n in names if n.replace("\\", "/").endswith(expected)), None)

            if inner is None:
                inner = sorted(names)[0]

            with zf.open(inner) as f:
                db_json = json.loads(f.read().decode("utf-8"))
    else:
        db_json = json.loads(original_bytes.decode("utf-8"))
    return db_json, original_bytes, is_zipped

_RAW_GH_RE = re.compile(r"^https?://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.*)$")

def parse_raw_github_base(url: str | None):
    if not url or not isinstance(url, str):
        return None
    m = _RAW_GH_RE.match(url)
    if not m:
        return None
    owner, repo, ref, rest = m.group(1), m.group(2), m.group(3), m.group(4)
    return owner, repo, ref

def _scan_for_urls(obj):
    """Yield URL strings found anywhere inside nested dict/list structures."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and (v.startswith("http://") or v.startswith("https://")):
                yield v
            else:
                yield from _scan_for_urls(v)
    elif isinstance(obj, list):
        for it in obj:
            yield from _scan_for_urls(it)

def collect_commits_from_db(db_json: dict) -> set[tuple[str, str, str]]:
    commits: set[tuple[str, str, str]] = set()

    # base_files_url
    parsed = parse_raw_github_base(db_json.get("base_files_url", ""))
    if parsed:
        commits.add(parsed)

    # linux (Distribution MiSTer)
    parsed = parse_raw_github_base(db_json.get("linux")) if db_json.get("linux") else None
    if parsed:
        commits.add(parsed)

    # zips optimization (Distribution MiSTer)
    for zip_entry in db_json.get("zips", []) or []:
        if not isinstance(zip_entry, dict):
            continue
        for key in ("summary_file", "contents_file"):
            parsed = parse_raw_github_base(zip_entry.get(key)) if zip_entry.get(key) else None
            if parsed:
                commits.add(parsed)

    # files list (common)
    files_list = db_json.get("files")
    if isinstance(files_list, list):
        for f in files_list:
            if isinstance(f, dict):
                url = f.get("url") or f.get("file")
                parsed = parse_raw_github_base(url) if url else None
                if parsed:
                    commits.add(parsed)
    # files dict-of-dicts (update_all_mister style)
    elif isinstance(files_list, dict):
        for v in files_list.values():
            if isinstance(v, dict):
                url = v.get("url") or v.get("file")
                parsed = parse_raw_github_base(url) if url else None
                if parsed:
                    commits.add(parsed)

    # last resort: scan everything for raw.githubusercontent URLs
    if not commits:
        for u in _scan_for_urls(db_json):
            parsed = parse_raw_github_base(u)
            if parsed:
                commits.add(parsed)

    return commits


# ----------------------------
# Mirroring repo commits (fast)
# ----------------------------
def mirror_repo_commit(owner: str, repo: str, ref: str) -> None:
    base_dir = PurePosixPath(owner) / repo / ref
    marker_path = base_dir / ".mirrored.json"

    if bunny_object_exists(marker_path):
        _log(f"[SKIP] {owner}/{repo}@{ref} already mirrored (marker present)")
        return

    zip_url = GITHUB_ZIPBALL_TEMPLATE.format(owner=owner, repo=repo, ref=ref)
    headers = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"

    _log(f"[ZIP] Downloading {owner}/{repo}@{ref} zipball ...")
    t0 = time.time()

    with tempfile.TemporaryDirectory(prefix="mister_mirror_") as tmp:
        tmp_path = Path(tmp)
        zip_path = tmp_path / "repo.zip"
        extract_path = tmp_path / "extract"
        extract_path.mkdir(parents=True, exist_ok=True)

        # Stream download to disk
        resp = http_get(zip_url, headers=headers, stream=True, timeout=300)
        with zip_path.open("wb") as f:
            for chunk in resp.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    f.write(chunk)

        # Extract
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(extract_path)

        # zipball has one top folder
        roots = [p for p in extract_path.iterdir() if p.is_dir()]
        if not roots:
            raise RuntimeError(f"Zipball for {owner}/{repo}@{ref} had no root folder?")
        root = roots[0]

        # Upload files in parallel
        total = 0
        ok = 0
        failed = 0
        futures = []

        def submit_upload(src_file: Path):
            rel = src_file.relative_to(root).as_posix()
            dest_path = base_dir / rel
            return executor.submit(put_file_to_bunny, dest_path, src_file)

        _log(f"[UPLOAD] Uploading files for {owner}/{repo}@{ref} with {UPLOAD_WORKERS} workers ...")
        with ThreadPoolExecutor(max_workers=UPLOAD_WORKERS) as executor:
            for dirpath, _, filenames in os.walk(root):
                for fn in filenames:
                    src = Path(dirpath) / fn
                    total += 1
                    futures.append(submit_upload(src))

                    # keep in-flight bounded
                    if len(futures) >= UPLOAD_IN_FLIGHT:
                        for fut in as_completed(futures):
                            if fut.result():
                                ok += 1
                            else:
                                failed += 1
                            if (ok + failed) % UPLOAD_LOG_EVERY == 0:
                                _log(f"[PROGRESS] {owner}/{repo}@{ref}: {ok}/{total} ok, {failed} failed")
                            # stop early drain after some completions
                            if len(futures) <= UPLOAD_WORKERS:
                                break
                        # remove done futures
                        futures = [f for f in futures if not f.done()]

            # Final drain
            for fut in as_completed(futures):
                if fut.result():
                    ok += 1
                else:
                    failed += 1
                if (ok + failed) % UPLOAD_LOG_EVERY == 0:
                    _log(f"[PROGRESS] {owner}/{repo}@{ref}: {ok}/{total} ok, {failed} failed")

        elapsed = time.time() - t0
        _log(f"[DONE] {owner}/{repo}@{ref}: total={total}, ok={ok}, failed={failed}, elapsed={elapsed:.1f}s")

        if failed > 0:
            _log(f"[WARN] {owner}/{repo}@{ref} had {failed} upload failures; NOT writing marker so next run retries.")
            return

        marker = {
            "owner": owner,
            "repo": repo,
            "ref": ref,
            "mirrored_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "total_files": total,
            "upload_seconds": round(elapsed, 3),
        }
        if not put_bytes_to_bunny(
            marker_path,
            json.dumps(marker, indent=2).encode("utf-8"),
            content_type="application/json",
        ):
            _log(f"[WARN] Failed to write marker for {owner}/{repo}@{ref}")
        else:
            _log(f"[MARK] wrote {marker_path} for {owner}/{repo}@{ref}")


# ----------------------------
# DB URL rewriting + placement
# ----------------------------
def _raw_prefix(owner: str, repo: str, ref: str) -> str:
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/"

def _mirror_prefix(owner: str, repo: str, ref: str) -> str:
    return f"{MIRROR_BASE_URL}/{owner}/{repo}/{ref}/"

def rewrite_db_urls(db_json: dict, commits: set[tuple[str, str, str]]) -> dict:
    # Build replacement table: raw -> mirror
    repl = {}
    for (o, r, ref) in commits:
        repl[_raw_prefix(o, r, ref)] = _mirror_prefix(o, r, ref)

    def rewrite_str(s: str) -> str:
        if not isinstance(s, str):
            return s
        for src, dst in repl.items():
            if s.startswith(src):
                return dst + s[len(src):]

        # Optional external payload rewriting (only if you also enabled mirroring them)
        if MIRROR_GITHUB_RELEASE_ASSETS:
            dest = _dest_for_github_release(s)
            if dest:
                return f"{MIRROR_BASE_URL}/{dest.as_posix()}"

        if MIRROR_ARCHIVE_ORG:
            dest = _dest_for_archive_org(s)
            if dest:
                return f"{MIRROR_BASE_URL}/{dest.as_posix()}"

        return s
        for src, dst in repl.items():
            if s.startswith(src):
                return dst + s[len(src):]
        # optional rewriting for github releases (keep hosted on github by default)
        if MIRROR_GITHUB_RELEASE_ASSETS and "https://github.com/" in s and "/releases/download/" in s:
            # Map to mirror under /owner/repo/releases/download/...
            p = urlparse(s)
            parts = [x for x in p.path.split("/") if x]
            if len(parts) >= 5 and parts[2] == "releases" and parts[3] == "download":
                owner, repo = parts[0], parts[1]
                return f"{MIRROR_BASE_URL}/{owner}/{repo}/" + "/".join(parts[2:])
        if MIRROR_ARCHIVE_ORG and "archive.org" in s:
            # Conservative placement
            p = urlparse(s)
            return f"{MIRROR_BASE_URL}/_ext/{p.netloc}" + p.path
        return s

    def walk(obj):
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                if isinstance(v, str):
                    out[k] = rewrite_str(v)
                else:
                    out[k] = walk(v)
            return out
        elif isinstance(obj, list):
            return [walk(x) for x in obj]
        else:
            return obj

    return walk(db_json)


# ----------------------------
# External payload mirroring (optional)
# ----------------------------
_GH_RELEASE_RE = re.compile(r"^https?://github\.com/([^/]+)/([^/]+)/releases/download/([^/]+)/(.+)$")

def _dest_for_github_release(url: str) -> PurePosixPath | None:
    m = _GH_RELEASE_RE.match(url)
    if not m:
        return None
    owner, repo, tag, filename = m.group(1), m.group(2), m.group(3), m.group(4)
    # normalize filename (strip query if any)
    filename = filename.split("?", 1)[0]
    return PurePosixPath(owner, repo, "releases", "download", tag, filename)

def _dest_for_archive_org(url: str) -> PurePosixPath | None:
    p = urlparse(url)
    if "archive.org" not in p.netloc:
        return None
    path = p.path.lstrip("/")
    if not path:
        return None
    return PurePosixPath("_ext", p.netloc, *path.split("/"))

def mirror_external_file(url: str, dest_path: PurePosixPath) -> None:
    if bunny_object_exists(dest_path):
        return

    _log(f"[EXT] Downloading {url}")
    with tempfile.TemporaryDirectory(prefix="mister_ext_") as tmp:
        tmp_path = Path(tmp) / "payload.bin"

        try:
            # follow redirects; stream to disk
            r = session().get(url, stream=True, timeout=600)
            status = r.status_code

            # Common external failures: don’t kill the run
            if status in (401, 403, 404, 410):
                _log(f"[WARN] External payload unavailable ({status}) for {url}; skipping.")
                return
            if 400 <= status < 500:
                _log(f"[WARN] External payload client error ({status}) for {url}; skipping.")
                return

            r.raise_for_status()

            with tmp_path.open("wb") as f:
                for chunk in r.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        f.write(chunk)

        except requests.exceptions.RequestException as e:
            _log(f"[WARN] External payload download failed for {url}; skipping. {e}")
            return
        finally:
            try:
                r.close()
            except Exception:
                pass

        if not put_file_to_bunny(dest_path, tmp_path):
            _log(f"[WARN] Failed to upload external payload to {dest_path}; skipping.")
            return

def mirror_external_payloads(db_json: dict) -> None:
    """
    If MIRROR_GITHUB_RELEASE_ASSETS / MIRROR_ARCHIVE_ORG are enabled, mirror any matching URLs
    referenced by this db_json.
    """
    if not (MIRROR_GITHUB_RELEASE_ASSETS or MIRROR_ARCHIVE_ORG):
        return

    release_urls = set()
    archive_urls = set()
    for u in _scan_for_urls(db_json):
        if MIRROR_GITHUB_RELEASE_ASSETS and _GH_RELEASE_RE.match(u):
            release_urls.add(u)
        if MIRROR_ARCHIVE_ORG and "archive.org" in u:
            archive_urls.add(u)

    # Release assets are usually few, but can be large.
    for u in sorted(release_urls):
        dest = _dest_for_github_release(u)
        if dest:
            mirror_external_file(u, dest)

    # Archive.org payloads can be enormous; use with care.
    for u in sorted(archive_urls):
        dest = _dest_for_archive_org(u)
        if dest:
            mirror_external_file(u, dest)

def bunny_db_mirror_path_for_db_url(db_url: str) -> str:
    """
    Preserve the full path after the branch/ref. (Fixes dropping /db/ etc.)
    raw.github: /owner/repo/branch/...
    """
    p = urlparse(db_url)
    parts = [x for x in p.path.split("/") if x]

    if "raw.githubusercontent.com" in p.netloc:
        if len(parts) < 4:
            raise ValueError(f"Unexpected db_url path: {db_url}")
        owner, repo, branch = parts[0], parts[1], parts[2]
        rest = parts[3:]
        return str(PurePosixPath(owner, repo, branch, *rest))

    # Generic fallback: host + full path
    return str(PurePosixPath(p.netloc, *parts))

def prune_old_commits(owner: str, repo: str, keep: int = KEEP_COMMITS) -> None:
    base_path = PurePosixPath(owner) / repo
    entries = list_bunny_directory(base_path)
    if not entries:
        return

    dirs = []
    for e in entries:
        if not e.get("IsDirectory"):
            continue
        name = e.get("ObjectName") or ""
        parts = [x for x in name.split("/") if x]
        if len(parts) != 3:
            continue
        ref = parts[2]
        last_changed = e.get("LastChanged") or ""
        dirs.append((name, ref, last_changed))

    if len(dirs) <= keep:
        return

    dirs_sorted = sorted(dirs, key=lambda x: x[2], reverse=True)
    to_delete = dirs_sorted[keep:]
    _log(f"[PRUNE] {owner}/{repo}: deleting {len(to_delete)} old refs (keep={keep})")

    for full_name, ref, last_changed in to_delete:
        _log(f"[PRUNE] Deleting {ref} (LastChanged={last_changed}) at {full_name}")
        delete_bunny_path(full_name)


# ----------------------------
# Main
# ----------------------------
def main():
    _log(f"Using Bunny host: {BUNNY_STORAGE_HOST}")
    _log(f"Using Bunny zone: {BUNNY_STORAGE_ZONE}")
    _log(f"Mirror base URL: {MIRROR_BASE_URL}")
    _log(f"Upload workers: {UPLOAD_WORKERS} (in-flight cap {UPLOAD_IN_FLIGHT})")

    upstream = load_upstream_databases_module()

    for name, db in iter_all_db_entries(upstream):
        db_url = db.db_url
        _log(f"\n=== Processing DB {name}: {db_url} ===")

        try:
            db_json, _, is_zipped = download_db_json(db_url)
        except Exception as e:
            _log(f"[ERROR] Failed to download DB for {name}: {e!r}")
            continue

        mirror_external_payloads(db_json)

        commits = collect_commits_from_db(db_json)
        _log(f"Commits discovered for {name}: {sorted({f'{o}/{r}/{ref}' for (o,r,ref) in commits})}")

        # Mirror all commits
        for (owner, repo, ref) in sorted(commits):
            mirror_repo_commit(owner, repo, ref)
            prune_old_commits(owner, repo, keep=KEEP_COMMITS)

        # Rewrite DB to point at mirror (even if commits empty, walk is safe)
        new_db_json = rewrite_db_urls(db_json, commits)

        # Serialize & zip if the original was zipped
        if is_zipped:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("db.json", json.dumps(new_db_json, separators=(",", ":")))
            new_bytes = buf.getvalue()
            content_type = "application/octet-stream"
        else:
            new_bytes = json.dumps(new_db_json, indent=2).encode("utf-8")
            content_type = "application/json"

        # Upload mirrored DB to Bunny under a stable layout
        dest_path = bunny_db_mirror_path_for_db_url(db_url)
        if not put_bytes_to_bunny(dest_path, new_bytes, content_type=content_type):
            _log(f"[ERROR] Failed to upload mirrored DB for {name} to {dest_path}")
            continue

        # Small metadata file for debugging
        meta = {
            "name": name,
            "source_db_url": db_url,
            "mirrored_commits": sorted({f"{o}/{r}/{ref}" for (o, r, ref) in commits}),
            "generated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        }
        meta_path = str(PurePosixPath(dest_path).with_suffix(".meta.json"))
        put_bytes_to_bunny(
            meta_path,
            json.dumps(meta, indent=2).encode("utf-8"),
            content_type="application/json",
        )

if __name__ == "__main__":
    main()
