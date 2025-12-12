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

import requests

UPSTREAM_DATABASES_URL = (
    "https://raw.githubusercontent.com/theypsilon/Update_All_MiSTer/"
    "master/src/update_all/databases.py"
)

GITHUB_ZIPBALL_TEMPLATE = "https://api.github.com/repos/{owner}/{repo}/zipball/{ref}"

BUNNY_STORAGE_ZONE = os.environ["BUNNY_STORAGE_ZONE"]
BUNNY_ACCESS_KEY = os.environ["BUNNY_ACCESS_KEY"]
MIRROR_BASE_URL = os.environ["MIRROR_BASE_URL"].rstrip("/")


def http_get(url, **kwargs):
    print(f"[GET] {url}")
    r = requests.get(url, timeout=60, **kwargs)
    r.raise_for_status()
    return r


def http_put_to_bunny(path, data, content_type="application/octet-stream"):
    """
    Upload a single file to Bunny Storage at /<zone>/<path>.
    """
    path = str(PurePosixPath(path))
    url = f"https://storage.bunnycdn.com/{BUNNY_STORAGE_ZONE}/{path}"
    print(f"[PUT] {url}")
    headers = {
        "AccessKey": BUNNY_ACCESS_KEY,
        "Content-Type": content_type,
    }
    r = requests.put(url, headers=headers, data=data, timeout=120)
    r.raise_for_status()


def list_bunny_directory(path):
    """
    List files in a Bunny Storage directory, returns JSON (list of objects with 'ObjectName', etc.)
    """
    dir_path = str(PurePosixPath(path))
    url = f"https://storage.bunnycdn.com/{BUNNY_STORAGE_ZONE}/{dir_path}"
    print(f"[LIST] {url}")
    headers = {"AccessKey": BUNNY_ACCESS_KEY}
    r = requests.get(url, headers=headers, timeout=60)
    if r.status_code == 404:
        return []
    r.raise_for_status()
    try:
        return r.json()
    except Exception:
        return []


def delete_bunny_path(path):
    url = f"https://storage.bunnycdn.com/{BUNNY_STORAGE_ZONE}/{path}"
    print(f"[DELETE] {url}")
    headers = {"AccessKey": BUNNY_ACCESS_KEY}
    r = requests.delete(url, headers=headers, timeout=60)
    if r.status_code not in (200, 204, 404):
        r.raise_for_status()


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
        # Basic duck-typing: must have db_url
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
    return (owner, repo, ref)
    """
    if not url:
        return None

    p = urlparse(url)
    if "raw.githubusercontent.com" not in p.netloc:
        return None

    parts = [x for x in p.path.split("/") if x]
    if len(parts) < 3:
        return None

    owner, repo, ref = parts[0], parts[1], parts[2]
    return owner, repo, ref


def collect_commits_from_db(db_json):
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
        for key in ("summary_file", "contents_file"):
            url = zip_entry.get(key)
            parsed = parse_raw_github_base(url) if url else None
            if parsed:
                commits.add(parsed)

    # 4. If no base_files_url, infer from first file url
    if not commits:
        files = db_json.get("files", [])
        if files:
            first = files[0]
            url = first.get("url") or first.get("file") or ""
            parsed = parse_raw_github_base(url)
            if parsed:
                commits.add(parsed)

    return commits


def mirror_repo_commit(owner, repo, ref):
    """
    Download the zipball of (owner, repo, ref), unpack, upload to Bunny under:
    /owner/repo/ref/<files...>
    """
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
            dest_path = PurePosixPath(owner) / repo / ref / rel_path
            http_put_to_bunny(dest_path, data)


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
        if "summary_file" in zip_entry:
            zip_entry["summary_file"] = rewrite_url(zip_entry["summary_file"])
        if "contents_file" in zip_entry:
            zip_entry["contents_file"] = rewrite_url(zip_entry["contents_file"])

    # files[*].url
    for f in new_db.get("files", []):
        if "url" in f:
            f["url"] = rewrite_url(f["url"])

    return new_db


def bunny_db_mirror_path_for_db_url(db_url):
    """
    For a db_url like:
    https://raw.githubusercontent.com/MiSTer-devel/Distribution_MiSTer/main/db.json.zip
    return a mirror path like:
    MiSTer-devel/Distribution_MiSTer/main/db.json.zip
    """
    p = urlparse(db_url)
    if "raw.githubusercontent.com" not in p.netloc:
        # you could choose to ignore or special-case other hosts later
        raise ValueError(f"Unsupported db_url host: {db_url}")

    parts = [x for x in p.path.split("/") if x]
    if len(parts) < 4:
        raise ValueError(f"Unexpected db_url path: {db_url}")
    owner, repo, branch = parts[0], parts[1], parts[2]
    filename = parts[-1]
    return str(PurePosixPath(owner) / repo / branch / filename)


def prune_old_commits(owner, repo, keep=3):
    """
    Look under /owner/repo/ and delete commit directories older than `keep`.
    We treat each entry at that level as a ref/commit name.
    """
    base_path = f"{owner}/{repo}"
    entries = list_bunny_directory(base_path)
    # entries is a list of dictionaries; "ObjectName" includes the full path
    refs = []
    for e in entries:
        name = e.get("ObjectName", "")
        # For folders, Bunny returns "owner/repo/ref/"
        parts = [x for x in name.split("/") if x]
        if len(parts) == 3:
            refs.append(parts[2])

    # Very naive "oldest first": sort alphabetically
    refs = sorted(refs)
    if len(refs) <= keep:
        return

    to_delete = refs[0 : len(refs) - keep]
    for ref in to_delete:
        delete_bunny_path(f"{owner}/{repo}/{ref}/")


def main():
    upstream = load_upstream_databases_module()
    
    # Discover all DB entries from upstream
    all_entries = [name for name, _ in iter_all_db_entries(upstream)]
    print("AllDBs entries:", all_entries)

    # Build a filter that targets any DB whose name looks like Distribution_MiSTer
    db_filter = {n.lower() for n in all_entries if "distribution" in n.lower()}
    print("Using db_filter:", db_filter)

    # For initial testing, you *might* want to restrict to just Distribution_MiSTer:
    # db_filter = {"distribution_mister"}
    #db_filter = None  # or a set of names in AllDBs.*
    #db_filter = {"distribution_mister"}

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
        if not commits:
            print(f"No commits discovered for {name}, skipping mirror.")
            continue

        print(f"Commits to mirror for {name}: {commits}")

        # Mirror all commits for this DB
        for (owner, repo, ref) in commits:
            mirror_repo_commit(owner, repo, ref)
            prune_old_commits(owner, repo, keep=3)

        # Rewrite DB to point at the mirror
        new_db_json = rewrite_db_urls(db_json, commits)

        # Serialize & zip if the original was zipped
        if is_zipped:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("db.json", json.dumps(new_db_json, separators=(",", ":")))
            new_bytes = buf.getvalue()
            filename = "db.json.zip"
        else:
            new_bytes = json.dumps(new_db_json, indent=2).encode("utf-8")
            filename = "db.json"

        # Upload mirrored DB to Bunny under mirror-1-like layout
        dest_path = bunny_db_mirror_path_for_db_url(db_url)
        http_put_to_bunny(dest_path, new_bytes, content_type="application/octet-stream")

        # Optional: also upload a small metadata file for debugging
        meta = {
            "name": name,
            "source_db_url": db_url,
            "mirrored_commits": list(sorted({f"{o}/{r}/{ref}" for (o, r, ref) in commits})),
        }
        meta_path = str(PurePosixPath(dest_path).with_suffix(".meta.json"))
        http_put_to_bunny(meta_path, json.dumps(meta, indent=2).encode("utf-8"),
                          content_type="application/json")


if __name__ == "__main__":
    main()

