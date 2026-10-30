import os
import sys
import urllib.request
import argparse

PANDOC_FILES = {
    ("linux", "amd64"): "pandoc-linux-amd64.zip",
    ("linux", "arm64"): "pandoc-linux-arm64.zip",
    ("darwin", "amd64"): "pandoc-darwin-amd64.zip",
    ("darwin", "arm64"): "pandoc-darwin-arm64.zip",
    ("windows", "amd64"): "pandoc-windows-amd64.zip",
}

def download_file(url, target_path):
    print(f"Downloading {url} -> {target_path} ...")
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as resp, open(target_path, "wb") as f:
        while True:
            chunk = resp.read(1024 * 1024)
            if not chunk:
                break
            f.write(chunk)
    print(f"Done: {target_path} ({os.path.getsize(target_path)} bytes)")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--goos", default="")
    parser.add_argument("--goarch", default="")
    args, _ = parser.parse_known_args()

    app_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app", "pandoc"))
    os.makedirs(app_dir, exist_ok=True)

    targets = []
    if args.goos and args.goarch:
        fn = PANDOC_FILES.get((args.goos, args.goarch))
        if fn:
            targets.append(fn)

    if not targets:
        targets = list(PANDOC_FILES.values())

    base_url = "https://raw.githubusercontent.com/siyuan-note/siyuan/dev/app/pandoc"
    for fn in targets:
        target_path = os.path.join(app_dir, fn)
        if not os.path.exists(target_path) or os.path.getsize(target_path) == 0:
            url = f"{base_url}/{fn}"
            try:
                download_file(url, target_path)
            except Exception as e:
                print(f"Failed to download {url}: {e}")
                # Fallback to github.com/raw
                fb_url = f"https://github.com/siyuan-note/siyuan/raw/dev/app/pandoc/{fn}"
                download_file(fb_url, target_path)

if __name__ == "__main__":
    main()
