import requests
import time
from hasher import generate_hash_from_url, compare_hashes

HEADERS = {
    "User-Agent": "contenttrace-scanner/1.0"
}

SUBREDDITS = [
    "CricketControversial",
    "ipl",
    "IndiaCricket",
]

def scan_reddit(registered_hash, content_name=""):
    matches = []

    seen_urls = set()   # ✅ avoid duplicate processing in same scan

    for subreddit in SUBREDDITS:
        print(f"Scanning r/{subreddit}...")

        try:
            url = f"https://www.reddit.com/r/{subreddit}/new.json?limit=10"
            response = requests.get(url, headers=HEADERS, timeout=10)

            if response.status_code != 200:
                print(f"Could not reach r/{subreddit} — status {response.status_code}")
                continue

            posts = response.json()["data"]["children"]
            print(f"Found {len(posts)} posts in r/{subreddit}")

            for post in posts:
                data = post["data"]
                post_url = data.get("url", "")

                if post_url in seen_urls:
                    continue
                seen_urls.add(post_url)

                image_url = None

                if any(post_url.endswith(ext) for ext in [".jpg", ".jpeg", ".png", ".webp"]):
                    image_url = post_url
                elif "i.redd.it" in post_url or "i.imgur.com" in post_url:
                    image_url = post_url

                if not image_url:
                    continue

                # ✅ safer hashing
                try:
                    post_hash = generate_hash_from_url(image_url)
                except Exception:
                    continue

                if not post_hash:
                    continue

                distance, match_score = compare_hashes(registered_hash, post_hash)

                if distance <= 15:
                    matches.append({
                        "source_url": f"https://reddit.com{data['permalink']}",
                        "post_title": data.get("title", "Unknown"),
                        "subreddit": subreddit,
                        "match_score": match_score,
                        "detection_method": "Hash" if distance <= 8 else "ML-Assisted"
                    })

                    print(f"Match found in r/{subreddit} — score {match_score}%")

        except Exception as e:
            print(f"Error scanning r/{subreddit}: {e}")

        time.sleep(2)   # ✅ reduced delay (faster scan)

    return matches
