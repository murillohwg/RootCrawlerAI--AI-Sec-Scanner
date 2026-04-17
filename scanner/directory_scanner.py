from concurrent.futures import ThreadPoolExecutor, as_completed
from scanner.http_client import make_request


def scan_directories(base_url, wordlist, threads=20):
    results = []

    def scan(word):
        url = f"{base_url}/{word}"

        print(f"[*] Testing: {url}")

        response = make_request(url)

        if not response or "error" in response:
            return None

        status = response["status_code"]

        if status not in (404, 0):
            print(f"[+] Found: {url} (Status: {status})")
            return response

        return None

    # THREAD POOL
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(scan, word) for word in wordlist]

        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    return results
