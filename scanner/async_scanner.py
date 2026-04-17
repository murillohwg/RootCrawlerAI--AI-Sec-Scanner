import aiohttp
import asyncio


async def fetch(session, url):
    try:
        async with session.get(url, timeout=5) as response:
            text = await response.text()

            return {
                "url": url,
                "status_code": response.status,
                "length": len(text),
                "headers": dict(response.headers)
            }
    except:
        return None


async def run_scan(base_url, wordlist, threads):
    connector = aiohttp.TCPConnector(limit=threads)

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []

        for word in wordlist:
            url = f"{base_url}/{word}"
            print(f"[*] Testing: {url}")
            tasks.append(fetch(session, url))

        responses = await asyncio.gather(*tasks)

    return [r for r in responses if r]


def scan_async(base_url, wordlist, threads=10):
    return asyncio.run(run_scan(base_url, wordlist, threads))
