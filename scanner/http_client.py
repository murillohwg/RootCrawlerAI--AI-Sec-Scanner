import requests

def make_request(url, method="GET", data=None, headers=None, timeout=5):
    try:
        if method == "GET":
            response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=False)
        elif method == "POST":
            response = requests.post(url, data=data, headers=headers, timeout=timeout, allow_redirects=False)
        else:
            return None
        return {
            "url": url,
            "method": method,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text[:1000],
            "length": len(response.text)
        }
    except requests.exceptions.RequestException as e:
        return {
            "url": url,
            "method": method,
            "error": str(e)
        }
