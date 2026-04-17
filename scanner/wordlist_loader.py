def load_wordlist(path):
    with open(path, "r") as file:
        return [line.strip() for line in file if line.strip()]
