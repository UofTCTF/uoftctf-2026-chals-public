import urllib.request
from collections import Counter

# (answer, first-row emojis)
GAMES = [
    ("REBUT", "⬛⬛🟨⬛🟨"),
    ("CRASS", "🟨⬛⬛⬛⬛"),
    ("DITTY", "⬛⬛⬛🟨⬛"),
]

WORDLIST_URL = "https://raw.githubusercontent.com/tabatkins/wordle-list/main/words"

def yellow_mask_from_emojis(row: str) -> int:
    # bit i = 1 if position i is yellow
    mask = 0
    for i, ch in enumerate(row.strip()):
        if ch == "🟨":
            mask |= (1 << i)
    return mask

def yellow_mask(guess: str, answer: str) -> int:
    guess = guess.lower()
    answer = answer.lower()

    # First remove greens so they don't count toward yellows
    remaining = Counter(answer)
    green = [False]*5
    for i in range(5):
        if guess[i] == answer[i]:
            green[i] = True
            remaining[guess[i]] -= 1

    # Now mark yellows using remaining letter counts
    mask = 0
    for i in range(5):
        if green[i]:
            continue
        c = guess[i]
        if remaining[c] > 0:
            mask |= (1 << i)
            remaining[c] -= 1
    return mask

def load_words() -> list[str]:
    with urllib.request.urlopen(WORDLIST_URL) as r:
        data = r.read().decode("utf-8", errors="replace")
    return [w.strip().lower() for w in data.split() if len(w.strip()) == 5 and w.strip().isalpha()]

def main():
    targets = [(ans.lower(), yellow_mask_from_emojis(row)) for ans, row in GAMES]
    words = load_words()

    out = []
    for w in words:
        if all(yellow_mask(w, ans) == tgt for ans, tgt in targets):
            out.append(w)

    print(f"{len(out)} candidates:")
    print("\n".join(out))

if __name__ == "__main__":
    main()
