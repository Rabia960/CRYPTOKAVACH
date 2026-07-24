import re

# ── Regex patterns for each cryptocurrency ──────────────────────────────────
PATTERNS = {
    "BTC": [
        r'\b1[a-zA-HJ-NP-Z0-9]{25,34}\b',        # Legacy P2PKH
        r'\b3[a-zA-HJ-NP-Z0-9]{25,34}\b',        # P2SH
        r'\bbc1[a-zA-HJ-NP-Z0-9]{39,59}\b',      # Bech32
    ],
    "ETH":  [r'\b0x[a-fA-F0-9]{40}\b'],
    "XMR":  [r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'],
    "LTC":  [r'\b[LM][a-km-zA-HJ-NP-Z1-9]{26,33}\b'],
    "DOGE": [r'\bD[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}\b'],
    "USDT_TRC20": [r'\bT[A-Za-z1-9]{33}\b'],
    "XRP":  [r'\br[a-zA-HJ-NP-Z0-9]{24,34}\b'],
}

# ── Keywords for category inference ─────────────────────────────────────────
CATEGORY_KEYWORDS = {
    "drugs": [
        "narcotics", "cocaine", "heroin", "meth", "fentanyl",
        "darknet market", "drug", "cannabis", "weed", "vendor"
    ],
    "ransomware": [
        "ransomware", "decrypt", "ransom", "locked files",
        "pay to restore", "lockbit", "ryuk", "revil", "darkside"
    ],
    "terrorism": [
        "terror", "isis", "al-qaeda", "jihad",
        "weapon smuggling", "extremist", "financing terror"
    ],
    "fraud": [
        "phishing", "scam", "ponzi", "fake exchange",
        "investment fraud", "impersonation", "rug pull"
    ],
    "money_laundering": [
        "laundering", "mixer", "tumbler", "clean funds",
        "wash", "layering", "smurfing"
    ],
    "sanctions": [
        "ofac", "sanctioned", "north korea", "iran",
        "russia sdn", "sdn list", "blocked entity"
    ],
    "cybercrime": [
        "malware", "botnet", "exploit", "hacked",
        "stolen funds", "breach", "keylogger"
    ],
}

# ── Detect all crypto addresses in a block of text ──────────────────────────
def detect_addresses(text):
    """
    Returns a dict like:
    { "BTC": ["1abc...", "3xyz..."], "ETH": ["0x123..."] }
    """
    found = {}
    for coin, patterns in PATTERNS.items():
        matches = []
        for pattern in patterns:
            matches += re.findall(pattern, text)
        if matches:
            found[coin] = list(set(matches))
    return found


# ── Infer category from surrounding text ────────────────────────────────────
def infer_category(text):
    """
    Returns (category_string, confidence_float)
    e.g. ("drugs", 0.85)
    """
    text_lower = text.lower()
    scores = {}
    for cat, keywords in CATEGORY_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in text_lower)
        if score > 0:
            scores[cat] = score

    if not scores:
        return "uncategorized", 0.3

    best_cat = max(scores, key=scores.get)
    # Normalize confidence: max keywords matched out of total keywords
    total_kw = len(CATEGORY_KEYWORDS[best_cat])
    confidence = round(min(scores[best_cat] / total_kw, 1.0), 2)
    return best_cat, confidence


# ── Quick test ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    sample = """
    The ransomware group LockBit demanded payment to this address:
    bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
    and also to 3FZbgi29cpjq2GjdwV8eyHuJJnkLtktZc5
    ETH address: 0x742d35Cc6634C0532925a3b844Bc454e4438f44e
    """
    print("Addresses found:", detect_addresses(sample))
    print("Category:", infer_category(sample))
