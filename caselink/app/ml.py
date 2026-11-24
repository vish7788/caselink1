"""Domain-name phishing classifier (character n-grams + a few lexical features).

It looks at the registered domain only (for example 'sbi-kyc-update.top'), never at the path, so it
does not learn the shortcut 'has a long URL path means phishing'. It supplements the rules; it does not replace them.
"""
import math
import re
from functools import lru_cache
from pathlib import Path

MODEL_DIR = Path(__file__).parent / "model"
MODEL_FILE = MODEL_DIR / "url_model.joblib"
SUSPICIOUS_TLDS = {"xyz", "top", "click", "icu", "shop", "live", "vip", "cc", "buzz", "cfd", "sbs", "work", "loan", "rest", "monster"}
BRAND_TOKENS = ("sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "npci", "amazon", "flipkart", "irctc", "incometax", "uidai", "epfo", "indiapost")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s))


def numeric_features(domain: str) -> list:
    label = domain.rsplit(".", 1)[0] if "." in domain else domain
    tld = domain.rsplit(".", 1)[-1]
    digits = sum(c.isdigit() for c in label)
    longest_digits = max((len(m) for m in re.findall(r"\d+", label)), default=0)
    vowels = sum(c in "aeiou" for c in label)
    n = max(1, len(label))
    return [len(label), label.count("-"), digits, digits / n, _entropy(label), longest_digits, vowels / n,
            float(tld in SUSPICIOUS_TLDS), len(tld), float("xn--" in domain),
            float(any(b in label for b in BRAND_TOKENS)), max((len(p) for p in label.split("-")), default=0), label.count(".")]


def featurize(model: dict, domains: list):
    from scipy.sparse import csr_matrix, hstack
    return hstack([model["vec"].transform([f"^{d}$" for d in domains]),
                   csr_matrix(model["scaler"].transform([numeric_features(d) for d in domains]))]).tocsr()


@lru_cache(maxsize=1)
def load_model():
    try:
        import joblib
        return joblib.load(MODEL_FILE)
    except Exception:
        return None


def phishing_probability(domain: str):
    """Probability in [0, 1] that the registered domain looks like a phishing domain, or None if no model is installed."""
    m = load_model()
    if not m or not domain:
        return None
    return float(m["clf"].predict_proba(featurize(m, [domain]))[0, 1])
