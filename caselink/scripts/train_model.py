"""Train the domain-name phishing classifier from public data.

Run from the project root:  python -m scripts.train_model

Phishing domains : random samples of the public Phishing.Database list (mitchellkrogza, GitHub).
Benign domains   : the public top-100k popular-domains list (zer0h/top-1000000-domains, GitHub).
Domains that appear in both are dropped, because they are mostly compromised legitimate sites.
"""
import json
import random
import subprocess
import time
from pathlib import Path

import joblib
import numpy as np
import sklearn
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_score, recall_score, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler

from app.extract import IP_RE, host_of, registered_domain
from app.ml import MODEL_DIR, MODEL_FILE, numeric_features

PHISH_URL = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt"
BENIGN_URL = "https://raw.githubusercontent.com/zer0h/top-1000000-domains/master/top-100000-domains"
PHISH_BYTES = 65_823_890  # size of the list when this was written; ranges past the end simply return less
RAW = Path("data/raw")
N_PER_CLASS = 20000


def curl(url, out, byte_range=None):
    cmd = ["curl", "-s", "-f", "-m", "60", "-o", str(out), url]
    if byte_range:
        cmd[1:1] = ["-r", byte_range]
    subprocess.run(cmd, check=True)


def phishing_domains(rng):
    RAW.mkdir(parents=True, exist_ok=True)
    domains = set()
    for i in range(60):  # spread samples over the whole file; the list is sorted, so the head alone would be biased
        start = rng.randrange(0, PHISH_BYTES - 120_000)
        f = RAW / f"phish_{i}.txt"
        if not f.exists():
            curl(PHISH_URL, f, f"{start}-{start + 120_000}")
        lines = f.read_text(errors="ignore").splitlines()[1:-1]  # drop the cut-off first and last lines
        for line in lines:
            if not line.lower().startswith(("http://", "https://")):
                continue
            host = host_of(line)
            if host and "." in host and not IP_RE.fullmatch(host):
                domains.add(registered_domain(host))
    return domains


def benign_domains():
    RAW.mkdir(parents=True, exist_ok=True)
    f = RAW / "benign.txt"
    if not f.exists():
        curl(BENIGN_URL, f)
    return [registered_domain(d.strip().lower()) for d in f.read_text().splitlines() if "." in d]


def main():
    rng = random.Random(7)
    t0 = time.time()
    benign_all = benign_domains()
    benign_set = set(benign_all)
    phish = sorted(d for d in phishing_domains(rng) if d not in benign_set)
    rng.shuffle(phish)
    benign = sorted(set(benign_all))
    rng.shuffle(benign)
    phish, benign = phish[:N_PER_CLASS], benign[:N_PER_CLASS]
    print(f"phishing domains: {len(phish)}, benign domains: {len(benign)}")

    domains = phish + benign
    y = np.array([1] * len(phish) + [0] * len(benign))
    idx = np.arange(len(domains))
    train_i, test_i = next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=7).split(idx, y, groups=domains))

    vec = TfidfVectorizer(analyzer="char", ngram_range=(3, 5), max_features=40000, sublinear_tf=True, dtype=np.float32)
    scaler = StandardScaler()
    tr = [domains[i] for i in train_i]
    X_tr = hstack([vec.fit_transform([f"^{d}$" for d in tr]), csr_matrix(scaler.fit_transform([numeric_features(d) for d in tr]))]).tocsr()
    clf = LogisticRegression(C=4.0, max_iter=2000, class_weight="balanced").fit(X_tr, y[train_i])
    model = {"vec": vec, "scaler": scaler, "clf": clf}

    from app.ml import featurize
    te = [domains[i] for i in test_i]
    p = clf.predict_proba(featurize(model, te))[:, 1]
    pred = (p >= 0.5).astype(int)
    metrics = {
        "trained_at": time.strftime("%Y-%m-%d", time.gmtime()), "sklearn": sklearn.__version__,
        "phishing_domains": len(phish), "benign_domains": len(benign), "holdout_size": len(te),
        "holdout_auc": round(float(roc_auc_score(y[test_i], p)), 4),
        "holdout_precision_at_0.5": round(float(precision_score(y[test_i], pred)), 4),
        "holdout_recall_at_0.5": round(float(recall_score(y[test_i], pred)), 4),
        "sources": {"phishing": PHISH_URL, "benign": BENIGN_URL},
        "caveat": "Benign set is popular sites, so the model separates 'unusual new-looking domains' from 'well-known domains'. Treat as a supporting signal.",
    }
    # refit on everything for the shipped model
    X_all = hstack([vec.fit_transform([f"^{d}$" for d in domains]), csr_matrix(scaler.fit_transform([numeric_features(d) for d in domains]))]).tocsr()
    model["clf"] = LogisticRegression(C=4.0, max_iter=2000, class_weight="balanced").fit(X_all, y)
    MODEL_DIR.mkdir(exist_ok=True)
    joblib.dump(model, MODEL_FILE, compress=3)
    (MODEL_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2))
    print(json.dumps(metrics, indent=2))
    from app.ml import load_model, phishing_probability
    load_model.cache_clear()
    for d in ["sbi-kyc-update.top", "sbi-rewards-claim.xyz", "indiapost-delivery-fee.click", "hdfc-secure-login.top",
              "sbi.co.in", "hdfcbank.com", "amazon.in", "wikipedia.org", "irctc.co.in", "razorpay.com"]:
        print(f"{d:34s} {phishing_probability(d):.2f}")
    print(f"done in {time.time() - t0:.0f}s, model {MODEL_FILE.stat().st_size / 1e6:.1f} MB")


if __name__ == "__main__":
    main()
