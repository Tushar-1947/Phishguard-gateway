"""ML phishing classifier: TF-IDF (word + char n-grams) -> Logistic Regression."""
import csv
import json
import os
from typing import Optional

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline

DEFAULT_MODEL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models", "phish_model.joblib")


def build_pipeline() -> Pipeline:
    feats = FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True, stop_words="english")),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3, sublinear_tf=True, max_features=30000)),
    ])
    return Pipeline([("tfidf", feats), ("clf", LogisticRegression(max_iter=1000, C=3.0, class_weight="balanced"))])


def load_csv(path: str):
    texts, labels = [], []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            texts.append(row["text"])
            labels.append(int(row["label"]))
    return texts, labels


def train(data_path: str, model_path: str = DEFAULT_MODEL, test_size: float = 0.2, seed: int = 42) -> dict:
    X, y = load_csv(data_path)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=test_size, stratify=y, random_state=seed)
    pipe = build_pipeline().fit(Xtr, ytr)
    pred = pipe.predict(Xte)
    rep = classification_report(yte, pred, target_names=["legitimate", "phishing"], output_dict=True)
    metrics = {"samples": len(X), "test_size": len(yte),
               "accuracy": round(rep["accuracy"], 4),
               "phishing_precision": round(rep["phishing"]["precision"], 4),
               "phishing_recall": round(rep["phishing"]["recall"], 4),
               "phishing_f1": round(rep["phishing"]["f1-score"], 4),
               "confusion_matrix": confusion_matrix(yte, pred).tolist()}
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump(pipe, model_path)
    with open(os.path.join(os.path.dirname(model_path), "metrics.json"), "w") as fh:
        json.dump(metrics, fh, indent=2)
    return metrics


class PhishModel:
    def __init__(self, path: str = DEFAULT_MODEL):
        self.pipe = joblib.load(path)

    def predict_proba(self, text: str) -> float:
        return float(self.pipe.predict_proba([text])[0][1])


def load_model(path: Optional[str] = None) -> Optional[PhishModel]:
    path = path or DEFAULT_MODEL
    return PhishModel(path) if os.path.exists(path) else None
