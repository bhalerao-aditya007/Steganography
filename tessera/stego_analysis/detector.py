"""Machine learning steganalysis distinguisher using SPAM features and Logistic Regression."""
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score, accuracy_score
from .spam import extract_spam_features

class SteganalysisDetector:
    """Logistic Regression classifier trained on SPAM features."""
    def __init__(self, C: float = 1.0, max_iter: int = 500):
        self.clf = LogisticRegression(C=C, max_iter=max_iter, solver="lbfgs")
        self.fitted = False

    def train(self, X_class0: list[np.ndarray], X_class1: list[np.ndarray]) -> dict:
        """Train classifier to distinguish class 0 from class 1.
        
        Args:
            X_class0: List of images for class 0 (e.g. Cover or Decoy-only)
            X_class1: List of images for class 1 (e.g. Decoy-only or Mirage)
            
        Returns:
            Dictionary with training accuracy and ROC AUC.
        """
        feats0 = [extract_spam_features(img) for img in X_class0]
        feats1 = [extract_spam_features(img) for img in X_class1]
        
        X = np.vstack([feats0, feats1])
        y = np.array([0] * len(feats0) + [1] * len(feats1))
        
        self.clf.fit(X, y)
        self.fitted = True
        
        probs = self.clf.predict_proba(X)[:, 1]
        preds = self.clf.predict(X)
        
        auc = roc_auc_score(y, probs) if len(np.unique(y)) > 1 else 0.5
        acc = accuracy_score(y, preds)
        
        return {"accuracy": float(acc), "auc": float(auc)}

    def predict_proba(self, img: np.ndarray) -> float:
        """Compute posterior probability P(class 1 | img)."""
        if not self.fitted:
            return 0.5
        feat = extract_spam_features(img).reshape(1, -1)
        return float(self.clf.predict_proba(feat)[0, 1])

    def evaluate(self, X_class0: list[np.ndarray], X_class1: list[np.ndarray]) -> dict:
        """Evaluate trained model on test images."""
        feats0 = [extract_spam_features(img) for img in X_class0]
        feats1 = [extract_spam_features(img) for img in X_class1]
        
        X = np.vstack([feats0, feats1])
        y = np.array([0] * len(feats0) + [1] * len(feats1))
        
        probs = self.clf.predict_proba(X)[:, 1]
        preds = self.clf.predict(X)
        
        auc = roc_auc_score(y, probs) if len(np.unique(y)) > 1 else 0.5
        acc = accuracy_score(y, preds)
        p_fa = float(np.mean(preds[:len(feats0)] == 1))
        p_md = float(np.mean(preds[len(feats0):] == 0))
        p_e = 0.5 * (p_fa + p_md)
        
        return {
            "accuracy": float(acc),
            "auc": float(auc),
            "p_fa": p_fa,
            "p_md": p_md,
            "p_e": p_e,
        }
