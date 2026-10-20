"""
Unit tests for VulnerabilityAIClassifier, ML inference, and dataset integrity.
"""

import json
import unittest
from pathlib import Path

from juicesec.ai_classifier import VulnerabilityAIClassifier


class VulnerabilityAIClassifierTests(unittest.TestCase):
    """Test suite verifying AI/Heuristic Classifier behavior."""

    @classmethod
    def setUpClass(cls):
        cls.project_root = Path(__file__).resolve().parent.parent
        cls.data_dir = cls.project_root / "data"
        cls.models_dir = cls.project_root / "models"
        cls.classifier = VulnerabilityAIClassifier()

    def test_classifier_initialization(self):
        """Classifier should initialize successfully in ML or Heuristic mode."""
        self.assertIsNotNone(self.classifier)
        self.assertIn(self.classifier.mode, ["ml", "heuristic"])
        self.assertTrue(hasattr(self.classifier, "predict_code"))
        self.assertTrue(hasattr(self.classifier, "rescore_ast_findings"))

    def test_fallback_mode_on_invalid_model_path(self):
        """When given an invalid model path, classifier safely falls back to heuristic mode."""
        fallback_clf = VulnerabilityAIClassifier(model_path="/non/existent/model.joblib")
        self.assertEqual(fallback_clf.mode, "heuristic")
        self.assertEqual(fallback_clf.model_name, "heuristic_fallback")

        res = fallback_clf.predict_code("const x = 1;")
        self.assertIsInstance(res, dict)
        self.assertIn("is_vulnerable", res)
        self.assertIn("confidence", res)
        self.assertFalse(res["is_vulnerable"])

    def test_predict_code_safe_vs_vulnerable(self):
        """Classifier predicts high confidence for dangerous code and low confidence for safe code."""
        safe_snippet = "db.execute('SELECT * FROM users WHERE id = ?', [user_id]);"
        vuln_snippet = "const q = 'SELECT * FROM users WHERE id=' + req.body.id;\ndb.query(q);"

        safe_res = self.classifier.predict_code(safe_snippet)
        vuln_res = self.classifier.predict_code(vuln_snippet)

        self.assertIsInstance(safe_res, dict)
        self.assertIsInstance(vuln_res, dict)
        self.assertGreater(
            vuln_res["confidence"],
            safe_res["confidence"],
            "Vulnerable snippet should have higher confidence score than safe snippet"
        )

    def test_predict_batch(self):
        """Batch prediction returns consistent results matching individual predict_code."""
        snippets = [
            "db.execute('SELECT * FROM users WHERE id = ?', [user_id]);",
            "const q = 'SELECT * FROM users WHERE id=' + req.body.id;\ndb.query(q);",
            "const safe_val = Math.floor(Math.random() * 100);",
        ]

        batch_res = self.classifier.predict_batch(snippets)
        self.assertEqual(len(batch_res), len(snippets))

        for i, snippet in enumerate(snippets):
            single_res = self.classifier.predict_code(snippet)
            self.assertEqual(batch_res[i]["is_vulnerable"], single_res["is_vulnerable"])
            self.assertAlmostEqual(batch_res[i]["confidence"], single_res["confidence"], places=2)

        # Empty list handling
        self.assertEqual(self.classifier.predict_batch([]), [])

        # Heuristic fallback batch handling
        fallback_clf = VulnerabilityAIClassifier(model_path="/non/existent/model.joblib")
        fb_batch = fallback_clf.predict_batch(snippets)
        self.assertEqual(len(fb_batch), len(snippets))
        for item in fb_batch:
            self.assertIn("is_vulnerable", item)
            self.assertIn("confidence", item)

    def test_rescore_ast_findings(self):
        """Rescoring should attach ai_confidence and ai_rescored metadata to findings."""
        findings = [
            {
                "id": "AST-01",
                "severity": "HIGH",
                "snippet": "const q = 'SELECT * FROM users WHERE id=' + req.body.id;",
            },
            {
                "id": "AST-02",
                "severity": "LOW",
                "snippet": "const safe_val = Math.floor(Math.random() * 100);",
            }
        ]

        rescored = self.classifier.rescore_ast_findings(findings)
        self.assertEqual(len(rescored), 2)
        for f in rescored:
            self.assertTrue(f.get("ai_rescored"))
            self.assertIn("ai_confidence", f)
            self.assertIn("original_severity", f)

    def test_empty_or_invalid_code_handling(self):
        """Empty or invalid code should safely return zero confidence without crashing."""
        res_empty = self.classifier.predict_code("")
        res_none = self.classifier.predict_code(None)  # type: ignore

        self.assertFalse(res_empty["is_vulnerable"])
        self.assertEqual(res_empty["confidence"], 0.0)
        self.assertFalse(res_none["is_vulnerable"])
        self.assertEqual(res_none["confidence"], 0.0)

    def test_dataset_integrity(self):
        """Validate datasets exist and have consistent JSON schema."""
        for filename in ["corpus.json", "holdout.json", "external_corpus.json"]:
            path = self.data_dir / filename
            self.assertTrue(path.exists(), f"Dataset file missing: {path}")

            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.assertIsInstance(data, list)
            self.assertGreater(len(data), 0)
            for item in data:
                self.assertIn("id", item)
                self.assertIn("positive", item)
                self.assertIn("source", item)
                self.assertIsInstance(item["positive"], bool)
                self.assertIsInstance(item["source"], str)

    def test_model_sha256_checksum_verification(self):
        """Model file integrity must match SHA-256 checksum to prevent pickle deserialization RCE."""
        model_path = self.models_dir / "vuln_classifier.joblib"
        checksum_path = self.models_dir / "model_checksum.sha256"

        self.assertTrue(model_path.exists(), "Model artifact must exist")
        self.assertTrue(checksum_path.exists(), "Model SHA-256 checksum file must exist")

        is_valid = VulnerabilityAIClassifier.verify_model_integrity(model_path)
        self.assertTrue(is_valid, "verify_model_integrity must return True for official model artifact")

    def test_tampered_model_integrity_rejection(self):
        """Tampered model should fail checksum verification and fall back to safe heuristic."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_model = Path(tmpdir) / "fake_model.joblib"
            tmp_chk = Path(tmpdir) / "fake_model.sha256"
            tmp_model.write_bytes(b"tampered pickle payload")
            tmp_chk.write_text("0000000000000000000000000000000000000000000000000000000000000000  fake_model.joblib")

            is_valid = VulnerabilityAIClassifier.verify_model_integrity(tmp_model)
            self.assertFalse(is_valid, "Tampered model hash must be rejected")

            clf = VulnerabilityAIClassifier(model_path=str(tmp_model))
            self.assertEqual(clf.mode, "heuristic")
            self.assertIn("integrity_mismatch", clf.model_name)

    def test_probabilistic_score_fusion(self):
        """Test Bayesian logit score fusion handles monotonic probabilities and edge cases."""
        p_high = VulnerabilityAIClassifier._probabilistic_fusion(0.9, 0.8)
        p_low = VulnerabilityAIClassifier._probabilistic_fusion(0.1, 0.2)
        p_neutral = VulnerabilityAIClassifier._probabilistic_fusion(0.5, 0.5)

        self.assertGreater(p_high, 0.8)
        self.assertLess(p_low, 0.2)
        self.assertAlmostEqual(p_neutral, 0.5, places=2)

    def test_get_detailed_explanation(self):
        """Test XAI explanation breakdown with active AST features."""
        code = "db.query('SELECT * FROM users WHERE id=' + req.query.id);"
        expl = self.classifier.get_detailed_explanation(code)
        self.assertIn("prediction", expl)
        self.assertIn("active_features", expl)
        self.assertIn("risk_level", expl)
        self.assertIn("categories_breakdown", expl)
        active_ids = [f["id"] for f in expl["active_features"]]
        self.assertTrue(any("sql" in fid or "source" in fid or "concat" in fid for fid in active_ids))


if __name__ == "__main__":
    unittest.main()
