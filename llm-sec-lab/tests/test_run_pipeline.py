import os
import unittest
from unittest.mock import patch


os.environ.setdefault("NVIDIA_API_KEY", "test-api-key")

import run_pipeline


ALERT = {
    "app": "juice_shop",
    "alert_name": "Timestamp Disclosure - Unix",
    "risk": "Low",
    "confidence": "Low",
    "url": "http://juice-shop:3000/app.js",
    "description": "timestamp",
    "evidence": "1666666667",
}


class FakePromptChain:
    def __init__(self, response):
        self.response = response
        self.invocations = 0

    def __or__(self, other):
        return self

    def invoke(self, alert):
        self.invocations += 1
        return self.response


class PromptAndStrategyTests(unittest.TestCase):
    def test_scan_target_list_uses_vulnerable_app(self):
        self.assertEqual(set(run_pipeline.TARGETS), {"juice_shop", "vulnerable_app"})
        self.assertNotIn("webgoat", run_pipeline.TARGETS)

    def test_strategy_set_and_confidence_instructions(self):
        self.assertEqual(
            list(run_pipeline.PROMPT_STRATEGIES),
            ["zero_shot", "few_shot", "cot"],
        )
        values = {
            "alert_name": "Test",
            "risk": "Low",
            "confidence": "Low",
            "url": "/",
            "description": "test",
            "evidence": "test",
        }
        for prompt in run_pipeline.PROMPT_STRATEGIES.values():
            rendered = "\n".join(message.content for message in prompt.format_messages(**values))
            self.assertIn("1.0 means certain true positive", rendered)
            self.assertIn("0.0 means certain false positive", rendered)
            self.assertIn("do not default to 0.5", rendered)
            self.assertIn("Do not include prose, Markdown fences, or comments", rendered)

        few_shot = "\n".join(
            message.content
            for message in run_pipeline.PROMPT_STRATEGIES["few_shot"].format_messages(**values)
        )
        self.assertIn('"confidence": 0.95', few_shot)
        self.assertIn('"confidence": 0.10', few_shot)
        self.assertIn("Cross-Domain Misconfiguration", few_shot)
        self.assertIn("credentials are exposed or sensitive data", few_shot)
        self.assertEqual(run_pipeline.MODEL, "meta/llama-3.1-8b-instruct")
        self.assertEqual(run_pipeline.MAX_COMPLETION_TOKENS, 1024)
        self.assertTrue(run_pipeline.ASSESSMENT_RESPONSE_FORMAT["json_schema"]["strict"])

    def test_success_parse_error_and_cached_results_retain_strategy(self):
        success_chain = FakePromptChain('{"is_vulnerability": false, "confidence": 0.1}')
        cache = {}
        with patch.object(run_pipeline, "build_assessment_chain", return_value=success_chain):
            success = run_pipeline.assess_alert(ALERT, "zero_shot", cache)
            cached = run_pipeline.assess_alert(ALERT, "zero_shot", cache)
        self.assertEqual(success["prompt_strategy"], "zero_shot")
        self.assertEqual(cached["prompt_strategy"], "zero_shot")
        self.assertEqual(success_chain.invocations, 1)

        failure_chain = FakePromptChain("not valid JSON")
        with patch.object(run_pipeline, "build_assessment_chain", return_value=failure_chain):
            failure = run_pipeline.assess_alert(ALERT, "cot")
        self.assertEqual(failure["prompt_strategy"], "cot")
        self.assertTrue(failure["parse_error"])
        self.assertFalse(failure["json_parsed"])
        self.assertTrue(failure["inference_diagnostic"]["repair_attempted"])
        self.assertEqual(failure_chain.invocations, 2)

    def test_json_comments_are_repaired_without_corrupting_urls(self):
        raw_response = """```json
{
  "is_vulnerability": false,
  "url": "http://example.test/login", // model explanation
  "confidence": 0.1
}
```"""
        parsed, repaired, error = run_pipeline.safe_parse_json(raw_response)
        self.assertIsNone(error)
        self.assertTrue(repaired)
        self.assertFalse(parsed["is_vulnerability"])
        self.assertEqual(parsed["url"], "http://example.test/login")


if __name__ == "__main__":
    unittest.main()
