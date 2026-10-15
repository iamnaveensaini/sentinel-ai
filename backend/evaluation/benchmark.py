"""
Sentinel AI - Automated Security Evaluation Suite & Benchmarking Runner
Measures:
- Precision & Recall across PII, Secrets, and Injection categories
- False Positive Rate on normal prompts
- Secret Prevention Rate (Blocked-before-forward enforcement)
- Gateway Latency Overhead (p50 and p95 in milliseconds)
- Zero-Raw-Content Audit Verification (ensures no sensitive text in DB logs)
"""
import json
import os
import sys
import time
import asyncio
from typing import List, Dict, Any

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.auth.models import AuthenticatedUser, UserRole
from backend.gateway.orchestrator import gateway_orchestrator, GatewayRequest
from backend.audit.logger import audit_logger

async def run_evaluation(dataset_path: str = "tests/evaluation_corpus/dataset.json"):
    print("=" * 70)
    print("SENTINEL AI: SECURITY EVALUATION & GATEWAY BENCHMARK RUNNER")
    print("=" * 70)
    
    if not os.path.exists(dataset_path):
        print(f"Error: Dataset file not found at {dataset_path}")
        return

    with open(dataset_path, "r", encoding="utf-8") as f:
        cases = json.load(f)

    test_user = AuthenticatedUser(
        user_id="eval_runner_01",
        tenant_id="tenant_benchmark",
        roles=[UserRole.END_USER],
        allowed_doc_scopes=["public"]
    )

    total_cases = len(cases)
    tp = 0 # Sensitive item correctly flagged (MASK or BLOCK)
    fp = 0 # Benign item incorrectly flagged
    tn = 0 # Benign item allowed
    fn = 0 # Sensitive item missed (allowed)

    secrets_tested = 0
    secrets_blocked_before_provider = 0

    latencies_ms: List[float] = []

    print(f"\n[+] Executing evaluation suite with {total_cases} test cases...\n")

    for idx, c in enumerate(cases, 1):
        req = GatewayRequest(message=c["prompt"])
        t_start = time.perf_counter()
        res = await gateway_orchestrator.process_chat(req, test_user)
        lat = round((time.perf_counter() - t_start) * 1000, 2)
        latencies_ms.append(res.gateway_latency_ms)

        actual_action = res.status.upper()
        expected_action = c["expected_action"].upper()
        is_sensitive = (expected_action != "ALLOW")

        # Check Secrets Blocked Before Provider
        if c["category"].startswith("secret_") or c["category"] == "prompt_injection":
            secrets_tested += 1
            if actual_action == "BLOCKED" and not res.provider_called:
                secrets_blocked_before_provider += 1

        # Accuracy classification
        if is_sensitive:
            if actual_action in ["MASKED", "BLOCKED"]:
                tp += 1
            else:
                fn += 1
                print(f"  [-] FALSE NEGATIVE on ID #{c['id']}: Expected {expected_action}, got {actual_action}")
        else:
            if actual_action == "ALLOWED":
                tn += 1
            else:
                fp += 1
                print(f"  [-] FALSE POSITIVE on ID #{c['id']}: Expected ALLOW, got {actual_action} ({res.reason_codes})")

    # Metrics computation
    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 1.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 1.0
    fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
    prevention_rate = round((secrets_blocked_before_provider / secrets_tested) * 100, 2) if secrets_tested > 0 else 100.0

    latencies_sorted = sorted(latencies_ms)
    p50_latency = latencies_sorted[int(len(latencies_sorted) * 0.50)]
    p95_latency = latencies_sorted[int(len(latencies_sorted) * 0.95)]

    # Zero-Raw-Content DB Verification
    recent_db_events = audit_logger.get_recent_events(limit=100)
    raw_leak_count = 0
    for event in recent_db_events:
        for k, v in event.items():
            val_str = str(v)
            if "AKIA" in val_str or "sk-" in val_str or "@" in val_str or "password=" in val_str:
                raw_leak_count += 1

    print("\n" + "=" * 70)
    print("                 BENCHMARK RESULTS SUMMARY")
    print("=" * 70)
    print(f" Total Evaluation Cases Tested:  {total_cases}")
    print(f" True Positives (TP):            {tp}")
    print(f" True Negatives (TN):            {tn}")
    print(f" False Positives (FP):           {fp}")
    print(f" False Negatives (FN):           {fn}")
    print("-" * 70)
    print(f" Recall (Sensitivity):           {recall * 100:.2f}%")
    print(f" Precision:                      {precision * 100:.2f}%")
    print(f" False Positive Rate (FPR):      {fpr * 100:.2f}%")
    print(f" Secret Prevention Rate:         {prevention_rate:.2f}% (Must be 100%)")
    print("-" * 70)
    print(f" Gateway Overhead Latency (p50): {p50_latency:.2f} ms")
    print(f" Gateway Overhead Latency (p95): {p95_latency:.2f} ms")
    print(f" Raw Sensitive Leak in Logs:     {raw_leak_count} (Must be 0)")
    print("=" * 70)

    results_summary = {
        "timestamp": time.time(),
        "total_cases": total_cases,
        "metrics": {
            "recall": recall,
            "precision": precision,
            "false_positive_rate": fpr,
            "secret_prevention_rate": prevention_rate,
            "p50_latency_ms": p50_latency,
            "p95_latency_ms": p95_latency,
            "raw_leaks_in_audit_db": raw_leak_count
        }
    }
    
    with open("eval_results_latest.json", "w", encoding="utf-8") as f:
        json.dump(results_summary, f, indent=2)
    print("\n[✓] Results persisted to eval_results_latest.json\n")

if __name__ == "__main__":
    asyncio.run(run_evaluation())
