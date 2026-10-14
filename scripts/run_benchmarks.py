"""
CAS-SE Evaluation & Benchmark Runner -- Phase 7

Executes evaluation benchmarks, outputs JSON report, and generates visual charts.

Usage:
  python scripts/run_benchmarks.py [--dataset fashion_mnist|cifar10] [--samples 300] [--output-dir evaluation_results/]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Ensure backend app is on sys.path
backend_path = Path(__file__).resolve().parent.parent / "backend"
if str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))

from app.evaluation.benchmarks import generate_evaluation_charts, run_all_benchmarks


def main() -> int:
    parser = argparse.ArgumentParser(description="Run CAS-SE Evaluation Benchmarks")
    parser.add_argument(
        "--dataset",
        choices=["fashion_mnist", "cifar10"],
        default="fashion_mnist",
        help="Dataset benchmark representation",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=300,
        help="Number of samples for classifier evaluation",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="evaluation_results",
        help="Output directory for reports and charts",
    )
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"=== Starting CAS-SE Evaluation Suite ({args.dataset.upper()}) ===")
    report = run_all_benchmarks(dataset_name=args.dataset, n_samples=args.samples)

    # 1. Save JSON Report
    report_json_path = out_dir / "benchmark_report.json"
    report_json_path.write_text(
        json.dumps(report.to_dict(), indent=2), encoding="utf-8"
    )
    print(f"[+] Saved evaluation report to: {report_json_path}")

    # 2. Generate SVG Charts
    charts = generate_evaluation_charts(report, out_dir)
    for c in charts:
        print(f"[+] Generated chart: {c}")

    # 3. Print Summary Table
    print("\n--- Baseline Classifier Comparison ---")
    print(
        f"{'Architecture':<16} {'Accuracy':<10} {'F1 Score':<10} {'Raw Released':<14} {'Denial Rate':<12}"
    )
    print("-" * 64)
    for b in report.baseline_comparisons:
        print(
            f"{b.architecture:<16} {b.accuracy:<10.3f} {b.f1_score:<10.3f} "
            f"{b.raw_images_released:<14} {b.unauthorized_denial_rate:<12.1f}%"
        )

    print("\n--- Performance Overhead ---")
    for p in report.performance_benchmarks:
        print(
            f"  * {p.operation:<35}: Plaintext={p.plaintext_latency_ms:.3f}ms | "
            f"CAS-SE={p.cas_se_latency_ms:.3f}ms (Overhead: +{p.overhead_ms:.3f}ms)"
        )

    print("\n--- Security Verification ---")
    for s in report.security_benchmarks:
        status = "PASSED" if s.passed else "FAILED"
        print(f"  * [{status}] {s.test_case}: {s.actual_outcome}")

    print(
        f"\n[OK] Storage Overhead: +{report.storage_overhead['net_overhead_bytes']} bytes "
        f"(+{report.storage_overhead['net_overhead_percentage']}%) per 64 KB envelope"
    )
    print("\n=== Evaluation Suite Completed Successfully ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
