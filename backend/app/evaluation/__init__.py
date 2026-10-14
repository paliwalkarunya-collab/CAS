"""CAS-SE Evaluation and Benchmarking Framework -- Phase 7"""

from __future__ import annotations

from app.evaluation.benchmarks import (
    BaselineComparisonResult,
    BenchmarkReport,
    PerformanceBenchmarkResult,
    generate_evaluation_charts,
    run_all_benchmarks,
    run_baseline_classifier_comparison,
    run_performance_benchmarks,
)

__all__ = [
    "BaselineComparisonResult",
    "BenchmarkReport",
    "PerformanceBenchmarkResult",
    "generate_evaluation_charts",
    "run_all_benchmarks",
    "run_baseline_classifier_comparison",
    "run_performance_benchmarks",
]
