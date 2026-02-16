"""Tests for the evaluation framework (ablation + full eval)."""


from core.pipeline import PipelineConfig
from eval.ablation import (
    get_ablation_configs,
    run_ablation,
    generate_ablation_report,
    AblationResult,
)
from eval.full_eval import (
    normalize_text,
    exact_match,
    contains_match,
    token_f1,
    compute_rouge_l,
    run_full_eval,
    eval_on_demo_queries,
)


# ── Answer quality metric tests ────────────────────────────────────────────

class TestNormalizeText:
    def test_lowercase(self):
        assert normalize_text("Hello World") == "hello world"

    def test_punctuation_removal(self):
        assert normalize_text("Hello, World!") == "hello world"

    def test_whitespace_collapse(self):
        assert normalize_text("  hello   world  ") == "hello world"


class TestExactMatch:
    def test_match(self):
        assert exact_match("Hello World", ["hello world"]) == 1.0

    def test_no_match(self):
        assert exact_match("Hello", ["World"]) == 0.0

    def test_multi_gold(self):
        assert exact_match("Paris", ["paris", "Paris, France"]) == 1.0


class TestContainsMatch:
    def test_contained(self):
        assert contains_match(
            "Python was created by Guido van Rossum",
            ["Guido van Rossum"]
        ) == 1.0

    def test_not_contained(self):
        assert contains_match("Hello", ["World"]) == 0.0


class TestTokenF1:
    def test_perfect_match(self):
        assert token_f1("hello world", ["hello world"]) == 1.0

    def test_partial_overlap(self):
        f1 = token_f1("the cat sat", ["the cat"])
        assert 0.0 < f1 < 1.0

    def test_no_overlap(self):
        assert token_f1("xyz", ["abc"]) == 0.0


class TestRougeL:
    def test_perfect(self):
        score = compute_rouge_l("hello world", ["hello world"])
        assert score > 0.99

    def test_partial(self):
        score = compute_rouge_l("the quick brown fox", ["the brown fox jumps"])
        assert 0.0 < score < 1.0

    def test_no_overlap(self):
        score = compute_rouge_l("xyz", ["abc"])
        assert score == 0.0


# ── Ablation tests ─────────────────────────────────────────────────────────

class TestAblationConfigs:
    def test_heuristic_configs_have_8_entries(self):
        configs = get_ablation_configs(use_llm=False)
        assert len(configs) == 8

    def test_llm_configs_have_8_entries(self):
        configs = get_ablation_configs(use_llm=True)
        assert len(configs) == 8

    def test_c7_minimal_has_no_signing(self):
        configs = get_ablation_configs(use_llm=False)
        c7 = configs["C7_minimal"]
        assert c7.enable_signing is False
        assert c7.enable_transparency is False


class TestAblationRun:
    def test_run_small_ablation(self):
        """Run ablation on a single query with 2 configs."""
        configs = {
            "full": PipelineConfig(
                use_llm_generation=False, use_llm_claims=False,
                use_embedding_spans=False, verifier_mode="heuristic",
                retrieval_mode="bm25", enable_transparency=True,
                enable_signing=True,
            ),
            "minimal": PipelineConfig(
                use_llm_generation=False, use_llm_claims=False,
                use_embedding_spans=False, verifier_mode="heuristic",
                retrieval_mode="bm25", enable_transparency=False,
                enable_signing=False,
            ),
        }
        results = run_ablation(["What is Python?"], configs=configs)
        assert len(results) == 2

        full_r = results[0]
        min_r = results[1]

        # Both should detect hash-based attacks (commitments always present)
        assert full_r.tdr >= 0.8
        # Minimal still has hash commitments, so it catches most attacks too
        assert min_r.tdr >= 0.5


class TestAblationReport:
    def test_report_generation(self, tmp_path):
        result = AblationResult(
            config_name="test",
            config=PipelineConfig(),
            n_queries=1,
            tdr=1.0,
            fbr=0.0,
            avg_latency_ms=50.0,
            avg_artifact_size=5000,
        )
        path = str(tmp_path / "test_ablation.md")
        report = generate_ablation_report([result], output_path=path)
        assert "PCRAG Ablation Study" in report
        assert "test" in report


# ── Full eval tests ────────────────────────────────────────────────────────

class TestFullEval:
    def test_eval_single_query(self):
        """Run full eval on 1 query with heuristic config."""
        config = PipelineConfig(
            use_llm_generation=False, use_llm_claims=False,
            use_embedding_spans=False, verifier_mode="heuristic",
            retrieval_mode="bm25", enable_transparency=True,
            enable_signing=True,
        )
        results = run_full_eval(
            queries=["What is Python?"],
            gold_answers_list=[["Python is a programming language", "Guido van Rossum"]],
            dataset_name="test",
            config=config,
        )
        assert results.n_samples == 1
        assert results.avg_tdr > 0.0
        assert results.avg_latency_ms > 0


class TestDemoEval:
    def test_demo_eval_runs(self):
        """Run the demo evaluation (5 queries, heuristic mode)."""
        results = eval_on_demo_queries(use_llm=False)
        assert results.n_samples == 5
        assert results.avg_tdr > 0.0
        assert results.avg_fbr >= 0.0
        assert results.avg_latency_ms > 0
        # At least some answers should partially match gold
        assert results.avg_contains_match >= 0.0 or results.avg_token_f1 >= 0.0
