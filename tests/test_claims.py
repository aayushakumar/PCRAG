"""Tests for claim extraction."""


from core.claims import extract_claims


class TestExtractClaims:
    def test_empty_input(self):
        assert extract_claims("") == []
        assert extract_claims("   ") == []

    def test_single_sentence(self):
        result = extract_claims("Python is a programming language.")
        assert len(result) == 1
        assert result[0] == "Python is a programming language."

    def test_multiple_sentences(self):
        text = "Python is interpreted. It supports OOP. Guido created it."
        result = extract_claims(text)
        assert len(result) == 3

    def test_short_fragments_filtered(self):
        text = "Hi. This is a proper sentence about programming."
        result = extract_claims(text)
        # "Hi." is too short (<=5 chars), should be filtered
        assert all(len(c) > 5 for c in result)

    def test_bullet_points(self):
        text = "Key features:\n- Dynamic typing support\n- Garbage collection built in"
        result = extract_claims(text)
        assert len(result) >= 2
        # Bullet markers should be stripped
        for claim in result:
            assert not claim.startswith("-")
            assert not claim.startswith("•")

    def test_numbered_list(self):
        text = "Steps:\n1. Install Python from python dot org\n2. Write your first program"
        result = extract_claims(text)
        assert len(result) >= 2
        for claim in result:
            assert not claim[0].isdigit() or "." not in claim[:3]

    def test_preserves_content(self):
        text = "SHA-256 generates a 256-bit hash. It is widely used in security."
        result = extract_claims(text)
        assert any("256" in c for c in result)
        assert any("security" in c for c in result)

    def test_question_mark_split(self):
        text = "What is Python? It is a language. How does it work? Through interpretation."
        result = extract_claims(text)
        assert len(result) >= 2
