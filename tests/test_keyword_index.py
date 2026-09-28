from __future__ import annotations

from app.retrieval.keyword_index import KeywordIndex, tokenize


def test_tokenize_lowercases_and_keeps_dots_and_slashes():
    tokens = tokenize("Scheduled Task via schtasks.exe C:\\Windows\\System32")
    assert "schtasks.exe" in tokens
    assert "c:\\windows\\system32" in tokens
    assert "scheduled" in tokens


def test_tokenize_drops_punctuation_not_in_pattern():
    tokens = tokenize("T1053.005, T1059!")
    assert "t1053.005" in tokens
    assert "t1059" in tokens


CHUNKS = [
    {"chunk_id": "T1053::technique_description::0", "text": "Scheduled Task/Job via schtasks.exe for persistence"},
    {"chunk_id": "T1003::technique_description::0", "text": "OS Credential Dumping from LSASS memory using mimikatz"},
    {"chunk_id": "T1059::technique_description::0", "text": "Command and Scripting Interpreter using powershell.exe"},
]


def test_keyword_index_search_ranks_exact_term_match_first():
    index = KeywordIndex.build(CHUNKS)
    results = index.search("schtasks.exe", n_results=3)
    assert results[0][0] == "T1053::technique_description::0"


def test_keyword_index_search_respects_n_results_limit():
    index = KeywordIndex.build(CHUNKS)
    results = index.search("persistence", n_results=1)
    assert len(results) == 1


def test_keyword_index_search_returns_chunk_id_score_pairs():
    index = KeywordIndex.build(CHUNKS)
    results = index.search("mimikatz")
    assert all(isinstance(chunk_id, str) and isinstance(score, float) for chunk_id, score in results)


def test_keyword_index_save_and_load_roundtrip(tmp_path):
    index = KeywordIndex.build(CHUNKS)
    path = tmp_path / "bm25.pkl"
    index.save(path)

    loaded = KeywordIndex.load(path)
    assert loaded.chunk_ids == index.chunk_ids

    original_results = index.search("powershell.exe")
    loaded_results = loaded.search("powershell.exe")
    assert original_results == loaded_results


def test_keyword_index_save_creates_parent_directories(tmp_path):
    index = KeywordIndex.build(CHUNKS)
    path = tmp_path / "nested" / "dir" / "bm25.pkl"
    index.save(path)
    assert path.exists()
