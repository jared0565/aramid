from aramid.fingerprint import compute_fingerprint, normalize_line

def test_id_stable_across_line_shift_and_crlf():
    a = compute_fingerprint("ruff","S102","src/a.py","    exec(x)\n",0)
    b = compute_fingerprint("ruff","S102","src/a.py","    exec(x)\r\n",0)   # CRLF
    c = compute_fingerprint("ruff","S102","SRC/A.PY","exec(x)",0)           # ws+case
    assert a == b == c

def test_occurrence_index_disambiguates_identical_lines():
    assert compute_fingerprint("ruff","S102","a.py","exec(x)",0) != \
           compute_fingerprint("ruff","S102","a.py","exec(x)",1)

def test_editing_line_changes_id():
    assert compute_fingerprint("ruff","S102","a.py","exec(x)",0) != \
           compute_fingerprint("ruff","S102","a.py","exec(y)",0)
