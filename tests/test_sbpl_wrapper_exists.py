from pathlib import Path


def test_sbpl_wrapper_built():
    wrapper = Path("book/api/SBPL-wrapper/wrapper")
    assert wrapper.exists(), "wrapper binary is missing; build with clang -o wrapper wrapper.c -lsandbox"
    assert wrapper.is_file()


def test_sbpl_wrapper_blob_mode_runs_allow_all():
    wrapper = Path("book/api/SBPL-wrapper/wrapper")
    blob = Path("book/experiments/sbpl-graph-runtime/out/allow_all.sb.bin")
    if not (wrapper.exists() and blob.exists()):
        return
    import subprocess
    res = subprocess.run(
        [str(wrapper), "--blob", str(blob), "--", "/bin/echo", "blob-test"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert res.returncode == 0
    assert "blob-test" in res.stdout
