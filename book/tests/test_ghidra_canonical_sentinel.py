import hashlib
import json
import unittest
from pathlib import Path

from book.api import path_utils


CANONICAL_DIR = Path("book/tests/fixtures/ghidra_canonical")
FIXTURE_NAME = "offset_inst_scan_0xc0_write_classify"
FIXTURE_PATH = CANONICAL_DIR / f"{FIXTURE_NAME}.json"
META_PATH = CANONICAL_DIR / f"{FIXTURE_NAME}.meta.json"
WORLD_PATH = Path("book/world/sonoma-14.4.1-23E224-arm64/world.json")
NORMALIZER_ID = "offset_inst_scan_normalizer_v1"
PROVENANCE_SCHEMA_VERSION = 1
META_SCHEMA_VERSION = 1
MAX_FIXTURE_BYTES = 1_000_000
MAX_HITS = 1000
MAX_BLOCKS = 10000
REFRESH_CMD = "python -m book.api.ghidra.refresh_canonical --name offset_inst_scan_0xc0_write_classify"


def _sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _hex_int(value: str) -> int:
    if value is None:
        raise AssertionError("missing hex value")
    return int(str(value), 16)


def _normalize_offset_inst_scan(payload: dict) -> dict:
    meta = dict(payload.get("meta", {}))
    hits = list(payload.get("hits", []))
    block_filter = list(meta.get("block_filter") or [])

    def block_key(entry: dict) -> tuple[int, int, str]:
        start = entry.get("start")
        end = entry.get("end")
        name = entry.get("name") or ""
        return (_hex_int(start) if start else 0, _hex_int(end) if end else 0, name)

    meta["block_filter"] = sorted(block_filter, key=block_key)

    def hit_key(entry: dict) -> tuple[int, str, str]:
        addr = entry.get("address")
        mnemonic = entry.get("mnemonic") or ""
        inst = entry.get("inst") or ""
        return (_hex_int(addr) if addr else 0, mnemonic, inst)

    hits_sorted = sorted(hits, key=hit_key)
    return {"meta": meta, "hits": hits_sorted}


def _expected_dep_paths(repo_root: Path) -> list[str]:
    dep_paths = set()
    dep_paths.add("book/api/ghidra/scripts/ghidra_bootstrap.py")
    ghidra_lib_dir = repo_root / "book" / "api" / "ghidra" / "ghidra_lib"
    if ghidra_lib_dir.exists():
        for path in ghidra_lib_dir.rglob("*.py"):
            dep_paths.add(path_utils.to_repo_relative(path, repo_root))
    return sorted(dep_paths)


class GhidraCanonicalSentinelTests(unittest.TestCase):
    def test_offset_scan_canonical_sentinel(self):
        repo_root = path_utils.find_repo_root()
        fixture_path = repo_root / FIXTURE_PATH
        meta_path = repo_root / META_PATH
        world_path = repo_root / WORLD_PATH

        if not fixture_path.exists():
            self.fail(f"missing canonical fixture: {fixture_path} (run: {REFRESH_CMD})")
        if not meta_path.exists():
            self.fail(f"missing canonical metadata: {meta_path} (run: {REFRESH_CMD})")
        if not world_path.exists():
            self.fail(f"missing world definition: {world_path}")

        meta = json.loads(meta_path.read_text())
        world = json.loads(world_path.read_text())

        generator_meta = meta.get("generator", {})
        input_meta = meta.get("input", {})
        output_meta = meta.get("output", {})
        script_rel = generator_meta.get("script_path")
        program_rel = input_meta.get("program_path")
        output_rel = output_meta.get("path")

        if not script_rel or not program_rel or not output_rel:
            self.fail(f"canonical metadata missing required paths (run: {REFRESH_CMD})")
        for rel_path in (script_rel, program_rel, output_rel):
            if Path(rel_path).is_absolute():
                self.fail(f"canonical metadata path must be repo-relative: {rel_path}")

        script_path = path_utils.ensure_absolute(script_rel, repo_root)
        program_path = path_utils.ensure_absolute(program_rel, repo_root)
        output_path = path_utils.ensure_absolute(output_rel, repo_root)

        if not output_path.exists():
            self.fail(f"missing canonical output: {output_path} (run: {REFRESH_CMD})")

        self.assertEqual(
            meta.get("world_id"),
            world.get("world_id"),
            f"world_id mismatch (run: {REFRESH_CMD})",
        )
        self.assertEqual(
            meta.get("meta_schema_version"),
            META_SCHEMA_VERSION,
            f"meta schema mismatch; bump schema_version + refresh canonical (run: {REFRESH_CMD})",
        )
        self.assertEqual(
            meta.get("normalizer_id"),
            NORMALIZER_ID,
            f"normalizer_id mismatch (run: {REFRESH_CMD})",
        )
        self.assertEqual(
            _sha256_path(script_path),
            generator_meta.get("script_content_sha256"),
            f"script hash mismatch (run: {REFRESH_CMD})",
        )
        self.assertEqual(
            _sha256_path(program_path),
            input_meta.get("program_sha256"),
            f"program hash mismatch (run: {REFRESH_CMD})",
        )
        self.assertEqual(
            _sha256_path(fixture_path),
            output_meta.get("normalized_sha256"),
            f"fixture hash mismatch (run: {REFRESH_CMD})",
        )
        self.assertTrue(generator_meta.get("runner_version"))
        self.assertTrue(meta.get("ghidra", {}).get("version"))
        self.assertTrue(meta.get("analysis", {}).get("profile_id"))

        deps = list(generator_meta.get("deps") or [])
        meta_dep_paths = sorted(dep.get("path") for dep in deps if dep.get("path"))
        expected_dep_paths = _expected_dep_paths(repo_root)
        self.assertEqual(
            meta_dep_paths,
            expected_dep_paths,
            f"dependency list incomplete; refresh canonical (run: {REFRESH_CMD})",
        )
        for dep in deps:
            dep_path = dep.get("path")
            dep_sha = dep.get("sha256")
            if not dep_path or not dep_sha:
                self.fail(f"canonical metadata dependency missing fields (run: {REFRESH_CMD})")
            if Path(dep_path).is_absolute():
                self.fail(f"canonical metadata dependency must be repo-relative: {dep_path}")
            dep_abs = path_utils.ensure_absolute(dep_path, repo_root)
            self.assertEqual(
                _sha256_path(dep_abs),
                dep_sha,
                f"dependency hash mismatch for {dep_path} (run: {REFRESH_CMD})",
            )

        fixture = json.loads(fixture_path.read_text())
        live = json.loads(output_path.read_text())

        provenance = live.get("_provenance")
        if provenance is None:
            self.fail(f"canonical output missing _provenance (run: {REFRESH_CMD})")
        if not isinstance(provenance, dict):
            self.fail(f"canonical output _provenance must be an object (run: {REFRESH_CMD})")
        self.assertEqual(
            provenance.get("schema_version"),
            PROVENANCE_SCHEMA_VERSION,
            f"provenance schema mismatch; bump schema_version + refresh canonical (run: {REFRESH_CMD})",
        )

        self.assertEqual(
            provenance.get("world_id"),
            meta.get("world_id"),
            f"output provenance world_id mismatch (run: {REFRESH_CMD})",
        )
        prov_gen = provenance.get("generator", {})
        prov_input = provenance.get("input", {})
        prov_analysis = provenance.get("analysis", {})
        self.assertEqual(
            prov_gen.get("script_path"),
            script_rel,
            f"output provenance script_path mismatch (run: {REFRESH_CMD})",
        )
        self.assertEqual(
            prov_gen.get("script_content_sha256"),
            generator_meta.get("script_content_sha256"),
            f"output provenance script hash mismatch (run: {REFRESH_CMD})",
        )
        self.assertEqual(
            prov_input.get("program_path"),
            program_rel,
            f"output provenance program_path mismatch (run: {REFRESH_CMD})",
        )
        self.assertEqual(
            prov_input.get("program_sha256"),
            input_meta.get("program_sha256"),
            f"output provenance program hash mismatch (run: {REFRESH_CMD})",
        )
        self.assertEqual(
            prov_analysis.get("profile_id"),
            meta.get("analysis", {}).get("profile_id"),
            f"output provenance profile mismatch (run: {REFRESH_CMD})",
        )

        prov_deps = list(prov_gen.get("deps") or [])
        prov_deps_sorted = sorted(prov_deps, key=lambda item: item.get("path", ""))
        meta_deps_sorted = sorted(deps, key=lambda item: item.get("path", ""))
        self.assertEqual(
            prov_deps_sorted,
            meta_deps_sorted,
            f"output provenance deps mismatch (run: {REFRESH_CMD})",
        )

        norm_fixture = _normalize_offset_inst_scan(fixture)
        norm_live = _normalize_offset_inst_scan(live)

        if norm_fixture != norm_live:
            self.fail(f"canonical output mismatch (run: {REFRESH_CMD})")

        hits = norm_live.get("hits", [])
        meta_live = norm_live.get("meta", {})
        self.assertLessEqual(
            fixture_path.stat().st_size,
            MAX_FIXTURE_BYTES,
            f"fixture too large; refresh + re-evaluate budget (run: {REFRESH_CMD})",
        )
        self.assertLessEqual(
            len(hits),
            MAX_HITS,
            f"hit count too large; refresh + re-evaluate budget (run: {REFRESH_CMD})",
        )
        self.assertLessEqual(
            len(meta_live.get("block_filter") or []),
            MAX_BLOCKS,
            f"block_filter too large; refresh + re-evaluate budget (run: {REFRESH_CMD})",
        )
        self.assertEqual(meta_live.get("hit_count"), len(hits))
        self.assertEqual(meta_live.get("offset"), "0xc0")
        self.assertTrue(meta_live.get("include_canonical"))
        self.assertTrue(meta_live.get("include_access"))

        seen = set()
        last_addr = None
        for hit in hits:
            addr = hit.get("address")
            addr_val = _hex_int(addr)
            if last_addr is not None:
                self.assertGreaterEqual(addr_val, last_addr)
            last_addr = addr_val
            self.assertEqual(hit.get("address_canon"), addr)
            self.assertIn(hit.get("access"), {"load", "store", "other"})
            self.assertIsInstance(hit.get("stack_access"), bool)
            key = (addr, hit.get("mnemonic"), hit.get("inst"))
            self.assertNotIn(key, seen)
            seen.add(key)


if __name__ == "__main__":
    unittest.main()
