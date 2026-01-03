"""Mapping generator job wrappers."""

from __future__ import annotations

from pathlib import Path

from book.integration.carton.jobs import common


def run_vocab(repo_root: Path) -> None:
    common.run_module("book.integration.carton.mappings.vocab.generate_vocab_from_dyld", repo_root=repo_root)
    common.run_module("book.integration.carton.mappings.vocab.generate_attestations", repo_root=repo_root)
    common.run_module("book.integration.carton.mappings.vocab.generate_ops_coverage", repo_root=repo_root)


def run_op_table(repo_root: Path) -> None:
    common.run_module("book.integration.carton.mappings.op_table.generate_op_table_mappings", repo_root=repo_root)


def run_anchors(repo_root: Path) -> None:
    common.run_module("book.integration.carton.mappings.anchors.generate_anchor_maps", repo_root=repo_root)


def run_tag_layouts(repo_root: Path) -> None:
    common.run_module("book.integration.carton.mappings.tag_layouts.generate_tag_layouts", repo_root=repo_root)
    common.run_module("book.integration.carton.mappings.tag_layouts.generate_tag_u16_roles", repo_root=repo_root)


def run_system_profiles(repo_root: Path) -> None:
    common.run_module("book.integration.carton.mappings.system_profiles.generate_digests_from_ir", repo_root=repo_root)
    common.run_module("book.integration.carton.mappings.system_profiles.generate_attestations", repo_root=repo_root)
    common.run_module("book.integration.carton.mappings.system_profiles.generate_header_contract", repo_root=repo_root)


def run_runtime_promote(repo_root: Path) -> None:
    common.run_module("book.integration.carton.mappings.runtime.promote_from_packets", repo_root=repo_root)


def run_runtime_expectations(repo_root: Path) -> None:
    common.run_module("book.integration.carton.mappings.runtime.generate_expectations", repo_root=repo_root)


def run_runtime_lifecycle(repo_root: Path) -> None:
    common.run_module("book.integration.carton.mappings.runtime.generate_lifecycle", repo_root=repo_root)


def run_runtime_other_inventory(repo_root: Path) -> None:
    common.run_module("book.integration.carton.mappings.runtime.generate_other_runtime_inventory", repo_root=repo_root)


def run_vfs_canonicalization(repo_root: Path) -> None:
    common.run_module(
        "book.integration.carton.mappings.vfs_canonicalization.generate_path_canonicalization_map",
        repo_root=repo_root,
    )
