"""Tests for charmlint rules.

Only METADATA-relevant tests live here during the rules-refactor; the
other rule families get their own test modules as they are re-added.
"""

import collections
import pathlib
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

from charmlint._linter import lint
from charmlint._models import Severity
from charmlint._rules._base import get_all_rules
from tests.conftest import make_full_charm, write_charm_source, write_charmcraft_yaml

_RULES_WITH_URL = sorted(
    (r for r in get_all_rules().values() if r.reference_url is not None),
    key=lambda r: r.id,
)


def _rules_by_page() -> dict[str, list[str]]:
    """Map each distinct page to the rules citing it.

    A `#fragment` never reaches the server, so several rules pointing at
    different anchors of one page are a single request. Collapsing them
    keeps the suite from hammering the same host once per rule.
    """
    pages: dict[str, list[str]] = collections.defaultdict(list)
    for rule in _RULES_WITH_URL:
        assert rule.reference_url is not None
        page, _ = urllib.parse.urldefrag(rule.reference_url)
        pages[page].append(rule.id)
    return dict(pages)


_REFERENCE_PAGES = sorted(_rules_by_page().items())


class TestMetadataRules:
    """Tests for metadata field checks."""

    def test_missing_name_is_error(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"display-name": "X"})
        report = lint(tmp_charm)
        ids = {d.rule_id for d in list(report)}
        assert "METADATA-001" in ids
        meta001 = [d for d in list(report) if d.rule_id == "METADATA-001"][0]
        assert meta001.severity == Severity.ERROR

    def test_full_metadata_no_meta_diagnostics(self, tmp_charm: pathlib.Path):
        make_full_charm(tmp_charm)
        report = lint(tmp_charm)
        meta_ids = {d.rule_id for d in list(report) if d.rule_id.startswith("METADATA")}
        assert not meta_ids

    def test_meta_diagnostics_path_is_charmcraft_yaml(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"display-name": "X"})
        report = lint(tmp_charm)
        meta001 = [d for d in list(report) if d.rule_id == "METADATA-001"][0]
        assert meta001.path == "charmcraft.yaml"

    def test_meta_diagnostics_path_is_metadata_yaml_for_legacy_charms(
        self, tmp_charm: pathlib.Path
    ):
        (tmp_charm / "metadata.yaml").write_text("display-name: X\n")
        report = lint(tmp_charm)
        meta001 = [d for d in list(report) if d.rule_id == "METADATA-001"][0]
        assert meta001.path == "metadata.yaml"

    def test_bare_metadata_fires_all_completeness_rules(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test-charm"})
        report = lint(tmp_charm)
        ids = {d.rule_id for d in list(report)}
        for rid in (
            "METADATA-002",
            "METADATA-003",
            "METADATA-004",
            "METADATA-005",
            "METADATA-006",
            "METADATA-007",
        ):
            assert rid in ids, f"{rid} should fire when the field is missing"

    def test_legacy_fields_in_charmcraft_yaml_do_not_satisfy_meta(self, tmp_charm: pathlib.Path):
        # Legacy metadata.yaml key names in charmcraft.yaml are the wrong spelling
        # for that file — the checks should still fire even though the info is
        # technically present.
        write_charmcraft_yaml(
            tmp_charm,
            {
                "name": "test-charm",
                "display-name": "Test Charm",
                "summary": "x",
                "description": "x",
                "docs": "https://example.com/docs",
                "issues": "https://example.com/issues",
                "source": "https://example.com/source",
            },
        )
        report = lint(tmp_charm)
        ids = {d.rule_id for d in list(report)}
        for rid in ("METADATA-002", "METADATA-005", "METADATA-006", "METADATA-007"):
            assert rid in ids, f"{rid} should fire — key belongs in metadata.yaml, not here"
        for rid in ("METADATA-003", "METADATA-004"):
            assert rid not in ids, f"{rid} accepts the same key in both files"

    def test_modern_fields_in_metadata_yaml_do_not_satisfy_meta(self, tmp_charm: pathlib.Path):
        # Modern charmcraft.yaml key names in metadata.yaml are the wrong spelling
        # for that file — the checks should still fire.
        (tmp_charm / "metadata.yaml").write_text(
            "name: test-charm\n"
            "title: Test Charm\n"
            "summary: x\n"
            "description: x\n"
            "links:\n"
            "  documentation: https://example.com/docs\n"
            "  issues: https://example.com/issues\n"
            "  source: https://example.com/source\n"
        )
        report = lint(tmp_charm)
        ids = {d.rule_id for d in list(report)}
        for rid in ("METADATA-002", "METADATA-005", "METADATA-006", "METADATA-007"):
            assert rid in ids, f"{rid} should fire — key belongs in charmcraft.yaml, not here"

    def test_legacy_fields_in_metadata_yaml_satisfy_meta(self, tmp_charm: pathlib.Path):
        (tmp_charm / "metadata.yaml").write_text(
            "name: test-charm\n"
            "display-name: Test Charm\n"
            "summary: x\n"
            "description: x\n"
            "docs: https://example.com/docs\n"
            "issues: https://example.com/issues\n"
            "source: https://example.com/source\n"
        )
        report = lint(tmp_charm)
        ids = {d.rule_id for d in list(report)}
        for rid in (
            "METADATA-002",
            "METADATA-003",
            "METADATA-004",
            "METADATA-005",
            "METADATA-006",
            "METADATA-007",
        ):
            assert rid not in ids, f"{rid} should not fire for legacy metadata.yaml fields"

    def test_modern_charmcraft_title_and_links_satisfy_meta(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(
            tmp_charm,
            {
                "name": "test-charm",
                "title": "Test Charm",
                "summary": "x",
                "description": "x",
                "links": {
                    "documentation": "https://example.com/docs",
                    "issues": "https://example.com/issues",
                    "source": "https://example.com/source",
                },
            },
        )
        report = lint(tmp_charm)
        ids = {d.rule_id for d in list(report)}
        for rid in (
            "METADATA-002",
            "METADATA-005",
            "METADATA-006",
            "METADATA-007",
        ):
            assert rid not in ids, f"{rid} should not fire for modern charmcraft.yaml"

    def test_bundle_skips_metadata_rules(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"type": "bundle", "name": "my-bundle"})
        report = lint(tmp_charm)
        meta_ids = {d.rule_id for d in list(report) if d.rule_id.startswith("METADATA")}
        assert not meta_ids

    def test_legacy_bundle_yaml_skips_metadata_rules(self, tmp_charm: pathlib.Path):
        # A charmcraft.yaml that doesn't say ``type: bundle``: the bundle.yaml
        # beside it is what marks the directory as a bundle.
        write_charmcraft_yaml(tmp_charm, {"description": "A bundle."})
        without = {d.rule_id for d in lint(tmp_charm)}
        assert "METADATA-001" in without
        (tmp_charm / "bundle.yaml").write_text("applications: {}\n")
        report = list(lint(tmp_charm))
        assert "FATAL" not in {d.rule_id for d in report}
        assert not {d.rule_id for d in report if d.rule_id.startswith("METADATA")}


class TestDocumentationRules:
    """Tests for documentation presence rules."""

    def test_no_readme(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        report = lint(tmp_charm)
        assert "DOCUMENTATION-001" in {d.rule_id for d in report}

    @pytest.mark.parametrize(
        "filename",
        ["README.md", "README.txt", "README.rst", "readme.md", "Readme.MD", "README.RST"],
    )
    def test_readme_present(self, tmp_charm: pathlib.Path, filename: str):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        (tmp_charm / filename).write_text("# Hello\n")
        report = lint(tmp_charm)
        assert "DOCUMENTATION-001" not in {d.rule_id for d in report}

    @pytest.mark.parametrize("filename", ["README.org", "README", "README.markdown"])
    def test_readme_unsupported_extension(self, tmp_charm: pathlib.Path, filename: str):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        (tmp_charm / filename).write_text("# Hello\n")
        report = lint(tmp_charm)
        assert "DOCUMENTATION-001" in {d.rule_id for d in report}


# A documentation host may throttle or hiccup; that is not a broken
# reference. Only a settled non-2xx answer counts as a failure.
_TRANSIENT_CODES = frozenset({408, 429, 500, 502, 503, 504})


def _fetch_status(url: str) -> int:
    """Return the HTTP status for *url*, retrying transient answers."""
    for attempt in range(3):
        try:
            request = urllib.request.Request(url, method="HEAD")  # ruff: ignore[suspicious-url-open-usage]
            with urllib.request.urlopen(request, timeout=10) as response:  # ruff: ignore[suspicious-url-open-usage]
                return response.status
        except urllib.error.HTTPError as exc:
            if exc.code == 405:
                # HEAD not allowed — retry with GET.
                with urllib.request.urlopen(url, timeout=10) as response:  # ruff: ignore[suspicious-url-open-usage]
                    return response.status
            if exc.code not in _TRANSIENT_CODES or attempt == 2:
                raise
        except (urllib.error.URLError, TimeoutError):
            if attempt == 2:
                raise
        time.sleep(2**attempt)
    raise AssertionError("unreachable")


@pytest.mark.network
class TestReferenceUrls:
    """Every rule with a reference_url must point somewhere live."""

    @pytest.mark.parametrize(("page", "rule_ids"), _REFERENCE_PAGES, ids=lambda v: v)
    def test_reference_url_resolves(self, page: str, rule_ids: list[str]):
        status = _fetch_status(page)
        cited_by = ", ".join(rule_ids)
        assert 200 <= status < 300, f"{cited_by}: {page} → HTTP {status}"


class TestStructureRules:
    """Tests for structure rules."""

    def test_no_licence(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        report = lint(tmp_charm)
        assert "STRUCTURE-001" in {d.rule_id for d in report}

    @pytest.mark.parametrize("name", ["LICENSE", "LICENCE"])
    def test_licence_present_no_diagnostic(self, tmp_charm: pathlib.Path, name: str):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        (tmp_charm / name).write_text("Apache-2.0\n")
        report = lint(tmp_charm)
        assert "STRUCTURE-001" not in {d.rule_id for d in report}

    def test_both_licence_spellings_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        (tmp_charm / "LICENSE").write_text("Apache-2.0\n")
        (tmp_charm / "LICENCE").write_text("Apache-2.0\n")
        report = lint(tmp_charm)
        str001 = [d for d in report if d.rule_id == "STRUCTURE-001"]
        assert len(str001) == 1
        assert "both" in str001[0].message.lower()

    def test_empty_licence_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        (tmp_charm / "LICENSE").write_text("")
        report = lint(tmp_charm)
        assert "STRUCTURE-001" in {d.rule_id for d in report}

    def test_licence_directory_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        (tmp_charm / "LICENSE").mkdir()
        report = lint(tmp_charm)
        assert "STRUCTURE-001" in {d.rule_id for d in report}

    def test_no_icon(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        report = lint(tmp_charm)
        assert "STRUCTURE-002" in {d.rule_id for d in report}

    def test_icon_present_no_diagnostic(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        (tmp_charm / "icon.svg").write_text('<svg xmlns="http://www.w3.org/2000/svg"/>\n')
        report = lint(tmp_charm)
        assert "STRUCTURE-002" not in {d.rule_id for d in report}

    def test_empty_icon_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        (tmp_charm / "icon.svg").write_text("")
        report = lint(tmp_charm)
        assert "STRUCTURE-002" in {d.rule_id for d in report}

    def test_icon_directory_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        (tmp_charm / "icon.svg").mkdir()
        report = lint(tmp_charm)
        assert "STRUCTURE-002" in {d.rule_id for d in report}

    def test_no_type_annotations(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        write_charm_source(
            tmp_charm,
            """\
import ops


class Charm(ops.CharmBase):
    def __init__(self, framework):
        super().__init__(framework)

    def _on_start(self, event):
        self.unit.status = ops.ActiveStatus()
""",
        )
        annotations = [d for d in lint(tmp_charm) if d.rule_id == "STRUCTURE-003"]
        assert len(annotations) == 1
        assert annotations[0].severity == Severity.INFO

    @pytest.mark.parametrize(
        "source",
        [
            pytest.param("def handle(event) -> None:\n    pass\n", id="return"),
            pytest.param("def handle(event: object):\n    pass\n", id="parameter"),
            pytest.param("def handle(*args: int):\n    pass\n", id="vararg"),
            pytest.param("def handle(**kwargs: int):\n    pass\n", id="kwarg"),
            pytest.param("def handle(event: object, /):\n    pass\n", id="positional-only"),
            pytest.param("def handle(*, event: object):\n    pass\n", id="keyword-only"),
            pytest.param("async def handle(event) -> None:\n    pass\n", id="async"),
            pytest.param("PORT: int = 8080\n\n\ndef handle(event):\n    pass\n", id="assign"),
        ],
    )
    def test_annotations_present_no_diagnostic(self, tmp_charm: pathlib.Path, source: str):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        write_charm_source(tmp_charm, source)
        assert "STRUCTURE-003" not in {d.rule_id for d in lint(tmp_charm)}

    def test_no_functions_no_diagnostic(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        write_charm_source(tmp_charm, "PORT = 8080\n")
        assert "STRUCTURE-003" not in {d.rule_id for d in lint(tmp_charm)}

    def test_no_charm_source_no_diagnostic(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        assert "STRUCTURE-003" not in {d.rule_id for d in lint(tmp_charm)}

    def test_vendored_library_annotations_do_not_count(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        write_charm_source(tmp_charm, "def handle(event):\n    pass\n")
        vendored = tmp_charm / "lib" / "charms" / "other_charm" / "v0"
        vendored.mkdir(parents=True)
        (vendored / "thing.py").write_text("def handle(event: object) -> None:\n    pass\n")
        assert "STRUCTURE-003" in {d.rule_id for d in lint(tmp_charm)}

    def test_owned_library_annotations_count(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test-charm"})
        write_charm_source(tmp_charm, "def handle(event):\n    pass\n")
        owned = tmp_charm / "lib" / "charms" / "test_charm" / "v0"
        owned.mkdir(parents=True)
        (owned / "thing.py").write_text("def handle(event: object) -> None:\n    pass\n")
        assert "STRUCTURE-003" not in {d.rule_id for d in lint(tmp_charm)}

    def test_test_annotations_do_not_count(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        write_charm_source(tmp_charm, "def handle(event):\n    pass\n")
        unit = tmp_charm / "tests" / "unit"
        unit.mkdir(parents=True)
        (unit / "test_charm.py").write_text("def test_thing() -> None:\n    pass\n")
        assert "STRUCTURE-003" in {d.rule_id for d in lint(tmp_charm)}

    @pytest.mark.parametrize(
        ("call",),
        [
            pytest.param('subprocess.run(["systemctl", "restart", "demo"])', id="subprocess"),
            pytest.param('os.system("systemctl restart demo")', id="os.system"),
            pytest.param('os.popen("systemctl restart demo")', id="os.popen"),
            pytest.param('os.execvp("demo", ["demo", "--restart"])', id="os.execvp"),
            pytest.param('os.spawnve(os.P_WAIT, "demo", ["demo"], os.environ)', id="os.spawnve"),
            pytest.param('os.posix_spawn("demo", ["demo", "--restart"], os.environ)', id="posix"),
        ],
    )
    def test_helper_module_host_commands_flagged(self, tmp_charm: pathlib.Path, call: str):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        write_charm_source(
            tmp_charm,
            f"""\
import subprocess
import os

import ops


def restart() -> None:
    {call}
""",
            filename="helper.py",
        )
        diagnostics = [d for d in lint(tmp_charm) if d.rule_id == "STRUCTURE-004"]
        assert len(diagnostics) == 1
        assert diagnostics[0].severity == Severity.INFO
        assert diagnostics[0].path == "src/helper.py"

    def test_workload_command_via_variable_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        write_charm_source(
            tmp_charm,
            """\
import subprocess

import ops


def restart() -> ops.BlockedStatus:
    cmd = ["systemctl", "restart", "demo"]
    subprocess.run(cmd)
    return ops.BlockedStatus("restart failed")
""",
            filename="helper.py",
        )
        diagnostics = [d for d in lint(tmp_charm) if d.rule_id == "STRUCTURE-004"]
        assert len(diagnostics) == 1
        assert diagnostics[0].path == "src/helper.py"

    def test_star_imported_ops_with_host_command_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        write_charm_source(
            tmp_charm,
            """\
import subprocess

from ops import *


def restart() -> None:
    subprocess.run(["systemctl", "restart", "demo"])
""",
            filename="helper.py",
        )
        diagnostics = [d for d in lint(tmp_charm) if d.rule_id == "STRUCTURE-004"]
        assert len(diagnostics) == 1
        assert diagnostics[0].path == "src/helper.py"

    def test_helper_module_container_exec_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        write_charm_source(
            tmp_charm,
            """\
import ops


class Backup(ops.Object):
    def run(self) -> None:
        self.container.exec(["rm", "-r", "/tmp/backup"]).wait_output()
""",
            filename="helper.py",
        )
        diagnostics = [d for d in lint(tmp_charm) if d.rule_id == "STRUCTURE-004"]
        assert len(diagnostics) == 1
        assert diagnostics[0].path == "src/helper.py"

    def test_helper_module_chained_container_exec_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        write_charm_source(
            tmp_charm,
            """\
import ops


class Backup(ops.Object):
    def run(self) -> None:
        self.unit.get_container("backup").exec(["rm", "-r", "/tmp/backup"]).wait_output()
""",
            filename="helper.py",
        )
        diagnostics = [d for d in lint(tmp_charm) if d.rule_id == "STRUCTURE-004"]
        assert len(diagnostics) == 1
        assert diagnostics[0].path == "src/helper.py"

    def test_entrypoint_host_commands_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        write_charm_source(
            tmp_charm,
            """\
import subprocess

import ops


class Charm(ops.CharmBase):
    def _on_install(self, event: ops.InstallEvent) -> None:
        subprocess.check_output(["lsb_release", "-r", "-s"])


if __name__ == "__main__":
    ops.main(Charm)
""",
        )
        diagnostics = [d for d in lint(tmp_charm) if d.rule_id == "STRUCTURE-004"]
        assert len(diagnostics) == 1
        assert diagnostics[0].path == "src/charm.py"
        assert "entrypoint" in diagnostics[0].message

    def test_configured_entrypoint_and_sibling_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(
            tmp_charm,
            {"name": "test", "parts": {"charm": {"charm-entrypoint": "src/myapp.py"}}},
        )
        source = """\
import subprocess

import ops


def restart() -> None:
    subprocess.check_output(["systemctl", "restart", "demo"])
"""
        write_charm_source(tmp_charm, source, filename="myapp.py")
        write_charm_source(tmp_charm, source, filename="helper.py")
        diagnostics = [d for d in lint(tmp_charm) if d.rule_id == "STRUCTURE-004"]
        assert len(diagnostics) == 2
        assert {d.path for d in diagnostics} == {"src/myapp.py", "src/helper.py"}

    def test_ops_main_module_host_commands_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        write_charm_source(
            tmp_charm,
            """\
import subprocess

import ops


class Charm(ops.CharmBase):
    def _on_install(self, event: ops.InstallEvent) -> None:
        subprocess.check_output(["lsb_release", "-r", "-s"])


if __name__ == "__main__":
    ops.main(Charm)
""",
            filename="k8s_charm.py",
        )
        diagnostics = [d for d in lint(tmp_charm) if d.rule_id == "STRUCTURE-004"]
        assert len(diagnostics) == 1
        assert diagnostics[0].path == "src/k8s_charm.py"
        assert "entrypoint" in diagnostics[0].message

    def test_ops_module_without_workload_not_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        write_charm_source(
            tmp_charm,
            """\
import ops


def blocked(message: str) -> ops.BlockedStatus:
    return ops.BlockedStatus(message)
""",
            filename="helper.py",
        )
        assert "STRUCTURE-004" not in {d.rule_id for d in lint(tmp_charm)}

    def test_os_environment_not_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        write_charm_source(
            tmp_charm,
            """\
import os

import ops


def path() -> str:
    return os.environ.get("PATH", "")
""",
            filename="helper.py",
        )
        assert "STRUCTURE-004" not in {d.rule_id for d in lint(tmp_charm)}

    def test_subprocess_module_without_ops_not_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        write_charm_source(
            tmp_charm,
            """\
import subprocess


def restart() -> None:
    subprocess.run(["systemctl", "restart", "demo"])
""",
            filename="helper.py",
        )
        assert "STRUCTURE-004" not in {d.rule_id for d in lint(tmp_charm)}

    def test_exception_types_not_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        write_charm_source(
            tmp_charm,
            """\
import subprocess

import ops


def restart() -> ops.BlockedStatus:
    try:
        pass
    except subprocess.CalledProcessError as error:
        raise subprocess.CalledProcessError(error.returncode, error.cmd) from error
""",
            filename="helper.py",
        )
        assert "STRUCTURE-004" not in {d.rule_id for d in lint(tmp_charm)}

    def test_workload_exec_wrapper_not_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        write_charm_source(
            tmp_charm,
            """\
import ops


class Backup(ops.Object):
    def run(self) -> None:
        self.workload.exec(["rm", "-r", "/tmp/backup"])
""",
            filename="helper.py",
        )
        assert "STRUCTURE-004" not in {d.rule_id for d in lint(tmp_charm)}

    def test_entrypoint_container_exec_not_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        write_charm_source(
            tmp_charm,
            """\
import ops


class Charm(ops.CharmBase):
    def _on_pebble_ready(self, event: ops.PebbleReadyEvent) -> None:
        container = self.unit.get_container("demo")
        container.exec(["demo", "--init"]).wait_output()
""",
        )
        assert "STRUCTURE-004" not in {d.rule_id for d in lint(tmp_charm)}

    def test_ops_main_module_container_exec_not_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        write_charm_source(
            tmp_charm,
            """\
import ops


class Charm(ops.CharmBase):
    def _on_pebble_ready(self, event: ops.PebbleReadyEvent) -> None:
        self.container.exec(["demo", "--init"]).wait_output()


if __name__ == "__main__":
    ops.main(Charm)
""",
            filename="k8s_charm.py",
        )
        assert "STRUCTURE-004" not in {d.rule_id for d in lint(tmp_charm)}

    def test_juju_hook_tools_not_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        write_charm_source(
            tmp_charm,
            """\
import json
import subprocess

import ops


def relation_ids(reltype: str) -> list[str]:
    cmd_line = ["relation-ids", "--format=json", reltype]
    return json.loads(subprocess.check_output(cmd_line))


def relation_list(relid: str) -> list[str]:
    return subprocess.run(args=["relation-list", "--format=json", "-r", relid])


def log(message: str) -> None:
    subprocess.check_call(["juju-log", message])


def ready() -> ops.ActiveStatus:
    return ops.ActiveStatus()
""",
            filename="helper.py",
        )
        assert "STRUCTURE-004" not in {d.rule_id for d in lint(tmp_charm)}

    def test_command_via_helper_module_not_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        write_charm_source(
            tmp_charm,
            """\
import util

import ops


class Charm(ops.CharmBase):
    def _on_install(self, event: ops.InstallEvent) -> None:
        util.run(["systemctl", "restart", "demo"])
""",
        )
        write_charm_source(
            tmp_charm,
            """\
import subprocess


def run(args: list[str]) -> None:
    subprocess.run(args)
""",
            filename="util.py",
        )
        assert "STRUCTURE-004" not in {d.rule_id for d in lint(tmp_charm)}

    def test_libraries_and_tests_out_of_scope(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test-charm"})
        source = """\
import subprocess

import ops


def restart() -> None:
    subprocess.run(["systemctl", "restart", "demo"])
"""
        owned = tmp_charm / "lib" / "charms" / "test_charm" / "v0"
        owned.mkdir(parents=True)
        (owned / "thing.py").write_text(source)
        unit = tmp_charm / "tests" / "unit"
        unit.mkdir(parents=True)
        (unit / "test_thing.py").write_text(source)
        assert "STRUCTURE-004" not in {d.rule_id for d in lint(tmp_charm)}


class TestTestingRules:
    """Tests for TESTING-001 — no unit tests found."""

    def test_no_unit_tests_is_warning(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test-charm"})
        report = lint(tmp_charm)
        testing = [d for d in list(report) if d.rule_id == "TESTING-001"]
        assert len(testing) == 1
        assert testing[0].severity == Severity.WARNING
        assert testing[0].path == "tests/unit/"

    def test_unit_tests_present_no_diagnostic(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test-charm"})
        (tmp_charm / "tests" / "unit").mkdir(parents=True)
        (tmp_charm / "tests" / "unit" / "test_charm.py").write_text("def test_x(): pass\n")
        report = lint(tmp_charm)
        assert "TESTING-001" not in {d.rule_id for d in list(report)}

    def test_reactive_unit_tests_layout_no_diagnostic(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test-charm"})
        (tmp_charm / "unit_tests").mkdir()
        (tmp_charm / "unit_tests" / "test_charm.py").write_text("def test_x(): pass\n")
        report = lint(tmp_charm)
        assert "TESTING-001" not in {d.rule_id for d in list(report)}

    def test_nested_unit_tests_no_diagnostic(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test-charm"})
        nested = tmp_charm / "tests" / "unit" / "test_workload"
        nested.mkdir(parents=True)
        (nested / "test_thing.py").write_text("def test_x(): pass\n")
        report = lint(tmp_charm)
        assert "TESTING-001" not in {d.rule_id for d in list(report)}


def _vendor_lib(charm_dir: pathlib.Path, owner: str, version: str, lib: str) -> pathlib.Path:
    """Simulate ``charmcraft fetch-lib`` by dropping a stub into lib/charms/."""
    lib_dir = charm_dir / "lib" / "charms" / owner / version
    lib_dir.mkdir(parents=True)
    path = lib_dir / f"{lib}.py"
    path.write_text('"""stub"""\n')
    return path


class TestLibraryRules:
    """Tests for vendored charm-library detection."""

    @pytest.mark.parametrize(
        ("owner", "version", "lib", "expected_pkg"),
        [
            (
                "tls_certificates_interface",
                "v3",
                "tls_certificates",
                "charmlibs-interfaces-tls-certificates",
            ),
            ("hydra", "v0", "oauth", "charmlibs-interfaces-oauth"),
            ("traefik_k8s", "v2", "forward_auth", "charmlibs-interfaces-forward-auth"),
            ("openfga_k8s", "v1", "openfga", "charmlibs-interfaces-openfga"),
            ("istio_beacon_k8s", "v0", "service_mesh", "charmlibs-interfaces-service-mesh"),
        ],
    )
    def test_interface_libs_flagged(
        self,
        tmp_charm: pathlib.Path,
        owner: str,
        version: str,
        lib: str,
        expected_pkg: str,
    ):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        lib_path = _vendor_lib(tmp_charm, owner, version, lib)
        report = lint(tmp_charm)
        lib001 = [d for d in report if d.rule_id == "LIBRARY-001"]
        assert len(lib001) == 1
        assert expected_pkg in lib001[0].message
        assert lib001[0].severity == Severity.WARNING
        assert lib001[0].path == str(lib_path)
        assert lib001[0].fix_hint is not None
        assert f"uv add {expected_pkg}" in lib001[0].fix_hint

    def test_operator_libs_linux_submodule_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        _vendor_lib(tmp_charm, "operator_libs_linux", "v0", "apt")
        report = lint(tmp_charm)
        lib001 = [d for d in report if d.rule_id == "LIBRARY-001"]
        assert len(lib001) == 1
        assert "charmlibs-apt" in lib001[0].message

    def test_general_lib_flagged_regardless_of_owner(self, tmp_charm: pathlib.Path):
        # rollingops ships under the rolling_ops charm, not operator_libs_linux,
        # so it exercises the owner-agnostic general mapping.
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        _vendor_lib(tmp_charm, "rolling_ops", "v0", "rollingops")
        report = lint(tmp_charm)
        lib001 = [d for d in report if d.rule_id == "LIBRARY-001"]
        assert len(lib001) == 1
        assert "charmlibs-rollingops" in lib001[0].message

    def test_unknown_operator_libs_linux_submodule_not_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        _vendor_lib(tmp_charm, "operator_libs_linux", "v0", "notreal")
        report = lint(tmp_charm)
        assert "LIBRARY-001" not in {d.rule_id for d in report}

    def test_unmapped_charm_lib_not_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        _vendor_lib(tmp_charm, "some_random_charm", "v0", "some_lib")
        report = lint(tmp_charm)
        assert "LIBRARY-001" not in {d.rule_id for d in report}

    def test_multiple_versions_reported_separately(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        _vendor_lib(tmp_charm, "operator_libs_linux", "v0", "apt")
        _vendor_lib(tmp_charm, "operator_libs_linux", "v1", "apt")
        report = lint(tmp_charm)
        assert len([d for d in report if d.rule_id == "LIBRARY-001"]) == 2

    def test_no_lib_dir_no_diagnostics(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        report = lint(tmp_charm)
        assert "LIBRARY-001" not in {d.rule_id for d in report}


class TestFullCharm:
    """Integration test — a well-formed charm should have minimal diagnostics."""

    def test_full_charm_minimal_issues(self, tmp_charm: pathlib.Path):
        make_full_charm(tmp_charm)
        report = lint(tmp_charm)
        assert report.error_count == 0
        for d in list(report):
            assert d.severity != Severity.ERROR, f"Unexpected error: {d.rule_id} {d.message}"
