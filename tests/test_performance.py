"""Tests for performance rules."""

import pathlib

from charmlint._linter import lint
from charmlint._models import Severity
from tests.conftest import write_charm_source, write_charmcraft_yaml

_RULE = "PERFORMANCE-001"


def _hits(charm_dir: pathlib.Path) -> list:
    """Return the PERFORMANCE-001 findings for a charm directory."""
    return [d for d in lint(charm_dir) if d.rule_id == _RULE]


class TestTimeSleepInCharmSource:
    """PERFORMANCE-001 — time.sleep() in the charm's own source."""

    def test_time_sleep_flagged_as_warning(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "x"})
        write_charm_source(tmp_charm, "import time\n\n\nprint('waiting')\ntime.sleep(1)\n")
        hits = _hits(tmp_charm)
        assert len(hits) == 1
        assert hits[0].severity == Severity.WARNING
        assert hits[0].path == "src/charm.py"
        assert hits[0].line == 5

    def test_from_time_import_sleep_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "x"})
        write_charm_source(tmp_charm, "from time import sleep\n\n\nprint('waiting')\nsleep(1)\n")
        assert len(_hits(tmp_charm)) == 1

    def test_aliased_module_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "x"})
        write_charm_source(tmp_charm, "import time as t\n\n\nprint('waiting')\nt.sleep(1)\n")
        assert len(_hits(tmp_charm)) == 1

    def test_aliased_from_import_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "x"})
        write_charm_source(tmp_charm, "from time import sleep as s\n\n\nprint('waiting')\ns(1)\n")
        assert len(_hits(tmp_charm)) == 1

    def test_computed_duration_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "x"})
        write_charm_source(
            tmp_charm, "import random\nimport time\n\n\ntime.sleep(random.randint(1, 10))\n"
        )
        assert len(_hits(tmp_charm)) == 1

    def test_multiple_sleeps_all_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "x"})
        write_charm_source(
            tmp_charm, "import time\n\n\nprint('waiting')\ntime.sleep(1)\ntime.sleep(2)\n"
        )
        assert [hit.line for hit in _hits(tmp_charm)] == [5, 6]

    def test_src_lib_helper_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "x"})
        src_lib = tmp_charm / "src" / "lib"
        src_lib.mkdir(parents=True)
        (src_lib / "helper.py").write_text("import time\n\n\nprint('waiting')\ntime.sleep(1)\n")
        hits = _hits(tmp_charm)
        assert len(hits) == 1
        assert hits[0].path == "src/lib/helper.py"

    def test_own_published_lib_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "my-charm"})
        lib = tmp_charm / "lib" / "charms" / "my_charm" / "v0"
        lib.mkdir(parents=True)
        (lib / "helper.py").write_text("import time\n\n\nprint('waiting')\ntime.sleep(1)\n")
        hits = _hits(tmp_charm)
        assert len(hits) == 1
        assert hits[0].path == "lib/charms/my_charm/v0/helper.py"

    def test_main_guard_without_argv_flagged(self, tmp_charm: pathlib.Path):
        # A `__main__` guard alone is a manual test hook on a library, not a
        # program: ceph-nvme's proxy.py is flagged despite having one.
        write_charmcraft_yaml(tmp_charm, {"name": "x"})
        write_charm_source(
            tmp_charm,
            "import time\n\n\ndef wait():\n    time.sleep(0.1)\n\n\n"
            "if __name__ == '__main__':\n    wait()\n",
        )
        assert len(_hits(tmp_charm)) == 1

    def test_command_line_program_importing_ops_flagged(self, tmp_charm: pathlib.Path):
        # Importing a Juju framework makes the module charm code even when it
        # reads command-line arguments.
        write_charmcraft_yaml(tmp_charm, {"name": "x"})
        write_charm_source(
            tmp_charm,
            "import ops\nimport sys\nimport time\n\n\ndef main():\n"
            "    if len(sys.argv) > 1:\n        time.sleep(1)\n\n\n"
            'if __name__ == "__main__":\n    main()\n',
        )
        assert len(_hits(tmp_charm)) == 1

    def test_src_tests_directory_not_flagged(self, tmp_charm: pathlib.Path):
        # A tests directory under src/ is test infrastructure, like the
        # top-level tests/ (ceph-rbd-mirror's src/tests/target.py).
        write_charmcraft_yaml(tmp_charm, {"name": "x"})
        tests = tmp_charm / "src" / "tests"
        tests.mkdir(parents=True)
        (tests / "target.py").write_text("import time\n\n\ntime.sleep(5)\n")
        assert not _hits(tmp_charm)

    def test_command_line_program_not_flagged(self, tmp_charm: pathlib.Path):
        # A program with its own argv-parsing entry point runs as its own
        # process (a continuous-writes worker, an observer daemon), not as
        # the hook.
        write_charmcraft_yaml(tmp_charm, {"name": "x"})
        write_charm_source(
            tmp_charm,
            "import sys\nimport time\n\n\ndef main():\n"
            "    table = sys.argv[1]\n"
            "    while True:\n"
            "        time.sleep(1)\n"
            "        write(table)\n\n\n"
            'if __name__ == "__main__":\n    main()\n',
        )
        assert not _hits(tmp_charm)

    def test_reversed_main_guard_program_not_flagged(self, tmp_charm: pathlib.Path):
        # The guard's operand order is arbitrary; "__main__" == __name__ is
        # the same entry point.
        write_charmcraft_yaml(tmp_charm, {"name": "x"})
        write_charm_source(
            tmp_charm,
            "import sys\nimport time\n\n\n"
            "duration = int(sys.argv[1])\n"
            "time.sleep(duration)\n\n\n"
            'if "__main__" == __name__:\n    pass\n',
        )
        assert not _hits(tmp_charm)

    def test_shadowed_sleep_parameter_flagged(self, tmp_charm: pathlib.Path):
        # A known limitation, pinned here: resolution is module-wide, so a
        # parameter shadowing the imported sleep still reads as time.sleep.
        # Fixing it needs scope-aware analysis in the linter core.
        write_charmcraft_yaml(tmp_charm, {"name": "x"})
        write_charm_source(
            tmp_charm, "from time import sleep\n\n\ndef f(sleep=sleep):\n    sleep(1)\n"
        )
        assert len(_hits(tmp_charm)) == 1

    def test_uncalled_reference_not_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "x"})
        write_charm_source(tmp_charm, "import time\n\n\ncallback = time.sleep\n")
        assert not _hits(tmp_charm)

    def test_dynamic_lookup_not_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "x"})
        write_charm_source(tmp_charm, "import time\n\n\ngetattr(time, 'sleep')(1)\n")
        assert not _hits(tmp_charm)

    def test_asyncio_sleep_not_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "x"})
        write_charm_source(tmp_charm, "import asyncio\n\n\nasyncio.sleep(1)\n")
        assert not _hits(tmp_charm)

    def test_gevent_sleep_not_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "x"})
        write_charm_source(tmp_charm, "import gevent\n\n\ngevent.sleep(1)\n")
        assert not _hits(tmp_charm)

    def test_vendored_lib_not_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "my-charm"})
        lib = tmp_charm / "lib" / "charms" / "someone" / "v0"
        lib.mkdir(parents=True)
        (lib / "helper.py").write_text("import time\n\n\ntime.sleep(1)\n")
        assert not _hits(tmp_charm)

    def test_tests_not_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "x"})
        tests = tmp_charm / "tests" / "unit"
        tests.mkdir(parents=True)
        (tests / "test_charm.py").write_text("import time\n\n\ntime.sleep(1)\n")
        assert not _hits(tmp_charm)

    def test_charm_without_sleep_not_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "x"})
        write_charm_source(tmp_charm, "import time\n\n\nprint(time.time())\n")
        assert not _hits(tmp_charm)
