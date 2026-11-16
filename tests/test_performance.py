"""Tests for PERFORMANCE-### rules."""

import pathlib
import textwrap

from charmlint._linter import lint
from charmlint._models import Severity
from tests.conftest import write_charm_source, write_charmcraft_yaml


class TestTimeSleep:
    """PERFORMANCE-001 — time.sleep() in charm source."""

    def test_import_spellings_flagged(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        write_charm_source(
            tmp_charm,
            textwrap.dedent("""\
                import time
                import time as t
                from time import sleep
                from time import sleep as s

                def wait(event):
                    time.sleep(1)
                    t.sleep(1)
                    sleep(1)
                    s(1)
            """),
        )
        report = lint(tmp_charm)
        found = [d for d in report if d.rule_id == "PERFORMANCE-001"]
        assert len(found) == 4
        assert found[0].severity == Severity.WARNING
        assert found[0].path == "src/charm.py"
        assert [d.line for d in found] == [7, 8, 9, 10]
        assert "time.sleep" in found[0].message

    def test_not_flagged_cases(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        write_charm_source(
            tmp_charm,
            textwrap.dedent("""\
                import asyncio
                import time

                callback = time.sleep

                async def wait(event):
                    await asyncio.sleep(1)

                def other(event):
                    sleep(1)

                def stamp(event):
                    print(time.asctime(), time.time())
            """),
        )
        (tmp_charm / "lib" / "charms" / "someone_else" / "v0").mkdir(parents=True)
        (tmp_charm / "lib" / "charms" / "someone_else" / "v0" / "helper.py").write_text(
            textwrap.dedent("""\
                import time

                def wait():
                    time.sleep(1)
            """)
        )
        (tmp_charm / "tests" / "unit").mkdir(parents=True)
        (tmp_charm / "tests" / "unit" / "test_charm.py").write_text(
            textwrap.dedent("""\
                import time

                def test_wait():
                    time.sleep(1)
            """)
        )
        (tmp_charm / "src" / "tests").mkdir()
        (tmp_charm / "src" / "tests" / "target.py").write_text(
            textwrap.dedent("""\
                import time

                def wait_for_state():
                    while True:
                        time.sleep(5)
            """)
        )
        report = lint(tmp_charm)
        assert "PERFORMANCE-001" not in {d.rule_id for d in report}

    def test_script_entry_handling(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        write_charm_source(
            tmp_charm,
            textwrap.dedent("""\
                import time

                def wait():
                    time.sleep(1)

                def main():
                    wait()

                if __name__ == "__main__":
                    main()
            """),
            filename="worker.py",
        )
        write_charm_source(
            tmp_charm,
            textwrap.dedent("""\
                import time

                def wait():
                    time.sleep(1)

                def main():
                    wait()

                def _on_start(event):
                    wait()

                if __name__ == "__main__":
                    main()
            """),
            filename="worker2.py",
        )
        write_charm_source(
            tmp_charm,
            textwrap.dedent("""\
                import ops
                import time

                class C(ops.CharmBase):
                    pass

                def main():
                    time.sleep(1)
                    ops.main(C)

                if __name__ == "__main__":
                    main()
            """),
        )
        (tmp_charm / "src" / "actions").mkdir()
        (tmp_charm / "src" / "actions" / "do-thing.py").write_text(
            textwrap.dedent("""\
                import time

                def main():
                    time.sleep(1)

                if __name__ == "__main__":
                    main()
            """)
        )
        report = lint(tmp_charm)
        found = [d for d in report if d.rule_id == "PERFORMANCE-001"]
        assert {(d.path, d.line) for d in found} == {
            ("src/worker2.py", 4),
            ("src/charm.py", 8),
            ("src/actions/do-thing.py", 4),
        }

    def test_branch_reachability(self, tmp_charm: pathlib.Path):
        write_charmcraft_yaml(tmp_charm, {"name": "test"})
        write_charm_source(
            tmp_charm,
            textwrap.dedent("""\
                import time

                def after_return(event):
                    return
                    time.sleep(1)

                def constant_false(event):
                    retry = False
                    if retry:
                        time.sleep(1)

                def parameter_branch(event, retry=True):
                    if not retry:
                        return
                    time.sleep(1)
            """),
        )
        report = lint(tmp_charm)
        found = [d for d in report if d.rule_id == "PERFORMANCE-001"]
        assert len(found) == 1
        assert found[0].line == 15
