"""Performance rules — code that makes a charm's hooks slow."""

import ast

from .. import _ast
from .. import _models as models
from ._base import Rule

# Test-suite directory names, wherever they sit in the charm tree.
_TEST_DIRS = frozenset({"tests", "unit_tests", "integration_tests"})

# Importing a Juju framework makes a module charm code, however it is
# invoked, so it is checked even when it reads command-line arguments.
_FRAMEWORKS = ("ops", "charmhelpers", "charms.reactive")


class TimeSleepInCharmSource(Rule):
    """Flag ``time.sleep()`` calls in the charm's own source.

    A hook that sleeps blocks for the whole duration: it burns the hook
    runner's wall-clock budget — exceeding it fails the hook — and delays
    every hook queued behind it. Sleeping is almost always polling for
    something that ``event.defer()`` (retrying on a later dispatch), a
    Pebble check, or a Pebble notice would handle properly.

    Every spelling that resolves to ``time.sleep`` is matched, including
    ``import time as t`` and ``from time import sleep``. A ``time.sleep``
    referenced as a value rather than called, and dynamic lookups such as
    ``getattr(time, "sleep")(1)``, are not; neither are other sleep
    functions — ``asyncio.sleep()``, ``gevent.sleep()`` — that do not
    block the hook runner. Name resolution is module-wide rather than
    scope-aware, so a local name shadowing an imported ``sleep`` — a
    parameter with a ``sleep=sleep`` default, say — is still read as
    ``time.sleep``.

    Only code that runs inside the hook is flagged. Test suites are
    passed over wherever they sit in the charm tree: a ``tests``
    directory under ``src/`` is test infrastructure like the top-level
    ``tests/``. So is a standalone command-line program: a module whose
    own ``__main__`` entry point parses ``sys.argv`` runs as its own
    process — a continuous-writes worker, an observer daemon the charm
    spawns — or is run by hand, and its sleeps do not hold up the hook
    runner. A module that imports the Juju framework is treated as charm
    code even when it reads arguments, and a ``__main__`` guard alone
    does not make a library a program.
    """

    category = "PERFORMANCE"
    number = 1
    name = "time-sleep-in-charm-source"
    description = "time.sleep() in charm source blocks the hook"
    default_severity = models.Severity.WARNING
    reference_url = "https://canonical.com/juju/docs/ops/latest/explanation/defer-guidance/"

    def check(self, context: models.CharmContext) -> list[models.Diagnostic]:
        diagnostics: list[models.Diagnostic] = []
        for module in context.charm_sources():
            if not _is_hook_code(module):
                continue
            imports = _ast.Imports.of(module)
            for call in module.walk(ast.Call):
                if _ast.call_target(call, imports) != "time.sleep":
                    continue
                diagnostics.append(
                    self.diagnostic(
                        "time.sleep() blocks the hook for the whole sleep — the "
                        "hook runner has a wall-clock budget, and every hook "
                        "queued behind this one is delayed",
                        path=module.path,
                        line=call.lineno,
                        fix_hint=(
                            "Handle the condition the sleep waits for directly: "
                            "`event.defer()` to retry on a later dispatch, or a "
                            "Pebble check or notice for a workload condition"
                        ),
                    )
                )
        return diagnostics


def _is_hook_code(module: models.Module) -> bool:
    """Whether *module* is charm code that runs inside the hook.

    Test suites and standalone programs are excluded: neither runs under
    the hook runner, so neither holds up a hook by sleeping.
    """
    if _TEST_DIRS.intersection(module.path.split("/")):
        return False
    return not _is_command_line_program(module)


def _is_command_line_program(module: models.Module) -> bool:
    """Whether *module* is a standalone program rather than hook code.

    A ``__main__`` entry point that parses ``sys.argv`` marks a program
    the charm spawns as its own process — a continuous-writes worker, an
    observer daemon — or one run by hand. A module importing a Juju
    framework is charm code whatever it reads from the command line, and
    a ``__main__`` guard without ``sys.argv`` is a library with a manual
    test hook, so neither counts.
    """
    if not any(_is_main_guard(node) for node in module.walk(ast.If)):
        return False
    imports = _ast.Imports.of(module)
    if any(imports.imports_module(name) for name in _FRAMEWORKS):
        return False
    return any(
        imports.resolve(node) == "sys.argv" for node in module.walk(ast.Attribute, ast.Name)
    )


def _is_main_guard(node: ast.If) -> bool:
    """Whether *node* is the ``__main__`` guard, in either operand order."""
    test = node.test
    if not (
        isinstance(test, ast.Compare)
        and len(test.ops) == 1
        and isinstance(test.ops[0], ast.Eq)
        and len(test.comparators) == 1
    ):
        return False
    sides = (test.left, test.comparators[0])
    names = [side for side in sides if isinstance(side, ast.Name) and side.id == "__name__"]
    mains = [side for side in sides if isinstance(side, ast.Constant) and side.value == "__main__"]
    return len(names) == 1 and len(mains) == 1
