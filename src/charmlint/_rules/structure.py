"""Structure rules — charm directory structure and required files."""

import ast
import pathlib

from .. import _ast
from .. import _models as models
from ._base import Rule
from .charmcraft_compat import _entrypoint


def _is_valid_licence(path: pathlib.Path) -> bool:
    return path.is_file() and path.stat().st_size > 0


class NoLicence(Rule):
    """Check that the charm ships a licence file.

    Charm source is published for people to read, fork and fix, and
    without a licence file none of them know on what terms they may.

    ``LICENSE`` and ``LICENCE`` are both accepted, but only at the
    charm root and only spelled in upper case — a ``COPYING``, a
    ``LICENSE.txt``, or a licence kept under ``docs/`` is not
    recognised. An empty file is not a licence either. Shipping *both*
    spellings is reported in its own right: two files invite the two
    drifting apart, and leave a reader guessing which one governs.
    """

    category = "STRUCTURE"
    number = 1
    name = "no-licence"
    description = "No LICENSE/LICENCE file found"
    default_severity = models.Severity.INFO

    def check(self, context: models.CharmContext) -> list[models.Diagnostic]:
        # LICENSE (US) and LICENCE (UK) are both accepted.
        valid = [
            name for name in ("LICENSE", "LICENCE") if _is_valid_licence(context.charm_dir / name)
        ]
        if not valid:
            return [self.diagnostic(self.description)]
        if len(valid) == 2:
            return [self.diagnostic("Both LICENSE and LICENCE files present; keep only one.")]
        return []


class NoIcon(Rule):
    """Check that the charm ships an ``icon.svg``.

    The icon is how the charm is recognised on Charmhub; a charm
    without one is shown under a placeholder, alongside every other
    charm that skipped it.

    The file has to be at the charm root, named exactly ``icon.svg``,
    and non-empty — a zero-byte placeholder is reported as though it
    were missing. Nothing inside the SVG is examined: dimensions and
    viewBox are charmcraft's business, not this rule's.
    """

    category = "STRUCTURE"
    number = 2
    name = "no-icon"
    description = "No icon.svg found"
    default_severity = models.Severity.INFO
    reference_url = (
        "https://canonical.com/juju/docs/charmcraft/stable/reference/files/icon-svg-file/"
    )

    def check(self, context: models.CharmContext) -> list[models.Diagnostic]:
        icon = context.charm_dir / "icon.svg"
        if not icon.is_file() or icon.stat().st_size == 0:
            return [self.diagnostic(self.description)]
        return []


class NoTypeAnnotations(Rule):
    """Check that the charm's own source uses type annotations at all.

    Annotations are what let a type checker catch a wrong event type, a
    misspelt attribute or a ``None`` that was never handled before the
    charm is deployed. A charm with none at all gets no help from one.

    The rule reports once per charm, not once per function. Any
    annotation passes: a return type, a parameter, or an annotated
    assignment. Only the charm's own source counts. That is ``src/`` plus
    any library the charm publishes, but not a vendored copy of someone
    else's library, and not the tests. A charm with no functions has
    nothing to annotate and is not reported.
    """

    category = "STRUCTURE"
    number = 3
    name = "no-type-annotations"
    description = "No type annotations found in charm source"
    default_severity = models.Severity.INFO

    def check(self, context: models.CharmContext) -> list[models.Diagnostic]:
        sources = list(context.charm_sources())
        if not any(any(module.functions()) for module in sources):
            # No charm code, or no functions in it: nothing to annotate, so
            # the rule has nothing to say.
            return []
        if any(_uses_annotations(module) for module in sources):
            return []
        return [
            self.diagnostic(
                self.description,
                fix_hint="Annotate function parameters and return types, and run a type checker.",
            )
        ]


class WorkloadWorkInOpsModule(Rule):
    """Check that charm logic and the commands that do the work are in
    separate modules.

    A charm's ``src/`` modules each play one of two parts. The entrypoint
    and its helpers observe events, map configuration to arguments and
    report status; workload modules run the commands that actually change
    the system. Keeping the two apart is what lets the charm's tests mock
    the workload module instead of intercepting ``subprocess`` or Pebble,
    and keeps each module readable as the one thing it is.

    A module under ``src/`` — other than an entrypoint — is reported when
    it imports ``ops`` and also runs the workload itself: a ``subprocess``
    or command-running ``os`` call, or ``container.exec``. An entrypoint is
    the file charmcraft designates, plus any module that calls
    ``ops.main()``: a charm can keep a Kubernetes and a machine charm
    beside each other and pick between them at dispatch. Entrypoints are
    reported when they run host commands (``subprocess``/``os``) themselves;
    driving Pebble from an entrypoint is what an entrypoint is for, so
    ``container.exec`` there is not a finding.

    Much is deliberately passed over. A module that imports ``ops`` only
    for event, status or exception types is fine, and so is a module that
    runs commands without ever importing ``ops`` — that separation is the
    shape the rule asks for. Exception types and constants
    (``subprocess.CalledProcessError``, ``os.environ``) are not calls and
    never count, and neither do ``subprocess`` calls that run a Juju hook
    tool (``relation-ids``, ``juju-log``, ``config-get``, ...) — those talk
    to Juju rather than the workload, whether the command line is written
    at the call or bound to a name first. Commands issued through an
    intermediate helper module are not followed across modules. An ``exec``
    on a receiver that is neither named ``container``/``*_container`` nor
    a ``get_container(...)`` result — the data-platform ``workload.exec``
    wrappers — is a different idiom and is left alone. Only ``src/`` is
    examined: charm libraries and tests are out of scope, and so is an
    entrypoint charmcraft designates outside it.
    """

    category = "STRUCTURE"
    number = 4
    name = "workload-work-in-ops-module"
    description = "Module imports ops and runs workload commands itself"
    default_severity = models.Severity.INFO
    reference_url = (
        "https://canonical.com/juju/docs/charmcraft/stable/reference/files/"
        "charmcraft-yaml-file/#charmcraft-yaml-key-parts-charm-charm-entrypoint"
    )

    def check(self, context: models.CharmContext) -> list[models.Diagnostic]:
        entrypoint = _entrypoint(context)
        diagnostics: list[models.Diagnostic] = []
        for module in context.modules(models.Scope.SRC):
            imports = _ast.Imports.of(module)
            if not imports.imports_module("ops"):
                continue
            host = _host_command(module, imports)
            if module.path == entrypoint or _calls_ops_main(module, imports):
                if host is None:
                    continue
                diagnostics.append(
                    self.diagnostic(
                        "Charm entrypoint runs host commands itself "
                        "(subprocess/os) rather than delegating to a workload module",
                        path=module.path,
                        line=host.lineno,
                        fix_hint="Move the host commands into a workload module "
                        "that doesn't import ops, and call it from the charm",
                    )
                )
                continue
            call = host if host is not None else _container_command(module)
            if call is None:
                continue
            if host is not None:
                how = "host commands itself (subprocess/os)"
            else:
                how = "commands in the workload container itself (container.exec)"
            diagnostics.append(
                self.diagnostic(
                    f"'{module.path}' imports ops and runs {how}",
                    path=module.path,
                    line=call.lineno,
                    fix_hint="Move the workload commands into a module that doesn't "
                    "import ops, so tests can mock the module instead of the commands",
                )
            )
        return diagnostics


def _uses_annotations(module: models.Module) -> bool:
    """Whether *module* carries a type annotation anywhere.

    Any annotation counts — an annotated return, an annotated parameter, or
    an annotated assignment. The rule asks whether the charm uses type hints
    at all, not whether it annotates everything, so a charm that annotates
    parameters but not returns has plainly answered the question.
    """
    for node in module.walk(ast.AnnAssign, ast.FunctionDef, ast.AsyncFunctionDef):
        if isinstance(node, ast.AnnAssign):
            return True
        if node.returns is not None:
            return True
        arguments = node.args
        for argument in (
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
            arguments.vararg,
            arguments.kwarg,
        ):
            if argument is not None and argument.annotation is not None:
                return True
    return False


# The ``subprocess`` functions that start a process. Everything else the
# module offers — exception types, ``CompletedProcess``, constants — is not
# workload work.
_SUBPROCESS_RUNS = frozenset({
    "Popen",
    "run",
    "call",
    "check_call",
    "check_output",
    "getoutput",
    "getstatusoutput",
})


def _host_command(module: models.Module, imports: _ast.Imports) -> ast.Call | None:
    """The first call in *module* that runs a command on the host, if any.

    Resolved through *imports*, so ``from subprocess import check_output``
    counts the same as ``subprocess.check_output``. Calls that run a Juju
    hook tool do not count: they talk to Juju, not the workload.
    """
    hook_tool_vars = _hook_tool_vars(module)
    for call in module.walk(ast.Call):
        target = _ast.call_target(call, imports)
        if target is None or not _runs_on_host(target):
            continue
        if not _invokes_hook_tool(call, hook_tool_vars):
            return call
    return None


# The Juju hook tools a charm's own code can run, all of which ask Juju for
# something rather than do work on the workload. Named as ``subprocess``
# sees them, hyphenated.
_JUJU_HOOK_TOOLS = frozenset({
    "action-fail",
    "action-get",
    "action-log",
    "action-set",
    "add-metric",
    "application-version-set",
    "close-port",
    "config-get",
    "credential-get",
    "goal-state",
    "is-leader",
    "juju-log",
    "juju-reboot",
    "leader-get",
    "leader-set",
    "network-get",
    "open-port",
    "opened-ports",
    "payload-register",
    "payload-set",
    "payload-status",
    "payload-unregister",
    "relation-get",
    "relation-ids",
    "relation-list",
    "relation-set",
    "resource-get",
    "secret-add",
    "secret-get",
    "secret-grant",
    "secret-info-get",
    "secret-remove",
    "secret-revoke",
    "secret-set",
    "state-set",
    "status-get",
    "status-set",
    "storage-add",
    "storage-get",
    "storage-list",
    "unit-get",
})


def _hook_tool_vars(module: models.Module) -> set[str]:
    """Names in *module* bound to a command line that starts with a hook tool.

    ``cmd_line = ["relation-list", "--format=json", relid]`` followed by
    ``subprocess.check_output(cmd_line)``: the command is built a statement
    before it runs, so the name is what the call site shows. The name is
    matched across the whole module, so one reused for other commands
    elsewhere hides those too — a gap rather than a wrong report.
    """
    found: set[str] = set()
    for assign in module.walk(ast.Assign, ast.AnnAssign):
        if _first_word(assign.value) not in _JUJU_HOOK_TOOLS:
            continue
        targets = assign.targets if isinstance(assign, ast.Assign) else [assign.target]
        for target in targets:
            if isinstance(target, ast.Name):
                found.add(target.id)
    return found


def _first_word(expr: ast.expr | None) -> str | None:
    """The command a literal argument spells, if it spells one.

    ``["relation-ids", "--format=json", reltype]`` → ``"relation-ids"``, and
    a plain string argument the same. Anything computed is ``None``.
    """
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        words = expr.value.split()
        return words[0] if words else None
    if isinstance(expr, ast.List | ast.Tuple) and expr.elts:
        return _first_word(expr.elts[0])
    return None


def _runs_on_host(target: str) -> bool:
    """Whether a resolved call target is a stdlib function that runs a command."""
    module_name, _, name = target.partition(".")
    if module_name == "subprocess":
        return name in _SUBPROCESS_RUNS
    # ``os.system``, ``os.popen`` and the ``os.exec*``/``os.spawn*`` families
    # run commands; the rest of ``os`` (``os.path``, ``os.environ``, ...) does
    # not. "os.path.join" keeps its dot in *name* and so matches nothing.
    return module_name == "os" and (
        name in {"system", "popen"} or name.startswith(("exec", "spawn", "posix_spawn"))
    )


def _invokes_hook_tool(call: ast.Call, hook_tool_vars: set[str]) -> bool:
    """Whether *call* runs a Juju hook tool rather than a workload command.

    The command is the first positional argument, or the ``args`` keyword
    when there is no positional argument.
    """
    command = call.args[0] if call.args else _ast.keyword(call, "args")
    if command is None:
        return False
    first = _first_word(command)
    if first is not None:
        return first in _JUJU_HOOK_TOOLS
    return isinstance(command, ast.Name) and command.id in hook_tool_vars


def _calls_ops_main(module: models.Module, imports: _ast.Imports) -> bool:
    """Whether *module* is an entrypoint in substance: it calls ``ops.main()``.

    A charm can keep a Kubernetes and a machine charm beside each other and
    let dispatch pick one, so the file charmcraft names is not the only
    module that owns the entrypoint's job.
    """
    return any(
        _ast.call_target(call, imports) in _ast.OPS_MAIN_TARGETS for call in module.walk(ast.Call)
    )


def _container_command(module: models.Module) -> ast.Call | None:
    """The first ``container.exec(...)`` call in *module*, if any.

    The container is recognised by name — ``container``, ``*_container`` —
    or as the result of ``get_container(...)``. The data-platform
    ``WorkloadBase.exec()`` wrappers (``self.workload.exec``, ``self.exec``)
    block internally and are a different idiom, and an ``exec`` on an
    unrelated object is indistinguishable from ``ops.Container.exec``
    without type information.
    """
    for call in module.walk(ast.Call):
        if not isinstance(call.func, ast.Attribute) or call.func.attr != "exec":
            continue
        if _is_container_exec(call):
            return call
    return None


def _is_container_exec(call: ast.Call) -> bool:
    """Whether *call* is an ``exec`` on something that is a workload container."""
    if not isinstance(call.func, ast.Attribute):
        return False
    name = _ast.receiver(call)
    if name is not None:
        lowered = name.lower()
        return lowered == "container" or lowered.endswith("_container")
    # ``self.unit.get_container("x").exec(...)``: the container never gets a
    # name of its own, so the ``get_container`` call is the receiver. Matched
    # on the method name alone, like CORRECTNESS-009.
    receiver = call.func.value
    return (
        isinstance(receiver, ast.Call)
        and isinstance(receiver.func, ast.Attribute)
        and receiver.func.attr == "get_container"
    )
