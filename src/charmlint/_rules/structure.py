"""Structure rules — charm directory structure and required files."""

import ast
import pathlib

from .. import _ast
from .. import _models as models
from ._base import Rule


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


class CharmWorkloadSeparation(Rule):
    """Check that charm logic and workload logic live in separate modules.

    The entrypoint is where events are observed, config is turned into
    arguments and status is reported; the commands that actually change
    the machine belong in a workload module of their own. Keeping them
    apart is what lets a charm be unit tested by mocking the workload
    module instead of patching ``subprocess`` in every state test.

    Two shapes are reported: the entrypoint running commands itself,
    and a module under ``src/`` that imports ``ops`` — any submodule,
    ``ops.pebble`` included — and also runs commands. A module may do
    either on its own: a workload module runs commands without knowing
    anything about ops, and a helper module may import ops without
    running anything.

    Running commands means ``subprocess``, ``os.system`` and the
    ``os.spawn*``/``os.exec*`` families. Not every command is workload
    work: Juju's own hook tools (``relation-get``, ``open-port``, …)
    talk to the controller rather than the machine, and a read-only
    command such as ``dig`` or ``lsb_release`` only asks the machine
    something — neither changes it, so neither is reported. A command
    whose name is built at runtime is not assumed to be either. The
    entrypoint is the file charmcraft designates
    (``parts.charm.charm-entrypoint``, defaulting to ``src/charm.py``),
    and only ``src/`` is examined otherwise. A Kubernetes workload module
    that reaches its container through Pebble without running commands is
    not reported — that is the standard way to talk to a container — and
    neither are filesystem writes or HTTP calls to a workload.
    """

    category = "STRUCTURE"
    number = 4
    name = "charm-workload-separation"
    description = "Charm and workload logic mixed in one module"
    default_severity = models.Severity.INFO
    reference_url = (
        "https://canonical.com/juju/docs/ops/latest/howto/run-workloads-with-a-charm-machines/"
    )

    def check(self, context: models.CharmContext) -> list[models.Diagnostic]:
        entrypoint = _entrypoint(context)
        diagnostics: list[models.Diagnostic] = []
        for module in context.modules():
            is_entrypoint = module.path == entrypoint
            if not is_entrypoint and module.scope is not models.Scope.SRC:
                continue
            imports = _ast.Imports.of(module)
            calls = _workload_calls(module, imports)
            if not calls:
                continue
            first = min(calls, key=lambda call: call.lineno)
            if is_entrypoint:
                diagnostics.append(
                    self.diagnostic(
                        f"{module.path} runs commands directly;"
                        " workload logic belongs in a module of its own",
                        path=module.path,
                        line=first.lineno,
                        fix_hint="Move the commands into a workload module and call it from the entrypoint.",
                    )
                )
            elif imports.imports_module("ops"):
                diagnostics.append(
                    self.diagnostic(
                        f"{module.path} imports ops and also runs commands directly;"
                        " split charm and workload logic",
                        path=module.path,
                        line=first.lineno,
                        fix_hint="Pass plain values in and out of this module, and keep the ops imports in the entrypoint.",
                    )
                )
        return diagnostics


def _entrypoint(context: models.CharmContext) -> str:
    """Return the charm-relative path of the file charmcraft runs as the entrypoint.

    The charm plugin's ``charm-entrypoint`` names the file ``dispatch``
    execs, relative to the project directory; charmcraft defaults it to
    ``src/charm.py``. The value is a plain string in charmcraft.yaml, so
    anything else (a list, say) falls back to the default.
    """
    configured = context.metadata.get("parts").get("charm").get("charm-entrypoint").value
    if not isinstance(configured, str) or not configured:
        configured = "src/charm.py"
    return pathlib.PurePosixPath(configured).as_posix()


def _workload_calls(module: models.Module, imports: _ast.Imports) -> list[ast.Call]:
    """Return the calls in *module* that run a command on the machine.

    ``subprocess`` in any spelling, plus the ``os`` calls that start or
    replace a process. The other things a module might do to a workload —
    write a file, speak HTTP, drive Pebble — are not commands and do not
    count, and neither is a command that only asks a question.
    """
    return [
        call
        for call in module.walk(ast.Call)
        if _runs_command(_ast.call_target(call, imports)) and not _is_probe(module, call)
    ]


def _runs_command(target: str | None) -> bool:
    """Whether a resolved call target starts a process."""
    if target is None:
        return False
    root, _, _ = target.partition(".")
    return root == "subprocess" or target.startswith(("os.system", "os.spawn", "os.exec"))


# Juju's own hook tools, which a charm runs through ``subprocess`` wherever
# ops offers no API for the same thing. They talk to the controller rather
# than to the machine, so running one is charm logic, not workload logic.
_JUJU_HOOK_TOOLS = frozenset({
    "action-fail",
    "action-get",
    "action-log",
    "action-set",
    "close-port",
    "config-get",
    "credential-get",
    "goal-state",
    "is-leader",
    "juju-log",
    "juju-reboot",
    "leader-set",
    "network-get",
    "open-port",
    "opened-ports",
    "payload-list",
    "payload-register",
    "payload-set",
    "payload-status",
    "relation-get",
    "relation-ids",
    "relation-list",
    "relation-set",
    "secret-add",
    "secret-get",
    "secret-grant",
    "secret-info",
    "secret-revoke",
    "secret-set",
    "status-get",
    "status-set",
    "storage-add",
    "storage-get",
    "storage-list",
    "unit-get",
})

# Commands that only report on the machine. A charm runs one to decide what
# to do next, not to change anything.
_READ_ONLY_COMMANDS = frozenset({"dig", "host", "lsb_release", "nslookup"})


def _is_probe(module: models.Module, call: ast.Call) -> bool:
    """Whether *call* only asks the machine or the model a question.

    Juju's hook tools and read-only commands such as ``dig`` or
    ``lsb_release`` never change the machine, so they are not workload
    work however they are invoked; ``sysctl`` reads a value unless it is
    told to write one. A command whose words cannot be read is not
    assumed to be any of these.
    """
    argv = _command_argv(module, call)
    if argv is None:
        return False
    name = pathlib.PurePosixPath(argv[0]).name
    if name in _JUJU_HOOK_TOOLS or name in _READ_ONLY_COMMANDS:
        return True
    return name == "sysctl" and not {"-w", "--write"}.intersection(argv[1:])


def _command_argv(module: models.Module, call: ast.Call) -> list[str] | None:
    """Return the words of the command *call* runs, else ``None``.

    A literal argument list or string is read as it stands, and so is a
    list concatenated onto something dynamic (``["dig"] + args.split()``).
    Otherwise the argument has to be a name bound to a literal earlier in
    the same scope — ``cmd = ["relation-get"]; check_output(cmd)``. A
    command built any other way is unreadable, and an unreadable command
    is never a probe.
    """
    if not call.args:
        return None
    literal = _literal_argv(call.args[0])
    if literal is not None:
        return literal
    if not isinstance(call.args[0], ast.Name):
        return None
    return _bound_argv(_enclosing_scope(module, call), call.args[0].id, call)


def _literal_argv(argument: ast.expr) -> list[str] | None:
    """Return the leading literal words of a command expression.

    Only the head has to be readable for the command to be named, so a
    list cut short by a dynamic element still yields what came before it.
    An expression with no literal head — a variable, a call, an f-string —
    yields ``None``.
    """
    while isinstance(argument, ast.BinOp) and isinstance(argument.op, ast.Add):
        argument = argument.left
    if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
        return argument.value.split() or None
    if not isinstance(argument, ast.List):
        return None
    words: list[str] = []
    for element in argument.elts:
        if not (isinstance(element, ast.Constant) and isinstance(element.value, str)):
            break
        words.append(element.value)
    return words or None


def _enclosing_scope(module: models.Module, call: ast.Call) -> ast.AST:
    """Return the innermost function containing *call*, or the module.

    Function bodies nest by line span, so the narrowest function covering
    the call is the one the call runs in; a call covered by none of them
    runs at module level.
    """
    scope: ast.AST = module.tree
    span: int | None = None
    for node in module.walk(ast.FunctionDef, ast.AsyncFunctionDef):
        end = node.end_lineno or node.lineno
        if node.lineno <= call.lineno <= end and (span is None or end - node.lineno < span):
            scope = node
            span = end - node.lineno
    return scope


def _bound_argv(scope: ast.AST, name: str, call: ast.Call) -> list[str] | None:
    """Return the literal command bound to *name* above *call* in *scope*.

    The closest binding above the call wins, so a name reused across a
    module's functions is read in the one that runs the command.
    """
    found: tuple[int, list[str]] | None = None
    for node in ast.walk(scope):
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        if node.lineno > call.lineno:
            continue
        if not any(isinstance(t, ast.Name) and t.id == name for t in targets):
            continue
        if node.value is None:
            continue
        argv = _literal_argv(node.value)
        if argv is not None and (found is None or node.lineno > found[0]):
            found = (node.lineno, argv)
    return found[1] if found is not None else None
