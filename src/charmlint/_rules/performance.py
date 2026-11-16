"""Performance rules — charm code that burns the hook's time budget."""

import ast

from .. import _ast
from .. import _models as models
from ._base import Rule


class TimeSleep(Rule):
    """Flag ``time.sleep(...)`` in code that runs inside a Juju hook.

    A hook runs under a wall-clock timeout, so a sleep spends time the
    hook does not have and delays every hook queued behind it. Use
    ``event.defer()``, a Pebble check, or a Pebble notice to wait for the
    condition instead.

    Every import spelling is resolved, including aliased imports. Not
    flagged: other sleep functions such as ``asyncio.sleep()``; a
    ``time.sleep`` referenced as a value; test code; dead code; and code
    that only runs in the module's ``if __name__ == "__main__":`` block.
    """

    category = "PERFORMANCE"
    number = 1
    name = "time-sleep"
    description = "time.sleep() in charm source delays the hook and the hooks queued behind it"
    default_severity = models.Severity.WARNING
    reference_url = "https://canonical.com/juju/docs/ops/latest/explanation/defer-guidance/"

    def check(self, context: models.CharmContext) -> list[models.Diagnostic]:
        diagnostics: list[models.Diagnostic] = []
        for module in context.charm_sources():
            if "tests" in module.path.split("/"):
                continue
            parents = {
                child: parent
                for parent in ast.walk(module.tree)
                for child in ast.iter_child_nodes(parent)
            }
            entry = _script_entry(module, parents)
            imports = _ast.Imports.of(module)
            for call in module.walk(ast.Call):
                if _ast.call_target(call, imports) != "time.sleep":
                    continue
                outer: ast.FunctionDef | ast.AsyncFunctionDef | None = None
                node = call
                while node in parents:
                    node = parents[node]
                    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                        outer = node
                if outer in entry:
                    continue
                if not _may_run(parents, call):
                    continue
                diagnostics.append(
                    self.diagnostic(
                        "time.sleep() blocks the hook for the whole sleep, spending "
                        "the hook's wall-clock timeout and delaying the hooks queued "
                        "behind it",
                        path=module.path,
                        line=call.lineno,
                        fix_hint=(
                            "Wait for the condition instead of polling for it: "
                            "`event.defer()` and re-run when the workload reports "
                            "ready, or react to a Pebble check or notice"
                        ),
                    )
                )
        return diagnostics


def _is_dunder_main(test: ast.expr) -> bool:
    if not (
        isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq)
    ):
        return False
    operands = [test.left, *test.comparators]
    names = [o.id for o in operands if isinstance(o, ast.Name)]
    constants = [o.value for o in operands if isinstance(o, ast.Constant)]
    return names == ["__name__"] and constants == ["__main__"]


def _script_entry(
    module: models.Module, parents: dict[ast.AST, ast.AST]
) -> frozenset[ast.FunctionDef | ast.AsyncFunctionDef]:
    if "actions" in module.path.split("/"):
        return frozenset()
    guard: ast.If | None = None
    for node in module.tree.body:
        if isinstance(node, ast.If) and _is_dunder_main(node.test):
            guard = node
            break
    if guard is None:
        return frozenset()
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {
        node.name: node
        for node in module.tree.body
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    }
    imports = _ast.Imports.of(module)
    reached: set[str] = set()
    targets: set[str | None] = set()
    pending = [call for call in ast.walk(guard) if isinstance(call, ast.Call)]
    while pending:
        call = pending.pop()
        targets.add(_ast.call_target(call, imports))
        if not (isinstance(call.func, ast.Name) and call.func.id in functions):
            continue
        if call.func.id in reached:
            continue
        reached.add(call.func.id)
        pending.extend(c for c in ast.walk(functions[call.func.id]) if isinstance(c, ast.Call))
    if targets & _ast.OPS_MAIN_TARGETS:
        return frozenset()
    entry: set[ast.FunctionDef | ast.AsyncFunctionDef] = {functions[name] for name in reached}
    return frozenset(
        function for function in entry if not _referenced_outside(function, parents, guard, entry)
    )


def _referenced_outside(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    parents: dict[ast.AST, ast.AST],
    guard: ast.If,
    entry: set[ast.FunctionDef | ast.AsyncFunctionDef],
) -> bool:
    for node in parents:
        if isinstance(node, ast.Name) and node.id == function.name:
            current = node
            while current in parents:
                current = parents[current]
                if current is guard or current in entry:
                    break
            else:
                return True
    return False


def _may_run(parents: dict[ast.AST, ast.AST], call: ast.Call) -> bool:
    node = call
    container: ast.stmt | None = None
    while node in parents:
        parent = parents[node]
        if isinstance(parent, ast.FunctionDef | ast.AsyncFunctionDef):
            return container is None or container in _reachable_statements(parent)
        if isinstance(parent, ast.stmt) and container is None:
            container = parent
        node = parent
    return True


def _reachable_statements(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> frozenset[ast.stmt]:
    reached: set[ast.stmt] = set()

    def run_block(
        stmts: list[ast.stmt], env: dict[str, object], reachable: bool
    ) -> tuple[dict[str, object], bool]:
        for stmt in stmts:
            if not reachable:
                break
            reached.add(stmt)
            env, reachable = run_statement(stmt, env, reachable)
        return env, reachable

    def run_statement(
        stmt: ast.stmt, env: dict[str, object], reachable: bool
    ) -> tuple[dict[str, object], bool]:
        if isinstance(stmt, ast.Assign | ast.AnnAssign | ast.AugAssign | ast.Delete):
            return _bind(stmt, env), reachable
        if isinstance(stmt, ast.Return | ast.Raise | ast.Break | ast.Continue):
            return dict(env), False
        if isinstance(stmt, ast.If):
            branch = _truth(stmt.test, env)
            if branch is True:
                return run_block(stmt.body, dict(env), reachable)
            if branch is False:
                return run_block(stmt.orelse, dict(env), reachable)
            taken, taken_exits = run_block(stmt.body, dict(env), reachable)
            skipped, skipped_exits = run_block(stmt.orelse, dict(env), reachable)
            if not taken_exits:
                return skipped, skipped_exits
            if not skipped_exits:
                return taken, taken_exits
            merged = {
                name: value
                for name, value in taken.items()
                if name in skipped and skipped[name] == value
            }
            return merged, taken_exits or skipped_exits
        if isinstance(stmt, ast.While | ast.For | ast.AsyncFor):
            if isinstance(stmt, ast.While) and _truth(stmt.test, env) is False:
                return run_block(stmt.orelse, dict(env), reachable)
            body_env = _invalidated([stmt], env)
            run_block(stmt.body, dict(body_env), reachable)
            run_block(stmt.orelse, dict(body_env), reachable)
            return dict(body_env), reachable
        if isinstance(stmt, ast.Try | ast.TryStar):
            run_block(stmt.body, dict(env), reachable)
            for handler in stmt.handlers:
                run_block(handler.body, dict(env), reachable)
            run_block(stmt.orelse, dict(env), reachable)
            run_block(stmt.finalbody, dict(env), reachable)
            return _invalidated([stmt], env), reachable
        if isinstance(stmt, ast.With | ast.AsyncWith):
            run_block(stmt.body, dict(env), reachable)
            return _invalidated([stmt], env), reachable
        if isinstance(stmt, ast.Match):
            for case in stmt.cases:
                run_block(case.body, dict(env), reachable)
            return _invalidated([stmt], env), reachable
        if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            for node in ast.walk(stmt):
                if isinstance(node, ast.Nonlocal):
                    for name in node.names:
                        env.pop(name, None)
            return dict(env), reachable
        return dict(env), reachable

    run_block(function.body, {}, True)
    return frozenset(reached)


def _bind(stmt: ast.stmt, env: dict[str, object]) -> dict[str, object]:
    if isinstance(stmt, ast.Assign):
        targets, value = stmt.targets, stmt.value
    elif isinstance(stmt, ast.AnnAssign):
        targets, value = [stmt.target], stmt.value
    elif isinstance(stmt, ast.AugAssign):
        targets, value = [stmt.target], None
    elif isinstance(stmt, ast.Delete):
        targets, value = stmt.targets, None
    else:
        return env
    literal = _UNKNOWN if value is None else _constant(value, env)
    for name in {n.id for t in targets for n in ast.walk(t) if isinstance(n, ast.Name)}:
        if literal is _UNKNOWN:
            env.pop(name, None)
        else:
            env[name] = literal
    return env


def _invalidated(stmts: list[ast.stmt], env: dict[str, object]) -> dict[str, object]:
    stored = {
        node.id
        for stmt in stmts
        for node in ast.walk(stmt)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
    }
    return {name: value for name, value in env.items() if name not in stored}


def _truth(test: ast.expr, env: dict[str, object]) -> bool | None:
    value = _constant(test, env)
    return None if value is _UNKNOWN else bool(value)


_UNKNOWN = object()


def _constant(node: ast.expr, env: dict[str, object]) -> object:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return env.get(node.id, _UNKNOWN)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        value = _constant(node.operand, env)
        return _UNKNOWN if value is _UNKNOWN else not value
    if isinstance(node, ast.BoolOp):
        pairs = [
            (value is not _UNKNOWN, value) for value in (_constant(v, env) for v in node.values)
        ]
        if isinstance(node.op, ast.Or):
            if any(known and value for known, value in pairs):
                return next(value for known, value in pairs if known and value)
            if all(known for known, _ in pairs):
                return pairs[-1][1]
        else:
            if any(known and not value for known, value in pairs):
                return next(value for known, value in pairs if known and not value)
            if all(known for known, _ in pairs):
                return pairs[-1][1]
        return _UNKNOWN
    if (
        isinstance(node, ast.Compare)
        and len(node.ops) == 1
        and isinstance(node.ops[0], ast.Eq | ast.NotEq)
    ):
        left = _constant(node.left, env)
        right = _constant(node.comparators[0], env)
        if left is not _UNKNOWN and right is not _UNKNOWN:
            return left == right if isinstance(node.ops[0], ast.Eq) else left != right
    return _UNKNOWN
