"""SUPPLYCHAIN rules — dependency and release hygiene.

A charm deploys more than its own source: everything it pulls in from
elsewhere, at build time or at deploy time. These rules check that the
charm records where each of those artefacts comes from and which
versions it accepts.
"""

import dataclasses
import functools
import pathlib
import re
from typing import Any

from .. import _dependencies, _yaml
from .. import _models as models
from ._base import Rule

_PEP508_RE = re.compile(
    r"""
    ^\s*
    (?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)   # the distribution name
    \s*
    (?:\[(?P<extras>[^\]]*)\])?            # optional [extras], e.g. ops[tracing]
    \s*
    (?P<rest>.*)                           # the version specifier and/or a PEP 508 marker
    """,
    re.VERBOSE | re.DOTALL,
)


@dataclasses.dataclass(frozen=True)
class _OpsDependency:
    """A charm's declared ``ops`` dependency, and where it was declared.

    Every rule about the ``ops`` dependency works from one of
    these, so the charm's packaging is parsed once and interrogated
    many times rather than each rule re-deriving the answer it happens
    to need. Keeping the specifier and the section rather than a
    collapsed verdict is what lets a later rule ask a question the
    current two do not — whether there is an upper bound, whether the
    pinned version is an LTS, whether the section it was found in is
    one a charm ought to be using.
    """

    #: The version specifier exactly as written, e.g. ``">=2.23,<4"``.
    #: Empty when the dependency is declared with no specifier at all.
    specifier: str
    #: Extras requested alongside it, e.g. ``("tracing",)``.
    extras: tuple[str, ...]
    #: The file it was declared in, relative to the charm directory.
    source: str
    #: Where within that file, as a dotted path for ``pyproject.toml``
    #: (``"project.dependencies"``) or the file name for a flat
    #: requirements file. Names a place a charm author can go and look.
    section: str
    #: 1-based line, or ``None`` for a ``pyproject.toml`` match —
    #: ``tomllib`` discards positions, so a finding there anchors to
    #: the file.
    line: int | None
    #: Whether it is a direct reference (``ops @ git+https://...``, or a
    #: Poetry ``git``, ``url`` or ``path`` table) rather than a version
    #: specifier. Neither pinning rule's advice applies to one: there is
    #: no range to add, and no ``==`` to replace.
    direct: bool = False

    @property
    def is_unpinned(self) -> bool:
        """Whether it carries no version constraint at all."""
        if self.direct:
            return False
        return not self.specifier or self.specifier == "*"

    @property
    def is_exact(self) -> bool:
        """Whether it is pinned to a single version with ``==`` or ``===``.

        A wildcard such as ``==2.*`` is a prefix match, which is a
        range, not a pin.
        """
        if self.direct:
            return False
        return any(
            clause.strip().startswith("==") and not clause.strip().endswith(".*")
            for clause in self.specifier.split(",")
        )

    @property
    def is_runtime(self) -> bool:
        """Whether it was declared where the charm's build installs from.

        That is ``project.dependencies``, Poetry's main
        ``dependencies`` table, or a requirements file the build plugin
        reads (whose section is the file itself). Optional dependencies
        and dependency groups are where test and lint tooling lives.
        """
        return self.section in _RUNTIME_SECTIONS or self.section == self.source

    @property
    def is_test_only(self) -> bool:
        """Whether this declaration is the testing harness rather than the runtime.

        ``ops[testing]`` pulls in ``ops.testing``, which runs in the
        test environment and never ships in the charm. Neither pinning
        rule has anything useful to say about it: a test harness wants
        the version the tests were written against, not a range chosen
        so security fixes flow into production.

        The extra only means that outside the runtime sections, though.
        ``ops[tracing,testing]`` in ``project.dependencies`` still
        ships ``ops`` in the charm, so it is the runtime declaration.
        """
        return "testing" in self.extras and not self.is_runtime

    @property
    def where(self) -> str:
        """A phrase naming the section, for a diagnostic message.

        Empty for a flat requirements file, where the section *is* the
        file the diagnostic already points at, and naming it again
        would only pad the message. For ``pyproject.toml``, where
        there is no line to anchor to and a charm can declare ``ops``
        in any of half a dozen places, it is the only thing telling
        the author which one to go and edit.
        """
        if self.section == self.source:
            return ""
        return f" in `{self.section}`"


def _parse_pep508(
    entry: str, source: str, section: str, line: int | None = None
) -> _OpsDependency | None:
    """Parse a PEP 508 requirement string, returning ``None`` if it isn't ``ops``."""
    match = _PEP508_RE.match(entry)
    if match is None or _dependencies.normalise(match.group("name")) != "ops":
        return None
    rest = match.group("rest").strip()
    if rest.startswith("@"):
        # A direct reference; its URL can itself contain a `;`.
        return _OpsDependency(
            specifier=rest,
            extras=_split_extras(match.group("extras")),
            source=source,
            section=section,
            line=line,
            direct=True,
        )
    # Drop any environment marker: `ops>=2.23; python_version < "3.12"`
    # constrains when the dependency applies, not which versions satisfy it.
    specifier = rest.split(";", 1)[0].strip()
    # PEP 508 still allows the old parenthesised form, `ops (==2.17.0)`.
    if specifier.startswith("(") and specifier.endswith(")"):
        specifier = specifier[1:-1].strip()
    return _OpsDependency(
        specifier=specifier,
        extras=_split_extras(match.group("extras")),
        source=source,
        section=section,
        line=line,
    )


#: Keys of a Poetry dependency table that make it a direct reference
#: rather than a version requirement.
_POETRY_DIRECT_KEYS = frozenset({"git", "url", "path", "file"})


def _parse_poetry(value: Any, source: str, section: str) -> _OpsDependency:
    """Parse a Poetry dependency value (bare string, or table with ``version``)."""
    direct = False
    if isinstance(value, dict):
        specifier = str(value.get("version", ""))
        extras = value.get("extras")
        extras = tuple(str(e) for e in extras) if isinstance(extras, list) else ()
        direct = not specifier and any(key in value for key in _POETRY_DIRECT_KEYS)
    else:
        specifier = str(value)
        extras = ()
    specifier = specifier.strip()
    # Poetry reads a bare version, `ops = "2.17.0"`, as an exact pin.
    # Normalise it to the PEP 440 spelling so `is_exact` sees it.
    if specifier[:1].isdigit():
        specifier = f"=={specifier}"
    return _OpsDependency(
        specifier=specifier,
        extras=extras,
        source=source,
        section=section,
        line=None,
        direct=direct,
    )


def _split_extras(extras: str | None) -> tuple[str, ...]:
    """Split the bracketed extras of a PEP 508 requirement into a tuple."""
    if not extras:
        return ()
    stripped = (part.strip() for part in extras.split(","))
    return tuple(part for part in stripped if part)


#: The ``pyproject.toml`` sections a charm's build installs from.
_RUNTIME_SECTIONS = frozenset({"project.dependencies", "tool.poetry.dependencies"})


def _find_ops_in_pyproject(
    data: dict[str, Any], *, runtime: bool | None = None
) -> _OpsDependency | None:
    """Look for an ``ops`` dependency across the common pyproject.toml layouts.

    *data* is the charm's parsed ``pyproject.toml``, read once by the
    linter core. ``None`` means no ``ops`` dependency appears in any
    known location. *runtime* restricts the search to the runtime
    sections (``True``) or to the rest (``False``); ``None`` searches
    both, runtime sections first.
    """
    if runtime is None:
        return _find_ops_in_pyproject(data, runtime=True) or _find_ops_in_pyproject(
            data, runtime=False
        )
    source = "pyproject.toml"
    for declaration in _dependencies.pyproject_declarations(data):
        if declaration.name != "ops":
            continue
        if declaration.requirement is not None:
            dep = _parse_pep508(declaration.requirement, source, declaration.section)
        else:
            dep = _parse_poetry(declaration.poetry_value, source, declaration.section)
        if dep is None or dep.is_runtime != runtime or dep.is_test_only:
            continue
        return dep
    return None


def _find_ops_in_requirements(
    requirements: pathlib.Path, name: str = "requirements.txt"
) -> _OpsDependency | None:
    """Look for an ``ops`` line in a ``requirements.txt``-style file.

    *name* is what the diagnostic calls the file. It defaults to
    ``requirements.txt`` because that is the file almost every charm
    uses, but the ``python`` plugin lets a charm name its requirements
    files itself, and a finding should point at the file the charm
    actually declared rather than at one it does not have.
    """
    return _scan_requirements(requirements, name, frozenset())


#: A ``-r``/``--requirement`` include line in a requirements file.
_INCLUDE_RE = re.compile(r"^(?:-r\s*|--requirement(?:\s*=\s*|\s+))(?P<path>\S+)")


def _scan_requirements(
    requirements: pathlib.Path, name: str, seen: frozenset[pathlib.Path]
) -> _OpsDependency | None:
    """Scan one requirements file, following ``-r`` includes in place.

    pip reads an included file at the point of the ``-r`` line, so a
    charm that keeps its runtime pins in a shared file and pulls it in
    with ``-r`` still declares ``ops`` there. *seen* stops an include
    cycle from recursing forever.
    """
    try:
        resolved = requirements.resolve()
        text = requirements.read_text()
    except OSError:
        return None
    seen = seen | {resolved}
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        include = _INCLUDE_RE.match(line)
        if include is not None:
            target = requirements.parent / include.group("path")
            if target.resolve() in seen:
                continue
            target_name = str(pathlib.PurePosixPath(name).parent / include.group("path"))
            dep = _scan_requirements(target, target_name, seen)
            if dep is not None:
                return dep
            continue
        if not line or line.startswith("-"):
            continue
        dep = _parse_pep508(line, name, name, lineno)
        if dep is not None and not dep.is_test_only:
            return dep
    return None


#: charmcraft plugins that resolve dependencies from ``pyproject.toml``
#: plus a lock file. Any ``requirements.txt`` alongside one of these is a
#: generated artefact, not a hand-written declaration, so the pinning
#: rules must not read it.
#:
#: This is a narrow guard, and deliberately so. Across the corpus it
#: changes the outcome for two charms — the ``kubernetes`` and ``machine``
#: charms of ``opensearch-dashboards-operator``, which export a
#: ``requirements.txt`` from ``poetry.lock`` (``--only main``) purely so
#: the pins are visible inside the built ``.charm``. That export pins
#: ``ops`` exactly, which is what a lock file is for; without this guard
#: SUPPLYCHAIN-006 would flag it.
_LOCKFILE_PLUGINS = frozenset({"poetry", "uv"})

#: Every charmcraft plugin that builds the charm's Python environment,
#: and so decides where the charm's dependencies are declared. The rest
#: of the plugins a charm uses — ``nil``, ``dump``, ``reactive`` — put
#: files in the payload without resolving anything, and say nothing
#: about where ``ops`` is declared.
_DEPENDENCY_PLUGINS = _LOCKFILE_PLUGINS | frozenset({"charm", "python"})


def _dependency_part(metadata: models.Yaml) -> models.Yaml | None:
    """Return the ``parts`` entry that builds the charm's Python environment.

    A charm has at most one. Across the corpus, 329 of 655 charms
    declare exactly one part using a dependency-resolving plugin and
    **none declares two**; the sets are disjoint as well as unique
    (``uv`` 198, ``poetry`` 79, ``charm`` 52). The remaining 326 either
    declare ``parts`` using only ``nil``, ``dump`` or ``reactive``, or
    declare no ``parts`` at all — so "no dependency-resolving part" is
    the common case, not an error, and the caller falls back to the
    default ``requirements.txt`` for it.
    """
    for _, part in metadata.get("parts").items():
        plugin = part.get("plugin").value
        if isinstance(plugin, str) and plugin in _DEPENDENCY_PLUGINS:
            return part
    return None


def _requirements_files(context: models.CharmContext) -> tuple[tuple[pathlib.Path, str], ...]:
    """Return the requirements files the charm's build plugin actually reads.

    Each entry is the path to read and the name to call it in a
    diagnostic. An empty tuple means the plugin resolves dependencies
    from ``pyproject.toml`` and a lock file, so there is no hand-written
    requirements file to read at all.
    """
    part = _dependency_part(context.metadata)
    default = ((context.charm_dir / "requirements.txt", "requirements.txt"),)
    if part is None:
        return default
    plugin = part.get("plugin").value
    if plugin in _LOCKFILE_PLUGINS:
        return ()
    # The python plugin names its own requirements files, as does the
    # charm plugin, and a charm using either need not call them
    # requirements.txt.
    key = {"python": "python-requirements", "charm": "charm-requirements"}.get(plugin)
    if key is not None:
        declared = tuple(
            (context.charm_dir / str(entry.value), str(entry.value))
            for entry in part.get(key).elements or ()
            if entry.value
        )
        if declared:
            return declared
    return default


#: The charm plugin's keys for packages it installs by name, listed in
#: ``charmcraft.yaml`` itself rather than in a requirements file. The
#: plugin installs these before the requirements files.
_CHARM_PLUGIN_PACKAGE_KEYS = ("charm-binary-python-packages", "charm-python-packages")


def _find_ops_in_charm_plugin_packages(context: models.CharmContext) -> _OpsDependency | None:
    """Look for ``ops`` among the packages the charm plugin installs by name."""
    part = _dependency_part(context.metadata)
    if part is None or part.get("plugin").value != "charm":
        return None
    for key in _CHARM_PLUGIN_PACKAGE_KEYS:
        for entry in part.get(key).elements or ():
            if not isinstance(entry.value, str):
                continue
            dep = _parse_pep508(entry.value, entry.source, entry.source, entry.line)
            if dep is not None and not dep.is_test_only:
                return dep
    return None


@functools.cache
def _find_ops_requirements(
    files: tuple[tuple[pathlib.Path, str], ...],
) -> _OpsDependency | None:
    """Scan the charm's requirements files once, for both pinning rules."""
    for path, name in files:
        if not path.is_file():
            continue
        dep = _find_ops_in_requirements(path, name)
        if dep is not None:
            return dep
    return None


def _find_ops_dep(context: models.CharmContext) -> _OpsDependency | None:
    """Return the charm's runtime ``ops`` dependency, or ``None``.

    Both pinning rules share this scan and stop at the first hit that
    is not the test harness. Declaring ``ops`` more than once is the
    norm rather than the exception — 245 of the 417 corpus charms that
    declare it at all do so twice or more, almost always runtime
    ``ops`` alongside ``ops[testing]`` in a test group — so
    :attr:`_OpsDependency.is_test_only` declarations are stepped over
    rather than returned.

    The search runs from the places the built charm installs ``ops``
    from to the places it does not: the runtime sections of
    ``pyproject.toml``, then the charm plugin's named packages, then
    the requirements files the charm's build plugin reads (see
    :func:`_requirements_files`), and only then the optional
    dependencies and groups of ``pyproject.toml``. A ``==`` pin in a
    ``unit`` group therefore no longer hides the range in
    ``requirements.txt`` that actually ships.
    """
    if context.pyproject is not None:
        dep = _find_ops_in_pyproject(context.pyproject, runtime=True)
        if dep is not None:
            return dep

    dep = _find_ops_in_charm_plugin_packages(context)
    if dep is not None:
        return dep

    dep = _find_ops_requirements(_requirements_files(context))
    if dep is not None:
        return dep

    if context.pyproject is not None:
        return _find_ops_in_pyproject(context.pyproject, runtime=False)
    return None


class OciImageMissingUpstreamSource(Rule):
    """Flag an ``oci-image`` resource with no ``upstream-source``."""

    category = "SUPPLYCHAIN"
    number = 1
    name = "oci-image-missing-upstream-source"
    description = "oci-image resource declared without an 'upstream-source'"
    default_severity = models.Severity.INFO

    def check(self, context: models.CharmContext) -> list[models.Diagnostic]:
        candidates = [
            (name, resource)
            for name, resource in context.metadata.get("resources").items()
            if resource.get("type").value == "oci-image" and not resource.get("upstream-source")
        ]
        if not candidates:
            return []

        # `upstream-source` names the image the resource is built from, so
        # it has nothing to say about an image this repository builds
        # itself: for those the build recipe is the record of provenance.
        local = _locally_built_images(context.charm_dir)
        diagnostics: list[models.Diagnostic] = []
        for name, resource in candidates:
            stem = _normalise_image_name(name)
            for suffix in _IMAGE_SUFFIXES:
                stem = stem.removesuffix(suffix)
            if stem in local or _normalise_image_name(name) in local:
                continue
            diagnostics.append(
                self.diagnostic(
                    f"OCI image resource '{name}' has no 'upstream-source', so there is "
                    "no record of which image it is built from",
                    # A split-metadata charm can declare `resources` in
                    # metadata.yaml, where the diagnostic — and any noqa
                    # silencing it — then belongs.
                    path=resource.source,
                    line=resource.line,
                    fix_hint=(
                        f"Add 'upstream-source' under resources.{name}, naming the image "
                        "the resource is built from (e.g. 'ghcr.io/canonical/foo:1.2.3')"
                    ),
                )
            )
        return diagnostics


class OpsDependencyUnpinned(Rule):
    """Flag an ``ops`` dependency with no version specifier."""

    category = "SUPPLYCHAIN"
    number = 5
    name = "ops-dependency-unpinned"
    description = "ops dependency has no version specifier"
    default_severity = models.Severity.WARNING

    def check(self, context: models.CharmContext) -> list[models.Diagnostic]:
        dep = _find_ops_dep(context)
        if dep is None or not dep.is_unpinned:
            return []
        return [
            self.diagnostic(
                f"ops dependency has no version specifier{dep.where} — "
                "charms should pin a supported range so dependency "
                "resolvers do not silently pull a major bump",
                path=dep.source,
                line=dep.line,
                fix_hint="Add a version range, e.g. `ops>=2.23,<4`",
            )
        ]


class OpsDependencyExactlyPinned(Rule):
    """Flag an ``ops`` dependency pinned with ``==``."""

    category = "SUPPLYCHAIN"
    number = 6
    name = "ops-dependency-exactly-pinned"
    description = "ops dependency pinned with `==`"
    default_severity = models.Severity.INFO

    def check(self, context: models.CharmContext) -> list[models.Diagnostic]:
        dep = _find_ops_dep(context)
        if dep is None or not dep.is_exact:
            return []
        return [
            self.diagnostic(
                f"ops dependency is exactly pinned (`==`){dep.where} — "
                "prefer a version range so security fixes flow in "
                "without a manual bump",
                path=dep.source,
                line=dep.line,
                fix_hint="Replace the `==` pin with a range, e.g. `ops>=2.23,<4`",
            )
        ]


_IMAGE_SUFFIXES = ("-image", "_image")


def _normalise_image_name(name: object) -> str:
    """Fold a rock, directory, or resource name to one comparable form."""
    return str(name).replace("_", "-").lower()


def _locally_built_images(charm_dir: pathlib.Path) -> set[str]:
    """Return the names of images this repository builds for itself.

    A rock or Dockerfile in the charm directory, or up to two levels
    below it, names an image the charm's own CI builds and uploads. So
    does one up to two levels below the repository root, since in a
    monorepo the rock is often a sibling of the charm (``app/charm/``
    beside ``app/rockcraft.yaml``) or sits at the top of the repository.
    The candidate names are the rock's declared ``name`` and the
    directory holding the build recipe, since the ``foo_rock/``,
    ``rock/`` and ``foo_rocks/<component>/`` layouts are all common.
    """
    charm_dir = charm_dir.resolve()
    names: set[str] = set()
    for root in {charm_dir, _repo_root(charm_dir)}:
        for depth in ("", "*/", "*/*/"):
            for rockcraft in root.glob(f"{depth}rockcraft.yaml"):
                try:
                    declared = _yaml.load(rockcraft).get("name")
                except _yaml.FileLoadError:
                    declared = models.Yaml.absent(rockcraft.name)
                if isinstance(declared.value, str):
                    names.add(_normalise_image_name(declared.value))
                names.add(
                    _normalise_image_name(
                        rockcraft.parent.name.removesuffix("_rock").removesuffix("-rock")
                    )
                )
            for dockerfile in root.glob(f"{depth}Dockerfile"):
                names.add(_normalise_image_name(dockerfile.parent.name))
    return names


def _repo_root(charm_dir: pathlib.Path) -> pathlib.Path:
    """Return the root of the git repository holding the charm.

    Falls back to the charm directory itself when it is not in a git
    repository, so the search never wanders further than it would have.
    """
    for directory in (charm_dir, *charm_dir.parents):
        if (directory / ".git").exists():
            return directory
    return charm_dir
