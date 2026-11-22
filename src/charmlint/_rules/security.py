"""Security rules — secrets management, TLS support."""

import re

from .. import _models as models
from .. import _yaml
from ._base import Rule

# Match a secret-like keyword only when it is the terminal
# hyphen/underscore-separated component of the config name, so that
# names like 'token-timeout' are not flagged. A bare 'key' is too broad
# ('ingress-key', 'cache-key'), so only the qualified forms count.
_SECRET_KEYWORD_RE = re.compile(
    r"(?:^|[-_])(?:"
    r"password|passwd|passphrase|secret|token|credentials?"
    r"|(?:api|private|ssh|ssl|tls|secret|access)[-_]?key"
    r")$",
    re.IGNORECASE,
)

# A secret is always a string; 'inject-password: boolean' is a feature
# flag, not a credential. 'type: secret' is a Juju secret already.
_NON_SECRET_TYPES = frozenset({"boolean", "int", "float", "secret"})

# An option whose description says it holds a Juju secret ID or URI is
# already the recommended pattern: the value is a reference, not the
# credential. That includes names that don't end in 'secret', such as
# Kafka's 'tls-private-key' and Ranger's 'ldap-credentials'.
_SECRET_REFERENCE_RE = re.compile(r"\bsecret[-_ ]?(?:id|uri)s?\b|\bsecret:", re.IGNORECASE)

# A plain-text option often points at its secret-holding replacement
# ("Deprecated: prefer setting token-secret-id instead"). That mentions a
# secret ID without being one, so it is still flagged.
_POINTS_ELSEWHERE_RE = re.compile(r"\b(?:prefer|instead|deprecated)\b", re.IGNORECASE)

# 'image-pull-secret' names a Kubernetes Secret object, not a credential.
_KUBERNETES_SECRET_NAME_RE = re.compile(r"(?:^|[-_])pull[-_]secrets?$", re.IGNORECASE)


class SecretInPlainConfig(Rule):
    """Detect config options that look like secrets but aren't using Juju secrets.

    A string option is flagged when the last hyphen- or
    underscore-separated part of its name is ``password``, ``passwd``,
    ``passphrase``, ``secret``, ``token`` or ``credential(s)``, or a
    qualified key: ``api-key``, ``private-key``, ``ssh-key``,
    ``ssl-key``, ``tls-key``, ``secret-key`` or ``access-key`` (with a
    hyphen, an underscore or nothing between the two words). A bare
    ``key`` is not flagged.

    An option is left alone when its description says it holds a Juju
    secret ID or URI, since that is already the recommended pattern,
    unless the description is pointing at a different option to use
    instead. An ``*-pull-secret`` option names a Kubernetes Secret, so it
    is left alone too.
    """

    category = "SECURITY"
    number = 1
    name = "secret-in-plain-config"
    description = "Secret-like config option found — use Juju secrets instead"
    default_severity = models.Severity.ERROR
    reference_url = "https://canonical.com/juju/docs/ops/latest/howto/manage-secrets/"

    def check(self, context: models.CharmContext) -> list[models.Diagnostic]:
        return [
            self.diagnostic(
                f"Config option '{name}' looks like a secret "
                f"— use Juju secrets instead of plain-text config",
                path=option.source,
                line=option.line,
                fix_hint="Use the Juju secrets API for sensitive data",
            )
            for name, option in context.config_options.items()
            if _yaml.option_type(option) not in _NON_SECRET_TYPES
            and isinstance(name, str)
            and _SECRET_KEYWORD_RE.search(name)
            and not _names_a_secret_object(name, option)
        ]


def _names_a_secret_object(name: str, option: models.Yaml) -> bool:
    """Whether an option holds a reference to a secret, not the secret itself."""
    if _KUBERNETES_SECRET_NAME_RE.search(name):
        return True
    description = option.get("description").value
    if not isinstance(description, str):
        return False
    return bool(_SECRET_REFERENCE_RE.search(description)) and not _POINTS_ELSEWHERE_RE.search(
        description
    )
