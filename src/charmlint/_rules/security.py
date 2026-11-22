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

# A '*-secret' option whose description says it holds a Juju secret ID
# or URI is already the recommended pattern: the value is a reference,
# not the credential.
_SECRET_REFERENCE_RE = re.compile(r"\bsecret[-_ ]?(?:id|uri)s?\b|\bsecret:", re.IGNORECASE)

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

    An option whose name ends in ``secret`` is left alone when its
    description says it holds a Juju secret ID or URI, since that is
    already the recommended pattern, and so is an ``*-pull-secret``
    option, which names a Kubernetes Secret.
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
    """Whether a ``*-secret`` option holds a reference to a secret, not the secret itself."""
    if _KUBERNETES_SECRET_NAME_RE.search(name):
        return True
    if not re.search(r"secrets?$", name, re.IGNORECASE):
        return False
    description = option.get("description").value
    return isinstance(description, str) and bool(_SECRET_REFERENCE_RE.search(description))
