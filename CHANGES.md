# 0.3.0 - 09 October 2026

## Features

* Add CORRECTNESS-009 (container-name-mismatch) ([#207](https://github.com/tonyandrewmeyer/charmlint/pull/207))
* Add SUPPLYCHAIN-001 (oci-image-missing-upstream-source) ([#58](https://github.com/tonyandrewmeyer/charmlint/pull/58))
* Add CONFIG-008 (config-options-not-nested) ([#411](https://github.com/tonyandrewmeyer/charmlint/pull/411))
* Add STRUCTURE-003 (no-type-annotations) ([#140](https://github.com/tonyandrewmeyer/charmlint/pull/140))
* Add FEATURES-007 (no-config-changed-observer) ([#54](https://github.com/tonyandrewmeyer/charmlint/pull/54))

## Fixes

* Flag `bases`/`platforms` in metadata.yaml as misplaced ([#248](https://github.com/tonyandrewmeyer/charmlint/pull/248))
* Don't print compile warnings about the charm's own code ([#343](https://github.com/tonyandrewmeyer/charmlint/pull/343))
* Keep the reference URL when a severity override applies ([#339](https://github.com/tonyandrewmeyer/charmlint/pull/339))
* Merge the duplicate [tool.ruff.format] tables ([#414](https://github.com/tonyandrewmeyer/charmlint/pull/414))
* Apply an own-line directive to a line with its own trailing directive ([#403](https://github.com/tonyandrewmeyer/charmlint/pull/403))

## Documentation

* Add a generated reference page for the rules ([#329](https://github.com/tonyandrewmeyer/charmlint/pull/329))
* Regenerate the rule reference for SUPPLYCHAIN-001 ([#338](https://github.com/tonyandrewmeyer/charmlint/pull/338))
* Correct the comment on naming an empty category ([#341](https://github.com/tonyandrewmeyer/charmlint/pull/341))
* Refresh the README ([#405](https://github.com/tonyandrewmeyer/charmlint/pull/405))
* Stop RST roles leaking into the rule reference ([#389](https://github.com/tonyandrewmeyer/charmlint/pull/389))

## Tests

* Stop tests passing only because their input is FATAL ([#373](https://github.com/tonyandrewmeyer/charmlint/pull/373))
* Deselect the reference-URL checks by default ([#391](https://github.com/tonyandrewmeyer/charmlint/pull/391))

## CI

* Close the remaining Charm Tech baseline gaps ([#332](https://github.com/tonyandrewmeyer/charmlint/pull/332))
* Stop Dependabot putting a scope in PR titles ([#415](https://github.com/tonyandrewmeyer/charmlint/pull/415))
* The SBOM lists only charmlint's runtime dependencies ([#407](https://github.com/tonyandrewmeyer/charmlint/pull/407))
* Make releases with the propose and draft-release workflows
* Stop with an error when a release is proposed from another branch
* Open the release PR as a draft with its next steps

# 0.2.1 - 23 September 2026

The same as 0.2.0, with the version number bumped.

# 0.2.0 - 23 September 2026

## Features

* Add CHARMCRAFT-007 (legacy-bases) ([#209](https://github.com/canonical/charmlint/pull/209))
* Add CONFIG-006 (config-option-undeclared) ([#208](https://github.com/canonical/charmlint/pull/208))
* Add TESTING-003 (uses-harness) ([#143](https://github.com/canonical/charmlint/pull/143))
* Add STATUS-001 (blocked-status-in-non-repeating-handler) ([#190](https://github.com/canonical/charmlint/pull/190))
* Add CHARMCRAFT-008/009 (charm-user, container user IDs) ([#241](https://github.com/canonical/charmlint/pull/241))
* Add CORRECTNESS-004 (non-deferrable-event-deferred) ([#21](https://github.com/canonical/charmlint/pull/21))
* Add CORRECTNESS-003: `container.exec()` result not consumed ([#40](https://github.com/canonical/charmlint/pull/40))
* Add CORRECTNESS-008 (observe-target-mismatch) ([#250](https://github.com/canonical/charmlint/pull/250))
* Adopt ruff's suppression-comment and rule-name style ([#255](https://github.com/canonical/charmlint/pull/255))
* Add SUPPLYCHAIN-005 and SUPPLYCHAIN-006: ops dependency pinning ([#67](https://github.com/canonical/charmlint/pull/67))
* Add FEATURES-004 (no-assumes-juju-version) ([#22](https://github.com/canonical/charmlint/pull/22))
* Add FEATURES-005 and FEATURES-006 (workload version) ([#46](https://github.com/canonical/charmlint/pull/46))
* Add CORRECTNESS-00{1,2} `event.defer()` not followed by return ([#38](https://github.com/canonical/charmlint/pull/38))

## Fixes

* A directory named test_*.py is not a Python file ([#211](https://github.com/canonical/charmlint/pull/211))
* Lint every charm in a multi-charm repository ([#240](https://github.com/canonical/charmlint/pull/240))

## Documentation

* Rewrite RULES_TRACKER to cover all open work, ordered by value
* Record the Phase 0 PRs in the tracker
* Track the rules that need type information in the tracker ([#262](https://github.com/canonical/charmlint/pull/262))
* Document how to measure a rule against the hyrum cache ([#264](https://github.com/canonical/charmlint/pull/264))
* Refresh the work tracker ([#268](https://github.com/canonical/charmlint/pull/268))

## Performance

* Only import importlib.metadata when --version is used ([#257](https://github.com/canonical/charmlint/pull/257))
