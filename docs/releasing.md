# release procedure

publishing is an owner-only manual operation. this repository does not publish
to production indexes from an automated agent or a normal development build.

## before a release

1. review every gate in [docs/verification.md](verification.md). a failed gate blocks release.
2. run the commands in [contributing.md](../contributing.md) from a clean clone.
3. build wheels and an sdist locally, install them in clean environments, and
   run the fast test subset.
4. review the wheel dependency reports on each target platform.
5. confirm the version, changelog, licenses, sbom, and release attestations.

## owner setup

1. register `oxar` on pypi and `oxar-core` on crates.io. a missing name is
   not reserved; an owner may choose a placeholder release to secure it.
2. configure pypi trusted publishing for the repository and release workflow.
3. verify the workflow against testpypi before production publication.
4. review the generated artifacts and attestations, then create the version tag
   (the initial tag is `v0.1.0`).
5. publish `oxar-core` and the python distribution through their intended
   workflows only after that review.

never use production credentials in local scripts or commit them to the
repository. the exact production steps depend on the owner account and the
final release workflow configuration.
