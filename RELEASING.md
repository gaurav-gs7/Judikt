# Releasing Judikt

A release publishes three things from one tag: the Python package on PyPI, the version-matched `judikt-mcp-security` skill ZIP, and a GitHub release. `.github/workflows/publish.yml` does all three when a GitHub release is published.

## One-time setup

1. **Claim the PyPI name with trusted publishing.** On PyPI, add a pending trusted publisher for project `judikt`. Use owner `gaurav-gs7`, repository `Judikt`, workflow `publish.yml`, and environment `pypi`. No API token is stored in GitHub.
2. **Create the `pypi` environment** in the repository settings (Settings → Environments). Optionally require a reviewer, so every publish needs a manual approval.
3. **Remove stale tags.** A tag whose version does not match `pyproject.toml` cannot publish, because the build job rejects it. It still confuses anyone installing `@v<tag>` from Git. List the tags with `git ls-remote --tags origin`.

## Every release

1. **Pick the version** `X.Y.Z` and update it in all three places:
   - `pyproject.toml` (`project.version`);
   - `src/judikt/__init__.py` (`__version__`);
   - `charts/judikt/Chart.yaml` (`version` and `appVersion`).

   `tests/test_version_consistency.py` fails if they disagree.

   In `CHANGELOG.md`, replace `(unreleased)` with the release date and make sure every change to a default is listed under **Upgrading**.
2. **Run the release gates locally:**

   ```bash
   ./scripts/run_release_tests.sh
   ./scripts/run_skill_acceptance.sh
   ```

3. **Merge to `main`** and wait for CI to pass.
4. **Tag exactly `vX.Y.Z`** on that commit, then publish a GitHub release for the tag. The build job refuses any tag that does not match `pyproject.toml`.
5. **Verify the published artifacts:**
   - `https://pypi.org/project/judikt/X.Y.Z/` lists `https://github.com/gaurav-gs7/Judikt` as its source;
   - the GitHub release has `judikt-mcp-security-vX.Y.Z.zip` attached;
   - in that ZIP, `references/setup.md` pins `judikt==X.Y.Z` and `@vX.Y.Z`.

The skill ZIP is what goes to marketplaces. Upload the ZIP from the GitHub release, not a build from a working tree.
