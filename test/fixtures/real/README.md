# Real scanner outputs

None of OSV-Scanner, Trivy or Grype was installed where these were made, so
the fixtures are the tools' own golden test outputs: what each tool's output
code printed in its project's test suite. They are copied unchanged except
where noted.

| File | Tool | Source (repository @ commit, path) |
|---|---|---|
| `osv-scanner.real.sarif` | OSV-Scanner 2.7.1, `--format sarif` | google/osv-scanner @ 02f96a40691c2d155fdda799af436e111231e365, `cmd/osv-scanner/scan/source/__snapshots__/command_test.snap`, block `TestCommand/Sarif_with_vulns - 1 - stdout` |
| `osv-scanner-git.real.sarif` | OSV-Scanner 2.7.1, `--format sarif`, a git dependency pinned by commit | same file, block `TestCommand_GithubActions/scanning_osv-scanner_custom_format_output_json - 1 - stdout` |
| `osv-scanner.real.json` | OSV-Scanner, `--format json` (versions and commits) | google/osv-scanner @ 6de73de4a590c7a1888d63f9f346471fc51c88ce, `internal/output/__snapshots__/machinejson_test.snap`, block `TestPrintJSONResults_WithMixedIssues/multiple_sources_with_a_mixed_count_of_packages_with_versions_and_commits…` |
| `trivy.real.sarif` | Trivy, `--format sarif` (image scan) | aquasecurity/trivy @ e5da6deee9904d00cb4fd5ea1f67e8a1711ec8dd, `integration/testdata/alpine-310.sarif.golden` |
| `grype.real.sarif` | Grype, `-o sarif` (directory scan) | anchore/grype @ 3a111a73c2f0978d711049f4b6131c7743430259, `grype/presenter/sarif/testdata/snapshot/TestSarifPresenter_directory.golden` |

The OSV-Scanner blocks were cut out of the snapshot files as is; the snapshot
tool had already replaced machine paths with `<rootdir>` and line hashes with
`[line-hash]`. Fetched on 13 Nov 2026 with
`gh api repos/<repo>/contents/<path>?ref=<commit> -H 'Accept: application/vnd.github.raw'`.

To refresh with outputs of your own (recommended before each release): run
each tool on a small repository with a known-vulnerable lockfile, e.g.
`osv-scanner scan source --format json -r .`, `osv-scanner scan source
--format sarif -r .`, `trivy fs --format sarif .`, `grype dir:. -o sarif`,
and add the files here with the tool version in the table.

## SAST outputs (14 Nov 2026)

Unlike the dependency scanners above, these were made by running the tools on
a small sample repository written for the purpose (an Express app with a SQL
injection, an `eval` and reflected output, and a Flask route that runs a
command; no customer code), in a temporary directory.

| File | Tool | How |
|---|---|---|
| `codeql-javascript.real.sarif` | CodeQL 2.27.4, `javascript-security-extended`, `codeql/javascript-queries` 2.5.0 | `codeql database analyze … --format=sarif-latest --sarif-add-snippets=false` |
| `codeql-python.real.sarif` | CodeQL 2.27.4, `python-security-extended`, `codeql/python-queries` 1.9.0 | same |
| `semgrep.real.sarif` | Semgrep OSS 1.185.0, `--config p/security-audit --config p/javascript`, `--sarif`, metrics off | `semgrep scan` |

Changed from the tools' output: the home directory of the machine (a
`file://` location of the query packs) is replaced by `/home/runner`, and in
the Semgrep file the `tool.driver.rules` array is cut to the 4 rules that
have results (the tool lists all 160 it ran). The CodeQL file names
(`javascript.sarif`, `python.sarif`) are the ones CodeQL writes into its
`output` directory.
