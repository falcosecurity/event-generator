# Contributing

For general Falco contribution guidelines, including DCO sign-off, see the organization-wide [CONTRIBUTING.md](https://github.com/falcosecurity/.github/blob/main/CONTRIBUTING.md).

## Helm Chart Contributions

The event-generator chart source lives in [`chart/event-generator`](chart/event-generator). Published Falco charts live in [`falcosecurity/charts`](https://github.com/falcosecurity/charts), and Falco infrastructure syncs this chart there only when the chart version is bumped.

Open event-generator chart issues and PRs in this repository; `falcosecurity/charts` receives the generated sync PR.

- Regular chart PRs: do not bump [`chart/event-generator/Chart.yaml`](chart/event-generator/Chart.yaml); add the change under `## Unreleased` in [`chart/event-generator/CHANGELOG.md`](chart/event-generator/CHANGELOG.md).
- Chart release PRs: use `/kind chart-release`, bump [`chart/event-generator/Chart.yaml`](chart/event-generator/Chart.yaml), and move the selected `## Unreleased` entries into the new version section. Entries not included in that release can stay under `## Unreleased`.

Use SemVer for the chart `version`: major for breaking changes, minor for backward-compatible chart features, patch for fixes or metadata changes. Set `appVersion` to the event-generator version rendered by the chart when preparing a chart release.

If chart values or chart documentation change, update [`chart/event-generator/README.gotmpl`](chart/event-generator/README.gotmpl) and regenerate [`chart/event-generator/README.md`](chart/event-generator/README.md).

Before opening a chart PR, run:

```bash
make chart-check
```
