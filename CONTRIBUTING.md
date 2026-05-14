# Contributing

For general Falco contribution guidelines, including DCO sign-off, see the organization-wide [CONTRIBUTING.md](https://github.com/falcosecurity/.github/blob/main/CONTRIBUTING.md).

## Helm Chart Contributions

The event-generator chart source lives in this repository under [`chart/event-generator`](chart/event-generator). This repository is the source of truth for chart changes, chart version bumps, changelog entries, and generated chart docs.

Published Falco charts live in [`falcosecurity/charts`](https://github.com/falcosecurity/charts). After chart changes are merged here, Falco infrastructure opens or updates the matching chart release PR in `falcosecurity/charts`.

PRs that change chart templates, values, release metadata, or the application version rendered by the chart must update [`chart/event-generator/Chart.yaml`](chart/event-generator/Chart.yaml) and [`chart/event-generator/CHANGELOG.md`](chart/event-generator/CHANGELOG.md) in this repository.

Use SemVer for the chart `version`: major for breaking changes to values, rendered resources, or upgrade behavior; minor for backward-compatible chart features; patch for backward-compatible fixes or metadata changes. Set `appVersion` to the event-generator version rendered by the chart.

If chart values or chart documentation change, update [`chart/event-generator/README.gotmpl`](chart/event-generator/README.gotmpl) and regenerate [`chart/event-generator/README.md`](chart/event-generator/README.md).

Before opening a chart PR, run:

```bash
make chart-check
```
