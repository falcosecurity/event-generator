# Release Process

Our release process is fully automated using [CircleCI](https://app.circleci.com/pipelines/github/falcosecurity/event-generator) and [goreleaser](https://github.com/goreleaser/goreleaser) tool for artifacts.

When we release we do the following process:

1. We decide together (usually in the #falco channel in [slack](https://sysdig.slack.com)) what's the next version to tag
2. A person with repository rights does the tag
3. The same person runs commands in their machine following the "Release commands" section below
4. Once the CI has done its job, the tag is live on [Github](https://github.com/falcosecurity/event-generator/releases) with the artifacts, and the container image is live on [DockerHub](https://hub.docker.com/r/falcosecurity/event-generator/tags) with proper tags

## Release commands

Tag the version

```bash
git tag -a v0.1.0-rc.0 -m "v0.1.0-rc.0"
git push origin v0.1.0-rc.0
```