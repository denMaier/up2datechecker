# Contributing

Issues and pull requests are welcome.

## Before you open a pull request

[Development](README.md#development) in the README describes `make dev`, a Docker test environment with real distributions and a local login.

Run the checks CI runs:

```sh
make test     # gofmt, go vet, go test
```

Keep a pull request to one change. This project keeps its dependencies few, so a new one needs a good reason in the description.

## Pull request titles

Pull requests are squash-merged, so the title becomes the commit on `main`. Titles follow [Conventional Commits](https://www.conventionalcommits.org/), and a check enforces it:

| Title | Release |
|---|---|
| `fix: handle an empty config` | patch (0.3.1 → 0.3.2) |
| `feat: add a dark theme` | minor (0.3.1 → 0.4.0) |
| `feat!: drop the old config format` | breaking: minor while below 1.0, major after |
| `docs:`, `test:`, `refactor:`, `ci:`, `chore:` | none |

A scope is optional: `fix(auth): …`. Mark a breaking change with `!` after the type.

## Releases

Releases are automatic. [release-please](https://github.com/googleapis/release-please) keeps a pull request open with the next version and changelog; merging it tags the release, and CI builds and publishes it. Dependabot keeps dependencies current, and a release made only of dependency fixes goes out on its own.

## License

By contributing you agree that your contribution is licensed under the project's license, AGPL-3.0 ([LICENSE](LICENSE)).
