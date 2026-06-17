# Shieldly — AI-Powered Security Analysis (GitHub Action)

Block insecure AWS infrastructure in pull requests. This Action runs
**AI-Powered** analysis of IAM policies and CloudFormation templates, posts
findings as a PR comment, and fails the build when issues meet your severity
threshold. Powered by [Shieldly](https://www.shieldly.io).

## Usage

```yaml
name: Shieldly Security Check
on: [pull_request]

permissions:
  contents: read
  pull-requests: write

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: AI-Powered Security Analysis
        uses: shieldly-io/action@v1
        with:
          api-key: ${{ secrets.SHIELDLY_API_KEY }}
          scan-path: ./cdk.out
          fail-on-severity: High
```

Point `scan-path` at your IaC output after the synth/package step — CDK writes
to `./cdk.out` (after `cdk synth`), Serverless Framework writes to
`./.serverless`. A direct `.json`/`.yaml` file path also works. When no IaC
files are found, the Action posts an informational comment and exits cleanly.

An `api-key` is **required** — demo mode is not available in CI. Create a free
key at [shieldly.io/app/api](https://www.shieldly.io/app/api) and store it as a
repository secret (`SHIELDLY_API_KEY`). The free tier covers both IAM policies
and CloudFormation templates. To try Shieldly without an account first, use the
[CLI](https://www.npmjs.com/package/@shieldly/cli) locally — it has a demo mode.

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `api-key` | `''` | **Required.** Shieldly API key (`sk_live_...`). Demo mode is not available in CI. |
| `scan-path` | `.` | Directory or file to scan. |
| `fail-on-severity` | `High` | Fail at/above this severity: `Critical`, `High`, `Medium`, `Low`, `none`. |
| `post-pr-comment` | `true` | Post results as a PR comment. Needs `pull-requests: write`. |
| `github-token` | `''` | Token for PR comments (defaults to `GITHUB_TOKEN`). |
| `api-url` | `https://api.shieldly.io` | API base URL (override for dev). |

## Outputs

| Output | Description |
| --- | --- |
| `score` | Security score (0–100). |
| `risk-level` | Overall risk: `Critical`, `High`, `Medium`, `Low`. |
| `findings-count` | Total findings. |
| `critical-count` | Number of Critical findings. |

## Using outputs

```yaml
      - name: AI-Powered Security Analysis
        id: shieldly
        uses: shieldly-io/action@v1
        with:
          api-key: ${{ secrets.SHIELDLY_API_KEY }}

      - run: echo "Score ${{ steps.shieldly.outputs.score }} (${{ steps.shieldly.outputs.risk-level }})"
```

## Privacy

Shieldly does **not** log your policy or template input. Cache keys are one-way
SHA-256 hashes.

## Links

- Web app & demo: https://www.shieldly.io
- API reference: https://www.shieldly.io/docs/api
- CLI: https://github.com/shieldly-io/cli

## License

MIT © Shieldly

---

*Amazon Web Services (AWS) is a trademark of Amazon.com, Inc. Shieldly is not
affiliated with, endorsed by, or sponsored by Amazon Web Services.*
