# Omni Secrets Scan

An [Omni Code](https://github.com/GraysonBannister/omni-code) add-on that scans your codebase for hardcoded secrets, API keys, and sensitive credentials.

## Features

- **Pattern-based detection**: Identifies common secret types using regex patterns
- **Fast scanning**: Uses `git ls-files` when available for efficient scanning
- **Customizable**: Choose specific patterns or exclude files/directories
- **Safe**: Read-only operation that never modifies your files

## Patterns Detected

| Pattern | Description |
|---------|-------------|
| AWS Access Key | Access key IDs starting with AKIA |
| AWS Secret Key | AWS secret access keys |
| GitHub Token | Personal access tokens (ghp_*) |
| GitHub OAuth | OAuth tokens (gho_*) |
| Slack Token | Bot/app tokens (xoxb-*, xoxa-*, etc.) |
| Generic API Key | Common API key patterns |
| Private Key | PEM private key blocks |
| Password Assignment | Password variable assignments |
| Secret Assignment | Secret variable assignments |
| Bearer Token | HTTP Bearer tokens |
| JWT Token | JSON Web Tokens |
| Stripe Key | Live Stripe API keys |
| Basic Auth | HTTP Basic auth headers |
| Connection String | Database URLs with credentials |

## Usage

### Scan entire project

```
Scan for secrets
```

### Scan specific directory

```
Scan for secrets in the src/config directory
```

### Scan with specific patterns only

```
Scan for AWS keys and GitHub tokens only
```

## How It Works

1. **File Discovery**: Attempts to use `git ls-files` for tracked files, falls back to recursive directory scan
2. **Pattern Matching**: Applies regex patterns to each line of text files
3. **Result Formatting**: Returns a markdown table with file, line, pattern type, and match preview
4. **Deduplication**: Avoids duplicate matches for the same file/line/pattern combination

## Limitations

- May produce false positives (test data, example values, documentation)
- Does not detect all possible secret types (focused on common patterns)
- Binary files are skipped
- Does not verify if detected secrets are actually valid

## Installation

Install via the Omni Code Add-ons panel or directly from the [registry](https://graysonbannister.github.io/omni-code-website/addons).

## License

MIT
