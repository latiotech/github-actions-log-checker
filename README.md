# GitHub Actions Log Checker

A security tool for scanning GitHub Actions logs for exposed secrets and credentials.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Set up authentication
export GITHUB_TOKEN='your_token'

# Basic scan (5 most recent workflow types from each repo)
python githubactionsearch.py https://github.com/your-org

# Full scan of a specific repository
python githubactionsearch.py https://github.com/your-org -r your-repo -f
```

## Default Settings

When run with no options, the script:
- Scans all repositories in the specified organization
- Examines only the 30 most recent workflow runs per repository (1 page)
- Limits scanning to 5 different workflow types per repository
- Uses 10 parallel workers for processing
- Outputs results to "results.txt" in the current directory
- Automatically detects both single and double base64-encoded secrets

To override these settings, use the command-line options described below.

## Requirements

- Python 3.x
- GitHub Token
- Trufflehog (for enhanced secret detection)

## Authentication

**Option 1: GitHub CLI (Recommended)**
```bash
gh auth login
gh auth status -t
export GITHUB_TOKEN='token_value'
```

**Option 2: Manual PAT**
1. Create a token at: https://github.com/settings/tokens
2. Set as environment variable: `export GITHUB_TOKEN='token_value'`

## API Rate Limits Warning

The script makes multiple GitHub API calls:
- One call to list repositories
- One call per page of workflow runs requested
- One call per workflow run to download logs

**Rate limit warnings:**
- Default scan of 50 repos: ~1,500 API calls
- Full scan of a single repo: ~3,100 API calls  
- Full scan of 50 repos: ~155,000 API calls (exceeds hourly rate limit of 5,000 for most people)

## Usage Examples

### Common Scenarios

```bash
# Scan most recent runs (max 30 runs per repo)
python githubactionsearch.py https://github.com/your-org

# Scan more history (max 150 runs per repo)
python githubactionsearch.py https://github.com/your-org -d 5

# Scan only a single repository
python githubactionsearch.py https://github.com/your-org -r your-repo

# Limit to scanning 3 repositories only
python githubactionsearch.py https://github.com/your-org -m 3

# Scan all workflow types (not just the 5 most recent types)
python githubactionsearch.py https://github.com/your-org -u 0

# Full scan (all workflows, maximum history)
python githubactionsearch.py https://github.com/your-org -f

# Date filtering
python githubactionsearch.py https://github.com/your-org --start-date 2023-01-01 --end-date 2023-12-31

# Custom output file
python githubactionsearch.py https://github.com/your-org -o custom-results.txt
```

### Scanning for Known Attacks

```bash
# Reviewdog attack (March 11, 2024)
python githubactionsearch.py https://github.com/your-org --start-date 2024-03-10 --end-date 2024-03-12

# tj-actions attack (March 14, 2024)
python githubactionsearch.py https://github.com/your-org --start-date 2024-03-13 --end-date 2024-03-15

# Both attack windows
python githubactionsearch.py https://github.com/your-org --start-date 2024-03-10 --end-date 2024-03-15
```

## Options

- `-r REPO` - Scan only specific repository
- `-d N` - Scan N pages of workflow runs (30 runs per page)
- `-u N` - Scan N unique workflow types (0=all types)
- `-m N` - Scan maximum N repositories
- `-w N` - Use N parallel workers (default 10)
- `-f` - Full scan (all workflows, max history)
- `-o FILE` - Output file (default results.txt)
- `--start-date YYYY-MM-DD` - Filter from this date
- `--end-date YYYY-MM-DD` - Filter until this date
- `-v` - Verbose output with API rate info

## Technical Details

**Workflows vs. Runs**: The script scans workflow runs (individual execution instances), not workflow definitions.

## License

MIT License
