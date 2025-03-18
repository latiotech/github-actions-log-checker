# GitHub Actions Log Checker

This repository contains a script `githubactionsearch.py` used to scan GitHub Actions logs for secrets and credentials encoded in base64 format. The script is designed to help identify potential security vulnerabilities by detecting sensitive information that may have been inadvertently exposed in workflow logs.

## Features
- Scans all or specific repositories within a GitHub organization.
- Retrieves and analyzes workflow runs for potential secrets.
- Supports parallel processing for efficient scanning.
- Provides detailed output of detected secrets, including their type and location.
- Option to save results to an output file.
- Date-based filtering to scan workflows within specific timeframes.
- Full scan mode to check all available workflows.

## Understanding Workflows vs. Runs

In GitHub Actions:
- **Workflow**: A configurable automated process defined in a YAML file (e.g., "Build and Test", "Deploy to Production")
- **Run**: A specific execution instance of a workflow that occurs when the workflow is triggered

This script primarily works with workflow runs (individual executions) rather than workflows themselves.

## GitHub API Rate Limits

The script makes multiple API calls to GitHub:
- One call to list repositories
- One call per page of workflow runs requested
- One call per workflow run to download logs

GitHub enforces the following rate limits:
- **Authenticated requests**: 5,000 requests per hour
- **Unauthenticated requests**: 60 requests per hour

### ⚠️ Rate Limit Warnings

1. **For large organizations**: Scanning all repositories in a large organization with many workflow runs can easily exceed rate limits. Consider using `-m` to limit the number of repositories.

2. **For full scans**: Using the `-f` flag on multiple repositories will make a very large number of API calls:
   - ~100 API calls per repository to list workflow runs
   - ~3,000 API calls per repository to download logs
   
3. **Estimated API calls**:
   - Default scan of 50 repos: ~1,500 API calls
   - Full scan of a single repo: ~3,100 API calls  
   - Full scan of 50 repos: ~155,000 API calls (would require multiple days due to rate limits)

The script includes automatic handling for rate limits by pausing when limits are reached, but for large scans, you may need to run over multiple sessions.

## Setup

### Prerequisites
- Python 3.x
- GitHub CLI (for authentication)
- Trufflehog (for scanning decoded content)

### Authentication

#### Option 1: Using GitHub CLI (Recommended)
To authenticate with the GitHub API, you need to set up a GitHub token:
1. Log in with GitHub CLI:
   ```bash
   gh auth login
   ```
2. Get your token:
   ```bash
   gh auth status -t
   ```
3. Set the environment variable:
   ```bash
   export GITHUB_TOKEN='paste_token_here'
   ```

#### Option 2: Creating a Personal Access Token (PAT) manually
You can also create a Personal Access Token manually through the GitHub website:
1. Go to your GitHub account settings: https://github.com/settings/tokens
2. Click "Generate new token" (or "Generate new token (classic)")
3. Add a note to identify the token (e.g., "GitHub Actions Log Checker")
4. Select the necessary scopes (at minimum: `repo` for private repositories, or `public_repo` for public repositories only)
5. Click "Generate token"
6. Copy the generated token and set it as an environment variable:
   ```bash
   export GITHUB_TOKEN='paste_token_here'
   ```
   
> **Note**: Be sure to save your token securely as GitHub will only display it once.

## Quick Start

# Install dependencies
pip install -r requirements.txt

# Set up authentication
export GITHUB_TOKEN='your_token'

# Run a basic scan
python githubactionsearch.py https://github.com/your-organization -m 3

## Usage

### Examples

- **Scan all repos, but only the most recent workflow runs (max 30 runs)**
  ```bash
  python githubactionsearch.py https://github.com/your-org
  ```
  *This examines the 30 most recent workflow runs from each repository, limited to 5 different workflow types.*

- **Scan all repos, looking at more workflow runs (max 150 runs per repo)**
  ```bash
  python githubactionsearch.py https://github.com/your-org -d 5
  ```
  *This fetches 5 pages of workflow runs (about 150 total) per repository, still limited to 5 workflow types.*

- **Scan only a specific repository, with more workflow runs**
  ```bash
  python githubactionsearch.py https://github.com/your-org -r your-repo -d 10
  ```
  *This fetches 10 pages of workflow runs (about 300 runs) from only the specified repository.*

- **Scan at most 3 repos, with just the most recent workflow runs**
  ```bash
  python githubactionsearch.py https://github.com/your-org -m 3
  ```
  *This limits scanning to only 3 repositories, examining only the 30 most recent workflow runs per repo.*

- **Scan for runs from 5 different workflow types in each repository**
  ```bash
  python githubactionsearch.py https://github.com/your-org -u 5
  ```
  *This examines runs from the 5 most recently executed different workflow types in each repository.*

- **Run a full scan on all available workflow runs**
  ```bash
  python githubactionsearch.py https://github.com/your-org -f
  ```
  *This fetches up to 100 pages (about 3000 workflow runs) and includes runs from all workflow types.*

- **Scan workflow runs from a specific date range**
  ```bash
  python githubactionsearch.py https://github.com/your-org --start-date 2023-01-01 --end-date 2023-12-31
  ```
  *This only examines workflow runs that were created during the 2023 calendar year.*

- **Save scan results to a custom output file**
  ```bash
  python githubactionsearch.py https://github.com/your-org -o custom-results.txt
  ```
  *This writes all detected secrets to "custom-results.txt" instead of the default "results.txt" file.*

### Recommended Approaches for Large Organizations

1. **Start with a limited scan** to assess the volume:
   ```bash
   python githubactionsearch.py https://github.com/your-org -m 5
   ```

2. **Focus on specific repositories** of concern:
   ```bash
   python githubactionsearch.py https://github.com/your-org -r high-risk-repo -f
   ```

3. **Use date filtering** to scan specific time periods:
   ```bash
   python githubactionsearch.py https://github.com/your-org --start-date 2023-06-01 --end-date 2023-06-30
   ```

### Scanning for Known GitHub Actions Attacks

1. **Check for the "reviewdog attack" (March 11, 2024)**:
   ```bash
   python githubactionsearch.py https://github.com/your-org --start-date 2024-03-10 --end-date 2024-03-12
   ```
   *This examines workflow runs during the timeframe of the reviewdog GitHub Actions compromise.*

2. **Check for the "tj-actions attack" (March 14, 2024)**:
   ```bash
   python githubactionsearch.py https://github.com/your-org --start-date 2024-03-13 --end-date 2024-03-15
   ```
   *This examines workflow runs during the timeframe of the tj-actions GitHub Actions compromise.*

3. **Check both attack windows**:
   ```bash
   python githubactionsearch.py https://github.com/your-org --start-date 2024-03-10 --end-date 2024-03-15
   ```
   *This covers both attack periods with a single scan.*

4. **Focus on a specific repository during attack timeframes**:
   ```bash
   python githubactionsearch.py https://github.com/your-org -r critical-repo --start-date 2024-03-10 --end-date 2024-03-15
   ```
   *This focuses on a single repository during the known attack windows.*

## Options
- `-d`, `--workflow-depth`: Number of pages of workflow runs to scan per repository (1 page ≈ 30 runs).
- `-u`, `--unique-workflows`: Maximum number of unique workflow types to scan (default is 5).
- `-r`, `--repo`: Scan only a specific repository.
- `-m`, `--max-repos`: Maximum number of repositories to scan (default is all).
- `-w`, `--workers`: Number of parallel workers (default is 10).
- `-v`, `--verbose`: Show verbose output including API rate limit info.
- `-o`, `--output-file`: Path to output file for saving detected secrets (default is "results.txt").
- `-f`, `--full`: Run a full check on all available workflows (overrides -d and -u).
- `--start-date`: Start date for workflow filtering (format: YYYY-MM-DD).
- `--end-date`: End date for workflow filtering (format: YYYY-MM-DD).

## License
This project is licensed under the MIT License.

# Install required dependencies
pip install requests
pip install trufflehog  # For enhanced secret detection
