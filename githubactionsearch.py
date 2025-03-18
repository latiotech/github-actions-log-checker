#!/usr/bin/env python3
import sys
import re
import requests
import io
import zipfile
import os
import concurrent.futures
import tempfile
import subprocess
import json
import time
import threading
from urllib.parse import urlparse
import argparse
import datetime

GITHUB_API = "https://api.github.com"
MAX_WORKERS = 10  # Number of parallel workers

# Progress tracking variables
progress = {
    "total_repos": 0,
    "processed_repos": 0,
    "total_runs": 0,
    "processed_runs": 0,
    "secrets_found": 0,
    "current_repo": "",
    "stop_spinner": False,
    "spinner_started": False  # Add this flag to track if spinner is running
}

def spinner():
    """Display an animated spinner to indicate the script is working."""
    spinner_chars = "|/-\\"
    i = 0
    
    # Mark spinner as started
    progress["spinner_started"] = True
    
    while not progress["stop_spinner"]:
        status = f"[{spinner_chars[i % len(spinner_chars)]}] "
        status += f"Repos: {progress['processed_repos']}/{progress['total_repos']} | "
        status += f"Runs: {progress['processed_runs']}/{progress['total_runs']} | "
        status += f"Secrets: {progress['secrets_found']}"
        if progress["current_repo"]:
            status += f" | Current: {progress['current_repo']}"
        
        sys.stdout.write('\r' + status)
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    
    # Clear the spinner line when done
    sys.stdout.write('\r' + ' ' * len(status) + '\r')
    sys.stdout.flush()
    
    # Mark spinner as stopped
    progress["spinner_started"] = False

# Start the spinner in a separate thread
def start_spinner():
    # Make sure we don't start multiple spinners
    if progress["spinner_started"]:
        return None
        
    spinner_thread = threading.Thread(target=spinner)
    spinner_thread.daemon = True
    spinner_thread.start()
    
    # Ensure spinner has time to start
    time.sleep(0.2)
    
    return spinner_thread

# Get GitHub token from environment variable
def get_github_token():
    """
    Get GitHub token from environment variable.
    
    To set up authentication:
    1. Log in with GitHub CLI:
       $ gh auth login
    
    2. Get your token with:
       $ gh auth status -t
    
    3. Copy the token value after "Token:" and set the environment variable:
       $ export GITHUB_TOKEN='paste_token_here'
    """
    # Check environment variable
    token = os.environ.get("GITHUB_TOKEN")
    
    if not token:
        print("ERROR: GitHub token not found in environment.")
        print("\nTo authenticate with GitHub API:")
        print("1. Log in with GitHub CLI:   gh auth login")
        print("2. Get your token:           gh auth status -t")
        print("3. Set environment variable: export GITHUB_TOKEN='paste_token_here'")
        print("\nAuthentication is required to use this script.")
        sys.exit(1)
    else:
        # Only show first few characters for security
        print(f"Using GitHub token: {token[:4]}...")
        
    return token

def get_auth_headers(token=None):
    """Create headers with authentication if token is available."""
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    return headers

def get_public_repos(org, token=None):
    """Retrieve all public repositories for the given organization."""
    repos = []
    url = f"{GITHUB_API}/orgs/{org}/repos?type=public&per_page=100"
    headers = get_auth_headers(token)
    while url:
        r = requests.get(url, headers=headers)
        if r.status_code == 403 and "rate limit exceeded" in r.text.lower():
            reset_time = int(r.headers.get('X-RateLimit-Reset', 0))
            if reset_time > 0:
                wait_time = max(reset_time - int(time.time()), 0) + 5
                print(f"\nRate limit exceeded. Waiting {wait_time} seconds for reset...")
                time.sleep(wait_time)
                # Try again after waiting
                continue
        if r.status_code != 200:
            print(f"Error fetching repos for organization {org}: {r.status_code} {r.text}")
            break
        repos.extend(r.json())
        url = r.links.get("next", {}).get("url")
    return repos

def get_workflow_runs(owner, repo, token=None, max_pages=1, unique_workflows=5, start_date=None, end_date=None):
    """Retrieve workflow runs with controlled pagination and unique workflow filtering.
    
    Args:
        owner: Repository owner/organization
        repo: Repository name
        token: GitHub API token
        max_pages: Maximum number of pages to retrieve (30 runs per page)
        unique_workflows: Maximum number of unique workflow types to include
                         (0 = include all workflows)
        start_date: Optional start date for filtering workflow runs (format: YYYY-MM-DD)
        end_date: Optional end date for filtering workflow runs (format: YYYY-MM-DD)
    """
    runs = []
    url = f"{GITHUB_API}/repos/{owner}/{repo}/actions/runs?per_page=30"
    headers = get_auth_headers(token)
    
    page_count = 0
    seen_workflows = set()  # Track unique workflow names
    
    while url and page_count < max_pages:
        page_count += 1
        
        r = requests.get(url, headers=headers)
        if r.status_code == 403 and "rate limit exceeded" in r.text.lower():
            reset_time = int(r.headers.get('X-RateLimit-Reset', 0))
            if reset_time > 0:
                wait_time = max(reset_time - int(time.time()), 0) + 5
                print(f"\nRate limit exceeded. Waiting {wait_time} seconds for reset...")
                time.sleep(wait_time)
                page_count -= 1  # Don't count this as a page
                continue
                
        if r.status_code != 200:
            print(f"Error fetching workflow runs for {owner}/{repo}: {r.status_code}")
            break
            
        data = r.json()
        
        # Filter by date if provided
        date_filtered_runs = []
        for run in data.get("workflow_runs", []):
            # Check date range if provided
            if start_date or end_date:
                run_date_str = run.get("created_at", "").split("T")[0]  # Extract YYYY-MM-DD
                run_date = datetime.datetime.strptime(run_date_str, "%Y-%m-%d").date() if run_date_str else None
                
                if run_date:
                    # Skip if before start_date
                    if start_date and run_date < start_date:
                        continue
                    # Skip if after end_date
                    if end_date and run_date > end_date:
                        continue
            
            date_filtered_runs.append(run)
        
        # Apply unique workflow filtering
        if unique_workflows > 0:
            filtered_runs = []
            for run in date_filtered_runs:
                workflow_name = run.get("name", "")
                # Include if we haven't reached the unique workflow limit yet
                if workflow_name not in seen_workflows:
                    if len(seen_workflows) < unique_workflows:
                        seen_workflows.add(workflow_name)
                        filtered_runs.append(run)
                # Always include runs from workflows we've already seen
                elif workflow_name in seen_workflows:
                    filtered_runs.append(run)
            
            runs.extend(filtered_runs)
            
            # If we've reached our unique workflow limit and have runs, don't fetch more pages
            if len(seen_workflows) >= unique_workflows and runs:
                break
        else:
            # No unique workflow filtering, include all date-filtered runs
            runs.extend(date_filtered_runs)
        
        # Only follow the next link if we haven't reached max_pages
        if page_count < max_pages:
            url = r.links.get("next", {}).get("url")
        else:
            url = None
    
    return runs

def get_run_logs(owner, repo, run_id, token=None):
    """Download the logs (ZIP file) for a given workflow run."""
    url = f"{GITHUB_API}/repos/{owner}/{repo}/actions/runs/{run_id}/logs"
    headers = get_auth_headers(token)
    r = requests.get(url, headers=headers, allow_redirects=True)
    
    if r.status_code == 410:
        # Logs have been deleted due to retention policy or manual deletion
        return None
    elif r.status_code != 200:
        return None
        
    return r.content

# Precompile regex patterns for performance
BASE64_REGEX = re.compile(r'\b(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b')
PRINTABLE_CHARS_REGEX = re.compile(r'^[\x20-\x7E\s]*$')
CRED_PATTERN_REGEX = re.compile(r'[A-Za-z0-9_\-]{8,}')
NO_SPACES_REGEX = re.compile(r'\s')
BASE64_VALIDATION_REGEX = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')
COMMON_VALUES = {'true', 'false', 'null', 'undefined', ''}

def is_printable(text):
    """Check if text contains only printable characters."""
    return PRINTABLE_CHARS_REGEX.match(text) is not None

def search_base64_in_zip(zip_content, base64_regex=BASE64_REGEX):
    """Extract files from the ZIP content, decode base64 strings, and scan with Trufflehog."""
    import base64 as b64module
    matches = {}
    
    try:
        with zipfile.ZipFile(io.BytesIO(zip_content)) as z:
            # Create temporary directory for decoded content
            with tempfile.TemporaryDirectory() as temp_dir:
                for filename in z.namelist():
                    try:
                        # Skip files that are unlikely to contain secrets
                        if any(skip in filename.lower() for skip in ['.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg']):
                            continue
                            
                        with z.open(filename) as f:
                            content = f.read().decode('utf-8', errors='ignore')
                            found = base64_regex.findall(content)
                            
                            if found:
                                # Process and save decoded content for Trufflehog scanning
                                decoded_file = os.path.join(temp_dir, f"decoded_{filename.replace('/', '_')}.txt")
                                double_decoded_file = os.path.join(temp_dir, f"double_decoded_{filename.replace('/', '_')}.txt")
                                
                                with open(decoded_file, 'w') as df:
                                    # Write all decoded base64 strings to a file
                                    for encoded in set(found):
                                        try:
                                            decoded = b64module.b64decode(encoded).decode('utf-8', errors='ignore')
                                            if is_printable(decoded) and decoded.strip():
                                                df.write(decoded)
                                                df.write("\n")
                                                
                                                # Try double decoding
                                                if BASE64_VALIDATION_REGEX.match(decoded):
                                                    try:
                                                        double_decoded = b64module.b64decode(decoded).decode('utf-8', errors='ignore')
                                                        if is_printable(double_decoded) and double_decoded.strip():
                                                            with open(double_decoded_file, 'a') as ddf:
                                                                ddf.write(double_decoded)
                                                                ddf.write("\n")
                                                    except:
                                                        pass
                                        except:
                                            continue
                                
                                # Run our own detection on decoded content
                                potential_secrets = []
                                for encoded in set(found):
                                    secret_info = analyze_potential_secret(encoded)
                                    if secret_info:
                                        potential_secrets.append(secret_info)
                                
                                # Run Trufflehog on the decoded files
                                if os.path.exists(decoded_file) and os.path.getsize(decoded_file) > 0:
                                    trufflehog_results = run_trufflehog(decoded_file)
                                    for result in trufflehog_results:
                                        potential_secrets.append({
                                            'encoded': 'From Trufflehog scan',
                                            'decoded': result.get('match', ''),
                                            'type': result.get('detector_type', 'TRUFFLEHOG_DETECTED'),
                                            'source': 'trufflehog'
                                        })
                                
                                # Run Trufflehog on double-decoded content
                                if os.path.exists(double_decoded_file) and os.path.getsize(double_decoded_file) > 0:
                                    trufflehog_results = run_trufflehog(double_decoded_file)
                                    for result in trufflehog_results:
                                        potential_secrets.append({
                                            'encoded': 'From Trufflehog scan (double-decoded)',
                                            'double_decoded': result.get('match', ''),
                                            'type': result.get('detector_type', 'TRUFFLEHOG_DETECTED'),
                                            'double_encoded': True,
                                            'source': 'trufflehog'
                                        })
                                
                                if potential_secrets:
                                    matches[filename] = potential_secrets
                    except Exception as e:
                        continue
                        
    except zipfile.BadZipFile:
        pass
    
    return matches

def run_trufflehog(file_path):
    """Run Trufflehog on a file and return the results."""
    try:
        # Check if trufflehog is installed
        result = subprocess.run(['which', 'trufflehog'], capture_output=True, text=True)
        if result.returncode != 0:
            print("Trufflehog not found. Please install it with: pip install trufflehog")
            return []
            
        # Run trufflehog on the file
        cmd = ['trufflehog', 'filesystem', '--json', file_path]
        process = subprocess.run(cmd, capture_output=True, text=True)
        
        if process.returncode != 0 and process.returncode != 183:  # 183 is success with results
            return []
            
        # Parse JSON results (one per line)
        results = []
        for line in process.stdout.splitlines():
            if line.strip():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
                    
        return results
    except Exception as e:
        return []

def detect_secret_type(text):
    """Detect if the text contains patterns matching known secret types."""
    # AWS Access Key (high confidence pattern)
    if re.search(r'AKIA[0-9A-Z]{16}', text):
        return 'AWS_ACCESS_KEY'
        
    # GitHub tokens (high confidence pattern)
    if re.search(r'gh[oprsu]_[a-zA-Z0-9]{20,}', text):
        return 'GITHUB_TOKEN'
        
    # Private keys or certificates
    if '-----BEGIN' in text and '-----END' in text:
        if 'PRIVATE KEY' in text:
            return 'PRIVATE_KEY'
        if 'CERTIFICATE' in text:
            return 'CERTIFICATE'
            
    # API keys with explicit labels
    if re.search(r'api[_-]?key|key[_-]?id|access[_-]?key|secret[_-]?key', text.lower()):
        return 'API_KEY'
        
    # Skip more generic patterns unless they're explicitly needed
    return None

def extract_org_from_url(org_url):
    """Extract the organization name from the provided GitHub URL."""
    parsed = urlparse(org_url)
    if parsed.netloc.lower() != "github.com":
        print("Provided URL must be from github.com")
        sys.exit(1)
    path_parts = parsed.path.strip("/").split("/")
    if not path_parts or path_parts[0] == "":
        print("Invalid URL: no organization found.")
        sys.exit(1)
    return path_parts[0]

def process_run(owner, repo_name, run, token):
    """Process a single workflow run and return any secrets found."""
    run_id = run.get("id")
    run_url = run.get("html_url")
    
    try:
        logs_content = get_run_logs(owner, repo_name, run_id, token)
        if not logs_content:
            return []
        
        matches = search_base64_in_zip(logs_content)
        if not matches:
            return []
            
        results = []
        for filename, secrets in matches.items():
            for secret in secrets:
                secret_type = secret.get('type', 'UNKNOWN')
                encoded = secret.get('encoded', 'Unknown encoded string')
                decoded = secret.get('decoded', 'Unable to decode')
                double_decoded = secret.get('double_decoded', None)
                
                # Prepare result object
                result = {
                    'type': secret_type,
                    'encoded': encoded,
                    'decoded': decoded,
                    'value': double_decoded if double_decoded else decoded,
                    'double_encoded': bool(double_decoded),
                    'repo': f"{owner}/{repo_name}",
                    'run_url': run_url,
                    'filename': filename
                }
                results.append(result)
        return results
    except Exception:
        return []

def analyze_potential_secret(encoded_string):
    """
    Analyze a base64 encoded string to determine if it might be a secret.
    Returns a dict with info about the potential secret, or None if it's likely not a secret.
    """
    # Check for valid base64 format
    try:
        import base64 as b64module
        # First level decoding
        decoded = b64module.b64decode(encoded_string).decode('utf-8', errors='ignore')
        
        # Skip if not printable or empty
        if not is_printable(decoded) or not decoded.strip():
            return None
            
        # Skip common values that aren't secrets
        if decoded.strip().lower() in COMMON_VALUES:
            return None
            
        # Check for secret patterns
        secret_type = detect_secret_type(decoded)
        
        # Try second level decoding
        double_decoded = None
        double_secret_type = None
        if BASE64_VALIDATION_REGEX.match(decoded):
            try:
                double_decoded = b64module.b64decode(decoded).decode('utf-8', errors='ignore')
                if is_printable(double_decoded) and double_decoded.strip():
                    double_secret_type = detect_secret_type(double_decoded)
            except:
                pass
        
        # Return info about the potential secret
        if secret_type:
            return {
                'encoded': encoded_string[:10] + '...' if len(encoded_string) > 10 else encoded_string,
                'decoded': decoded,
                'type': secret_type
            }
            
        if double_secret_type:
            return {
                'encoded': encoded_string[:10] + '...' if len(encoded_string) > 10 else encoded_string,
                'decoded': decoded,
                'double_decoded': double_decoded,
                'type': double_secret_type,
                'double_encoded': True
            }
            
        # For strings that look like credentials without a specific pattern
        if len(decoded) > 8 and CRED_PATTERN_REGEX.search(decoded) and not NO_SPACES_REGEX.search(decoded):
            return {
                'encoded': encoded_string[:10] + '...' if len(encoded_string) > 10 else encoded_string,
                'decoded': decoded,
                'type': 'POTENTIAL_CREDENTIAL'
            }
            
    except Exception:
        pass
        
    return None

def main():
    """Main function with improved CLI experience."""
    parser = argparse.ArgumentParser(
        description="Scan GitHub Actions logs for secrets and credentials in base64 format.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument("org_url", help="GitHub organization URL (e.g., https://github.com/organization)")
    parser.add_argument("-d", "--workflow-depth", type=int, default=1, 
                        help="Number of workflow runs to scan per repository (1=most recent only)")
    parser.add_argument("-u", "--unique-workflows", type=int, default=5,
                        help="Maximum number of unique workflow types to scan (0=all workflows)")
    parser.add_argument("-r", "--repo", help="Scan only a specific repository")
    parser.add_argument("-m", "--max-repos", type=int, default=0,
                        help="Maximum number of repositories to scan (0=all)")
    parser.add_argument("-w", "--workers", type=int, default=MAX_WORKERS,
                        help="Number of parallel workers")
    parser.add_argument("-v", "--verbose", action="store_true", 
                        help="Show verbose output including API rate limit info")
    parser.add_argument("-o", "--output-file", type=str, default="results.txt",
                        help="Path to output file for saving detected secrets")
    parser.add_argument("-f", "--full", action="store_true",
                        help="Run a full check on all workflows (overrides -d and -u)")
    parser.add_argument("--start-date", type=lambda d: datetime.datetime.strptime(d, "%Y-%m-%d").date(),
                        help="Start date for workflow filtering (format: YYYY-MM-DD)")
    parser.add_argument("--end-date", type=lambda d: datetime.datetime.strptime(d, "%Y-%m-%d").date(),
                        help="End date for workflow filtering (format: YYYY-MM-DD)")
    
    args = parser.parse_args()
    
    # Handle --full option (overrides workflow-depth and unique-workflows)
    if args.full:
        args.workflow_depth = 100  # High number to get more pages
        args.unique_workflows = 0  # No limit on unique workflows
    
    # Extract organization name from URL
    org = extract_org_from_url(args.org_url)
    token = get_github_token()
    
    # Initial setup message
    if args.repo:
        print(f"Scanning only {org}/{args.repo} repository")
    else:
        repos_msg = "all repositories" if args.max_repos == 0 else f"up to {args.max_repos} repositories"
        print(f"Scanning {repos_msg} in {org} organization")
    
    if args.full:
        print(f"Running FULL check on all available workflows")
    else:
        print(f"Scanning {args.workflow_depth} most recent workflow run(s) per repository")
        
        if args.unique_workflows > 0:
            print(f"Limiting to {args.unique_workflows} unique workflow types per repository")
        else:
            print("Scanning all workflow types in each repository")
    
    # Display date filtering if active
    if args.start_date or args.end_date:
        date_range = ""
        if args.start_date:
            date_range += f"from {args.start_date.isoformat()}"
        if args.end_date:
            date_range += f" to {args.end_date.isoformat()}" if date_range else f"until {args.end_date.isoformat()}"
        print(f"Filtering workflows by date: {date_range}")
    
    # Start the spinner immediately to show activity
    spinner_thread = start_spinner()
    
    # Fetch repositories - either all or just the specified one
    all_runs = []
    
    if args.repo:
        # Skip fetching all repos - just use the one specified
        progress["current_repo"] = f"Fetching workflow runs for {org}/{args.repo}..."
        progress["total_repos"] = 1
        
        # Get only the specified number of workflow runs with unique workflow limiting
        runs = get_workflow_runs(org, args.repo, token, 
                                max_pages=args.workflow_depth,
                                unique_workflows=args.unique_workflows,
                                start_date=args.start_date,
                                end_date=args.end_date)
        
        for run in runs:
            all_runs.append((org, args.repo, run))
        
        progress["processed_repos"] = 1
    else:
        # Process all repos (or max number specified)
        progress["current_repo"] = f"Fetching repos for {org}..."
        
        repos = get_public_repos(org, token)
        
        # Limit number of repositories if specified
        if args.max_repos > 0 and len(repos) > args.max_repos:
            if args.verbose:
                print(f"\nLimiting scan to {args.max_repos} repositories (out of {len(repos)} total)")
            repos = repos[:args.max_repos]
        
        progress["total_repos"] = len(repos)
        
        # Fetch workflow runs for each repository
        for idx, repo in enumerate(repos):
            repo_name = repo.get("name")
            owner = repo.get("owner", {}).get("login")
            
            # Update progress
            progress["current_repo"] = f"{owner}/{repo_name} ({idx+1}/{len(repos)})"
            progress["processed_repos"] = idx  # Show progress during fetching phase
            
            # Get workflow runs with unique workflow filtering
            runs = get_workflow_runs(owner, repo_name, token, 
                                    max_pages=args.workflow_depth,
                                    unique_workflows=args.unique_workflows,
                                    start_date=args.start_date,
                                    end_date=args.end_date)
            
            for run in runs:
                all_runs.append((owner, repo_name, run))
    
    progress["total_runs"] = len(all_runs)
    progress["processed_repos"] = 0  # Reset for the processing phase
    
    # Prepare output file
    output_file = open(args.output_file, 'w')
    print(f"Results will be saved to: {args.output_file}")
    
    # Use ThreadPoolExecutor for parallel processing
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        # Submit all tasks
        future_to_run = {
            executor.submit(process_run, owner, repo_name, run, token): (owner, repo_name)
            for owner, repo_name, run in all_runs
        }
        
        # Process results as they complete
        for future in concurrent.futures.as_completed(future_to_run):
            owner, repo_name = future_to_run[future]
            progress["processed_runs"] += 1
            
            results = future.result()
            for result in results:
                # Count secrets found
                progress["secrets_found"] += 1
                
                # Print each secret found (temporarily stopping the spinner)
                progress["stop_spinner"] = True
                secret_output = (
                    f"\n{'='*80}\n"
                    f"POSSIBLE SECRET [{result['type']}]\n"
                    f"  Encoded: {result['encoded']}\n"
                    f"  Decoded: {result['value']}\n"
                    f"  Repo: {result['repo']}\n"
                    f"  Run: {result['run_url']}\n"
                    f"  File: {result['filename']}\n"
                    f"{'='*80}\n"
                )
                print(secret_output)
                
                # Write to output file
                output_file.write(secret_output)
                
                progress["stop_spinner"] = False
            
            # Update processed repos if this is the last run for the repo
            if all(progress["processed_runs"] >= progress["total_runs"] or 
                   future_to_run[f][0] != owner or future_to_run[f][1] != repo_name 
                   for f in future_to_run if not f.done()):
                progress["processed_repos"] += 1
    
    # Close the output file
    output_file.close()
    
    # Stop the spinner
    progress["stop_spinner"] = True
    spinner_thread.join(timeout=1.0)
    
    # Final summary
    print(f"\nScan complete: {progress['processed_repos']} repositories, "
          f"{progress['processed_runs']} workflow runs, "
          f"{progress['secrets_found']} potential secrets found.")
    
    # Add reminder about output file location
    if progress['secrets_found'] > 0:
        print(f"Results have been saved to: {args.output_file}")

if __name__ == "__main__":
    main()
