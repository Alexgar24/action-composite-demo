#!/usr/bin/env python3
import os
import sys
import json
import subprocess
from pathlib import Path

def run_command(cmd, capture_output=True):
    """Run a shell command and return output."""
    print(f"Running: {' '.join(cmd)}")
    
    if capture_output:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error: {result.stderr}")
        return result
    else:
        # For commands that need to show output in real-time
        return subprocess.run(cmd)

def scan_terraform(directory, severity_threshold, exit_code, output_format):
    """Run Trivy scan on Terraform files."""
    print("=" * 60)
    print("🔍 Trivy Terraform Security Scanner")
    print("=" * 60)
    print()
    
    # Get absolute path
    scan_path = Path(directory).absolute()
    
    print(f"📁 Scanning directory: {scan_path}")
    print(f"🎯 Severity threshold: {severity_threshold}")
    print(f"📊 Output format: {output_format}")
    print()
    
    # Check if directory exists
    if not scan_path.exists():
        print(f"❌ Error: Directory '{scan_path}' not found!")
        return 1
    
    # Count Terraform files
    tf_files = list(scan_path.rglob("*.tf"))
    print(f"📄 Found {len(tf_files)} Terraform files")
    
    if not tf_files:
        print("⚠️  No Terraform files found in the specified directory")
        return 0
    
    # Build Trivy command
    cmd = [
        "trivy",
        "config",
        str(scan_path),
        "--severity", severity_threshold,
        "--exit-code", str(exit_code),
        "--format", output_format
    ]
    
    # Add additional options based on format
    if output_format == "json":
        cmd.extend(["--quiet"])
        
    # Add output file if specified
    output_file = os.environ.get("INPUT_OUTPUT-FILE", "")
    output_file_path = None
    
    if output_file:
        # Make it absolute path to ensure we can find it later
        output_file_path = Path(output_file).absolute()
        cmd.extend(["-o", str(output_file_path)])
        print(f"💾 Results will be saved to: {output_file_path}")
    
    print("\n" + "=" * 60)
    print("🚀 Starting Trivy scan...")
    print("=" * 60 + "\n")
    
    # Run Trivy scan
    result = run_command(cmd, capture_output=False)
    
    print("\n" + "=" * 60)
    
    # Set outputs
    if result.returncode == 0:
        print("✅ Scan completed successfully - No issues found!")
        set_output("scan-result", "success")
        set_output("issues-found", "false")
    else:
        if int(exit_code) > 0:
            print(f"❌ Scan found security issues above {severity_threshold} severity!")
            set_output("scan-result", "failed")
            set_output("issues-found", "true")
        else:
            print(f"⚠️  Scan found issues but exit-code is 0")
            set_output("scan-result", "success-with-issues")
            set_output("issues-found", "true")
    
    # If output file was created, set its path
    if output_file_path and output_file_path.exists():
        set_output("results-file", str(output_file_path))
    
    print("=" * 60)

    # Write to summary (pass the actual file path)
    write_summary(scan_path, severity_threshold, result.returncode != 0, output_format, output_file_path)
    
    return result.returncode

def set_output(name, value):
    """Set GitHub Action output."""
    output_file = os.environ.get('GITHUB_OUTPUT')
    if output_file:
        with open(output_file, 'a') as f:
            f.write(f"{name}={value}\n")
    else:
        # Fallback for local testing
        print(f"::set-output name={name}::{value}")

def write_summary(scan_path, severity_threshold, issues_found, output_format, output_file_path):
    """Write scan results to GitHub Actions summary."""
    summary_file = os.environ.get('GITHUB_STEP_SUMMARY')
    if not summary_file:
        return
    
    with open(summary_file, 'a') as f:
        f.write("## 🛡️ Trivy Security Scan Results\n\n")
        f.write(f"**Scanned Path:** `{scan_path}`\n\n")
        f.write(f"**Severity Filter:** `{severity_threshold}`\n\n")
        
        if issues_found:
            f.write("### ❌ Security Issues Found!\n\n")
            f.write("Run Trivy locally to see detailed results:\n")
            f.write("```bash\n")
            f.write(f"trivy config {scan_path} --severity {severity_threshold}\n")
            f.write("```\n\n")
            
            # If we have a results file, try to parse and display it
            if output_file_path and output_file_path.exists() and output_format == "json":
                try:
                    with open(output_file_path, 'r') as rf:
                        results = json.load(rf)
                        
                    f.write("### Top Security Issues:\n\n")
                    f.write("| Severity | Type | Title | Resource |\n")
                    f.write("|----------|------|-------|----------|\n")
                    
                    issue_count = 0
                    for result in results.get('Results', []):
                        for misconfig in result.get('Misconfigurations', []):
                            if issue_count >= 10:  # Limit to top 10
                                break
                            severity = misconfig.get('Severity', 'UNKNOWN')
                            title = misconfig.get('Title', 'N/A')
                            type_ = misconfig.get('Type', 'N/A')
                            resource = misconfig.get('CauseMetadata', {}).get('Resource', 'N/A')
                            
                            # Truncate long titles
                            if len(title) > 50:
                                title = title[:47] + "..."
                            
                            f.write(f"| {severity} | {type_} | {title} | `{resource}` |\n")
                            issue_count += 1
                    
                    if issue_count >= 10:
                        f.write("\n*Showing first 10 issues. Run scan locally for complete results.*\n")
                        
                except Exception as e:
                    f.write(f"\n*Could not parse detailed results: {e}*\n")
                    f.write(f"*Output file path: {output_file_path}*\n")
        else:
            f.write("### ✅ No Security Issues Found!\n\n")
            f.write("All Terraform configurations passed the security scan.\n")

def main():
    # Get inputs from environment variables
    directory = os.environ.get("INPUT_SCAN-DIRECTORY", "/github/workspace")
    severity = os.environ.get("INPUT_SEVERITY", "CRITICAL,HIGH")
    exit_code = os.environ.get("INPUT_EXIT-CODE", "1")
    output_format = os.environ.get("INPUT_FORMAT", "table")
    
    # Show GitHub context
    print("🔧 GitHub Context:")
    print(f"  • Repository: {os.environ.get('GITHUB_REPOSITORY', 'Not set')}")
    print(f"  • Workflow: {os.environ.get('GITHUB_WORKFLOW', 'Not set')}")
    print(f"  • Actor: {os.environ.get('GITHUB_ACTOR', 'Not set')}")
    print()
    
    # Run the scan
    exit_status = scan_terraform(directory, severity, exit_code, output_format)
    
    sys.exit(exit_status)

if __name__ == "__main__":
    main()