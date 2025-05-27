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
    if output_file:
        cmd.extend(["-o", output_file])
        print(f"💾 Results will be saved to: {output_file}")
    
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
    if output_file and Path(output_file).exists():
        set_output("results-file", output_file)
    
    print("=" * 60)
    
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