#!/usr/bin/env python3
import os
import sys

def main():
    print("=" * 50)
    print("🐋 Hello World from Docker Action!")
    print("=" * 50)
    print()
    
    print("📍 Environment Information:")
    print(f"  • Python Version: {sys.version.split()[0]}")
    print(f"  • Container Workdir: {os.getcwd()}")
    print()
    
    print("🔧 GitHub Context:")
    print(f"  • Repository: {os.environ.get('GITHUB_REPOSITORY', 'Not set')}")
    print(f"  • Workflow: {os.environ.get('GITHUB_WORKFLOW', 'Not set')}")
    print(f"  • Run ID: {os.environ.get('GITHUB_RUN_ID', 'Not set')}")
    print(f"  • Actor: {os.environ.get('GITHUB_ACTOR', 'Not set')}")
    print()
    
    print("✅ Docker action executed successfully!")
    print("=" * 50)

if __name__ == "__main__":
    main()