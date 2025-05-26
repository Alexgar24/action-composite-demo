#!/usr/bin/env python3

print("Hello World from Composite Action!")
print("This is a simple Python script running inside a GitHub Action.")
print(f"Action path: {__import__('os').environ.get('GITHUB_ACTION_PATH', 'Not set')}")
print(f"Workspace: {__import__('os').environ.get('GITHUB_WORKSPACE', 'Not set')}")
print(f"Repository: {__import__('os').environ.get('GITHUB_REPOSITORY', 'Not set')}")