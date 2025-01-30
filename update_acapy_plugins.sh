#!/bin/bash

# update_acapy_plugins.sh

# Ensure we exit on any error
set -e

# Usage information
usage() {
  echo "Usage: $0 [--mode test|release] [--new-tag NEW_TAG] [--new-branch NEW_BRANCH]"
  echo ""
  echo "Modes:"
  echo "  test     - Update for testing purposes using GitHub references"
  echo "  release  - Update using final, released packages from PyPI"
  echo ""
  echo "Options:"
  echo "  --new-tag      - The new tag version (e.g., 1.2.1-20250130)"
  echo "  --new-branch   - The new branch name for testing updates"
  exit 1
}

# Default values
MODE=""
NEW_TAG=""
NEW_BRANCH=""

# Parse command-line arguments
while [[ "$#" -gt 0 ]]; do
  case $1 in
  --mode)
    MODE="$2"
    shift 2
    ;;
  --new-tag)
    NEW_TAG="$2"
    shift 2
    ;;
  --new-branch)
    NEW_BRANCH="$2"
    shift 2
    ;;
  *)
    echo "Unknown parameter passed: $1"
    usage
    ;;
  esac
done

# Validate mandatory parameters
if [[ -z "$MODE" ]] || [[ -z "$NEW_TAG" ]]; then
  echo "Error: --mode and --new-tag are required."
  usage
fi

if [[ "$MODE" != "test" && "$MODE" != "release" ]]; then
  echo "Error: --mode must be either 'test' or 'release'."
  usage
fi

if [[ "$MODE" == "test" && -z "$NEW_BRANCH" ]]; then
  echo "Error: --new-branch is required in test mode."
  usage
fi

# Variables
OLD_TAG="1.2.0-20250127"                          # The old version tag to be replaced
TAG_VERSION=$(echo "$NEW_TAG" | sed 's/-/.post/') # e.g., 1.2.1-20250130 -> 1.2.1.post20250130

# Directories for plugins
GROUPS_PLUGIN_DIR="../acapy-wallet-groups-plugin"
NATS_PLUGIN_DIR="../aries-acapy-plugins/nats_events"
CLOUDAPI_DIR="../aries-cloudapi-python"

# Function to check and clean git state
check_git_state() {
  local dir=$1
  cd "$dir" || exit 1

  # Check for uncommitted changes
  if ! git diff --quiet HEAD; then
    echo "Error: Uncommitted changes found in $dir"
    echo "Please commit or stash changes before running this script"
    exit 1
  fi

  cd - >/dev/null || exit 1
}

# Function to update pyproject.toml based on mode
update_pyproject() {
  local plugin_dir=$1
  local plugin_type=$2 # "groups" or "nats"

  echo "Updating pyproject.toml in $plugin_dir for mode: $MODE"

  cd "$plugin_dir" || exit

  if [[ "$MODE" == "test" ]]; then
    if [[ "$plugin_type" == "groups" ]]; then
      # Update version and acapy-agent-didx to GitHub reference
      sed -i "s/version = \"$OLD_TAG\"/version = \"$NEW_TAG\"/" pyproject.toml
      sed -i "s/acapy-agent-didx = { version = \".*\", source = \"testpypi\" }/acapy-agent-didx = { git = \"https:\/\/github.com\/didx-xyz\/acapy\", branch = \"release-$NEW_TAG\" }/" pyproject.toml
    elif [[ "$plugin_type" == "nats" ]]; then
      # Update only acapy-agent-didx to GitHub reference
      sed -i "s/acapy-agent-didx = { version = \".*\", source = \"testpypi\" }/acapy-agent-didx = { git = \"https:\/\/github.com\/didx-xyz\/acapy\", branch = \"release-$NEW_TAG\" }/" pyproject.toml
    fi
  elif [[ "$MODE" == "release" ]]; then
    if [[ "$plugin_type" == "groups" ]]; then
      # Update version and acapy-agent-didx to PyPI source with post version
      sed -i "s/version = \"$OLD_TAG\"/version = \"$NEW_TAG\"/" pyproject.toml
      sed -i "s/acapy-agent-didx = { git = \".*\", branch = \".*\" }/acapy-agent-didx = { version = \"$TAG_VERSION\", source = \"testpypi\" }/" pyproject.toml
    elif [[ "$plugin_type" == "nats" ]]; then
      # Update acapy-agent-didx to PyPI source with post version
      sed -i "s/acapy-agent-didx = { git = \".*\", branch = \".*\" }/acapy-agent-didx = { version = \"$TAG_VERSION\", source = \"testpypi\" }/" pyproject.toml
    fi
  fi

  # Run poetry lock
  echo "Running poetry lock in $plugin_dir"
  poetry lock

  # Check if poetry lock succeeded
  if [ $? -ne 0 ]; then
    echo "Error: poetry lock failed in $plugin_dir"
    exit 1 # Exit the script with an error status
  fi

  cd - >/dev/null || exit
}

# Function to update pyproject.toml and handle git branches
update_plugin() {
  local plugin_dir=$1
  local git_dir=$2
  local plugin_type=$3 # "groups" or "nats"

  # Ensure the directory is up to date with origin
  echo "Switching to main branch in $git_dir, fetching and pulling latest changes"
  cd "$git_dir" || exit
  git checkout main
  git fetch origin --prune
  git pull origin main

  # Update pyproject.toml based on mode
  update_pyproject "$plugin_dir" "$plugin_type"

  # Create a new branch if in test mode
  if [[ "$MODE" == "test" ]]; then
    echo "Creating new branch $NEW_BRANCH in $git_dir"
    git checkout -b "$NEW_BRANCH"
  fi

  # Commit changes
  echo "Committing changes in $plugin_dir"
  cd "$plugin_dir" || exit
  git add pyproject.toml poetry.lock
  git commit -m "Update acapy tag to $NEW_TAG for testing"

  # Push changes
  if [[ "$MODE" == "test" ]]; then
    git push --set-upstream origin "$NEW_BRANCH"
  else
    # For release, push to main or designated branch as needed
    git push origin main
  fi

  cd - >/dev/null || exit
}

# Function to update Dockerfiles
update_dockerfiles() {
  local cloudapi_dir=$1

  echo "Updating Dockerfiles in $cloudapi_dir with new test branches and tags"

  # Update base image tag
  sed -i "s|FROM ghcr.io/didx-xyz/acapy-agent${BBS_SUFFIX}:py3.12-$OLD_TAG|FROM ghcr.io/didx-xyz/acapy-agent${BBS_SUFFIX}:py3.12-$NEW_TAG|" "$cloudapi_dir"/dockerfiles/agents/*

  if [[ "$MODE" == "test" ]]; then
    # Update plugin references to use GitHub branches for test mode

    # Update acapy-wallet-groups-plugin to use GitHub branch
    sed -i "s|git\+https://github.com/didx-xyz/acapy-wallet-groups-plugin@.*|git+https://github.com/didx-xyz/acapy-wallet-groups-plugin@$NEW_BRANCH|" "$cloudapi_dir"/dockerfiles/agents/*

    # Update aries-acapy-plugins to use GitHub branch for nats_events
    sed -i "s|git\+https://github.com/didx-xyz/aries-acapy-plugins@.*#subdirectory=nats_events|git+https://github.com/didx-xyz/aries-acapy-plugins@$NEW_BRANCH#subdirectory=nats_events|" "$cloudapi_dir"/dockerfiles/agents/*

  elif [[ "$MODE" == "release" ]]; then
    # Update plugin references for release mode

    # Update acapy-wallet-groups-plugin to use PyPI testpypi version
    sed -i "s|git\+https://github.com/didx-xyz/acapy-wallet-groups-plugin@.*|acapy-wallet-groups-plugin==$TAG_VERSION|" "$cloudapi_dir"/dockerfiles/agents/*

    # Update aries-acapy-plugins to use GitHub tag for nats_events
    sed -i "s|git\+https://github.com/didx-xyz/aries-acapy-plugins@.*#subdirectory=nats_events|git+https://github.com/didx-xyz/aries-acapy-plugins@release-$NEW_TAG#subdirectory=nats_events|" "$cloudapi_dir"/dockerfiles/agents/*
  fi

  echo "Dockerfiles updated successfully."
}

# Check git state in all directories before proceeding
echo "Checking git state in all directories..."
check_git_state "$GROUPS_PLUGIN_DIR"
check_git_state "$NATS_PLUGIN_DIR"
check_git_state "$CLOUDAPI_DIR"

# Update the acapy-wallet-groups-plugin
update_plugin "$GROUPS_PLUGIN_DIR" "$GROUPS_PLUGIN_DIR" "groups"

# Update the aries-acapy-plugins/nats_events
update_plugin "$NATS_PLUGIN_DIR" "$(dirname "$NATS_PLUGIN_DIR")" "nats"

# Update Dockerfiles in cloudapi project
update_dockerfiles "$CLOUDAPI_DIR"

echo "Process complete! Mode: $MODE, New tag: $NEW_TAG, New branch: $NEW_BRANCH"
