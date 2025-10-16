#!/bin/bash
set -e

# --- Parse CLI args ---
BUILD=false
COMMENT="Testing"

while [[ "$#" -gt 0 ]]; do
  case $1 in
    --build|-b)
      BUILD=true
      ;;
    --commit-message|-c)
      COMMENT="$2"
      shift
      ;;
    *)
      echo "Unknown parameter passed: $1"
      echo "Usage: $0 [--build] [--commit-message|-c <commit message>]"
      exit 1
      ;;
  esac
  shift
done

echo ">>> Terminate any running enclaves"
sudo nitro-cli terminate-enclave --all

# Step 1: Navigate to oyster-monorepo
echo ">>> Changing directory to oyster-monorepo..."
cd oyster-monorepo

# Step 2: Flush INPUT iptables rules
echo ">>> Flushing INPUT iptables rules..."
sudo iptables -F INPUT

# Step 3: Conditionally build with Nix
if $BUILD; then
  echo ">>> Adding and committing changes..."
  git add .
  git commit -m "$COMMENT" || echo "No changes to commit."
  echo ">>> Building enclave image with Nix..."
  nix build -vL --accept-flake-config .#musl.sdks.docker-enclave.default
else
  echo ">>> Skipping build (no --build flag provided)."
fi

# Step 4: Move into the result directory
echo ">>> Changing directory to build result..."
cd result

# Step 5: Set iptables rules
echo ">>> Setting new iptables rules..."
sudo iptables -P INPUT ACCEPT
sudo iptables -A INPUT -i ens5 -p tcp -m tcp --dport 80 -j NFQUEUE --queue-num 0
sudo iptables -A INPUT -i ens5 -p tcp -m tcp --dport 443 -j NFQUEUE --queue-num 0
sudo iptables -A INPUT -i ens5 -p tcp -m tcp --dport 1024:61439 -j NFQUEUE --queue-num 0

# Step 6: Run the enclave
echo ">>> Running enclave..."
sudo nitro-cli run-enclave \
  --cpu-count 2 \
  --memory 3000 \
  --eif-path image.eif \
  --enclave-cid 88 \
  --attach-console
