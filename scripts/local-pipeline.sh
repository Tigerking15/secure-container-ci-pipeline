#!/usr/bin/env bash
# ==============================================================================
# local-pipeline.sh
#
# Runs the secure container supply chain CI pipeline locally on macOS / Linux
# using containerized Trivy, Syft, and Conftest without needing local tool installs
# and without requiring Docker Desktop host file sharing permissions.
#
# Usage:
#   ./scripts/local-pipeline.sh                     # Runs full pipeline (tests + build + scan + gate)
#   ./scripts/local-pipeline.sh --test-only         # Runs ONLY Rego policy unit tests
#   ./scripts/local-pipeline.sh --unsigned          # Simulates unsigned image (gate FAILS)
#   ./scripts/local-pipeline.sh --signed false      # Explicit signed flag
#   ./scripts/local-pipeline.sh --image my-app:test # Custom image name
# ==============================================================================

set -uo pipefail

# Colors for terminal output
CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Default options
IMAGE_NAME="secure-container-ci-pipeline:local"
SIGNED="true"
TEST_ONLY="false"

show_help() {
    cat <<EOF
Usage: ./scripts/local-pipeline.sh [options]

Runs the end-to-end container security pipeline locally on macOS/Linux.

Options:
  -t, --test-only       Run ONLY the Rego policy unit tests and exit
  -i, --image <name>    Local Docker image tag to build (default: secure-container-ci-pipeline:local)
  -s, --signed <bool>   Simulate Cosign signature verification: true or false (default: true)
      --unsigned        Shorthand for --signed false (demonstrates policy rejection)
  -h, --help            Show this help message and exit

Examples:
  ./scripts/local-pipeline.sh                  # Full passing run (tests + build + scan + gate)
  ./scripts/local-pipeline.sh --test-only      # Fast verification of policy/deny_test.rego
  ./scripts/local-pipeline.sh --unsigned       # Demo gate failure (blocks unsigned image)
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--test-only)
            TEST_ONLY="true"
            shift
            ;;
        -i|--image)
            IMAGE_NAME="$2"
            shift 2
            ;;
        -s|--signed)
            SIGNED="$2"
            shift 2
            ;;
        --unsigned)
            SIGNED="false"
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}Error: Unknown argument $1${NC}"
            show_help
            exit 1
            ;;
    esac
done

# Resolve repo root directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

step() {
    echo -e "\n${CYAN}${BOLD}==> $1${NC}"
}

# Verify Docker is available
if ! command -v docker >/dev/null 2>&1; then
    echo -e "${RED}Error: 'docker' command not found in PATH.${NC}"
    echo "Please ensure Docker Desktop is installed and running."
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo -e "${RED}Error: Docker daemon is not responding.${NC}"
    echo "Please launch Docker Desktop and try again."
    exit 1
fi

# Detect Python
PYTHON_BIN=""
if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
else
    echo -e "${RED}Error: Python 3 is required to run helper scripts.${NC}"
    exit 1
fi

# 1. Rego Policy Unit Tests
step "Running Rego policy unit tests (policy/deny_test.rego)"
TEST_CID=$(docker create -w /workspace openpolicyagent/conftest:v0.56.0 verify -p policy)
docker cp policy "$TEST_CID:/workspace/policy"

set +e
docker start -a "$TEST_CID"
TEST_EXIT_CODE=$?
set -e
docker rm -f "$TEST_CID" >/dev/null 2>&1

if [ $TEST_EXIT_CODE -ne 0 ]; then
    echo -e "${RED}${BOLD}✖ Policy unit tests FAILED! Deployment rules are broken.${NC}"
    exit $TEST_EXIT_CODE
else
    echo -e "${GREEN}${BOLD}✔ All policy unit tests PASSED.${NC}"
fi

# If test-only was requested, stop here
if [ "$TEST_ONLY" = "true" ]; then
    echo -e "\n${GREEN}${BOLD}================================================================${NC}"
    echo -e "${GREEN}${BOLD}✔ Policy unit testing complete (--test-only).${NC}"
    echo -e "${GREEN}${BOLD}================================================================${NC}"
    exit 0
fi

# 2. Build Docker Image
step "Building Docker image ($IMAGE_NAME)"
docker build -t "$IMAGE_NAME" ./app

# 3. Scan image with Trivy (streaming JSON via stdout to bypass host mount restrictions)
step "Scanning image with Trivy for vulnerabilities"
docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    aquasec/trivy:latest image \
    --quiet \
    --format json \
    "$IMAGE_NAME" > trivy-report.json

# 4. Generate SBOM with Syft (streaming CycloneDX via stdout)
step "Generating CycloneDX SBOM with Syft"
docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    anchore/syft:latest \
    --quiet \
    "$IMAGE_NAME" \
    -o cyclonedx-json > sbom.json

# 5. Build facts.json
step "Building facts.json (signed=$SIGNED)"
"$PYTHON_BIN" scripts/build-facts.py \
    --trivy-report trivy-report.json \
    --signed "$SIGNED" \
    --out facts.json
cat facts.json

# 6. Evaluate Conftest Rego Policy Gate (using container cp to avoid bind-mount restrictions)
step "Evaluating OPA/Conftest policy gate (policy/deny.rego)"
CONFTEST_CID=$(docker create -w /workspace openpolicyagent/conftest:v0.56.0 test facts.json -p deny.rego)
docker cp facts.json "$CONFTEST_CID:/workspace/facts.json"
docker cp policy/deny.rego "$CONFTEST_CID:/workspace/deny.rego"

set +e
docker start -a "$CONFTEST_CID" > conftest-output.txt 2>&1
GATE_EXIT_CODE=$?
set -e

docker rm -f "$CONFTEST_CID" >/dev/null 2>&1

cat conftest-output.txt

# 7. Generate Markdown Summary
if [ -f "scripts/generate-summary.py" ]; then
    step "Generating Security Report (summary.md)"
    "$PYTHON_BIN" scripts/generate-summary.py \
        --facts facts.json \
        --sbom sbom.json \
        --trivy-report trivy-report.json \
        --conftest-output conftest-output.txt \
        --image-ref "$IMAGE_NAME" \
        --out summary.md
fi

echo ""
if [ $GATE_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}${BOLD}================================================================${NC}"
    echo -e "${GREEN}${BOLD}✔ POLICY GATE: PASSED — image is signed & clear of critical CVEs.${NC}"
    echo -e "${GREEN}${BOLD}✔ Workload would be approved for deployment.${NC}"
    echo -e "${GREEN}${BOLD}================================================================${NC}"
else
    echo -e "${RED}${BOLD}================================================================${NC}"
    echo -e "${RED}${BOLD}✖ POLICY GATE: FAILED — deployment blocked by security policy!${NC}"
    echo -e "${RED}${BOLD}================================================================${NC}"
fi

exit $GATE_EXIT_CODE
