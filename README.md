# Quiz8s

A Kubernetes quiz app that tests your understanding of GitOps deployments. It parses your Kubernetes manifests and generates conceptual questions about how components work together. Answer in natural language and Claude judges your responses.

## Prerequisites

- Python 3.10+
- Node.js (for Claude Code)
- Claude Code CLI: `npm install -g @anthropic-ai/claude-code`

## Installation

```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install the package
pip install -e .
```

## Usage

```bash
# Start the quiz (default: 5 questions from all categories)
quiz8s

# Specify the manifest directory (default: ./Asimov-k8s)
quiz8s /path/to/your/k8s-repo

# Set number of questions
quiz8s -n 10

# Filter by difficulty (easy, medium, hard)
quiz8s -d hard

# List all available questions without starting quiz
quiz8s --list

# Use offline mode (keyword matching instead of Claude)
quiz8s --offline
```

## During the Quiz

- Type your answer in natural language
- Type `hint` for hints
- Type `context` to see the relevant manifest
- Type `skip` to skip a question
- Type `quit` to exit

## Question Categories

- **FluxCD / GitOps** - Kustomizations, dependencies, reconciliation, pruning
- **TLS / Cert-Manager** - ACME challenges, ClusterIssuers, certificate flow
- **Ingress / Networking** - Traffic flow, load balancers, TLS termination
- **Secrets Management** - External Secrets, Azure Key Vault, WorkloadIdentity
- **Helm Charts** - Version constraints, values interpretation
- **Stateful Workloads** - ZooKeeper, Solr, JVM tuning, rolling updates
- **Security** - Container security contexts, Linux capabilities
- **Monitoring** - Prometheus retention, ServiceMonitor discovery
- **Architecture** - Base/overlay patterns, infrastructure/apps separation

## How It Works

1. Parses all YAML manifests in your GitOps repository
2. Extracts relationships between resources (dependencies, references, configurations)
3. Generates conceptual questions based on patterns found
4. Uses Claude (via `claude-agent-sdk`) to judge natural language answers
5. Provides feedback on what you got right and what you missed
