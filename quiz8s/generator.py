"""Dynamic question generation using Claude."""

import json
import random
import anyio
import yaml

from claude_agent_sdk import query, ClaudeAgentOptions, AssistantMessage, TextBlock

from .parser import ClusterArchitecture, extract_relationships
from .questions import Question, QuestionCategory


GENERATOR_SYSTEM_PROMPT = """You are a Kubernetes expert creating quiz questions to test understanding of GitOps deployments.

Your questions should test CONCEPTUAL understanding, not just fact recall. Good questions ask:
- How components work together
- What happens when something fails
- Why certain configurations exist
- How to troubleshoot issues
- The flow of data/requests through the system

Avoid simple "what is the value of X" questions. Instead ask "why is X configured this way" or "what would happen if X changed"."""


CATEGORY_MAPPING = {
    "flux": QuestionCategory.FLUX_GITOPS,
    "gitops": QuestionCategory.FLUX_GITOPS,
    "tls": QuestionCategory.TLS_CERTIFICATES,
    "cert": QuestionCategory.TLS_CERTIFICATES,
    "certificate": QuestionCategory.TLS_CERTIFICATES,
    "ingress": QuestionCategory.INGRESS_NETWORKING,
    "network": QuestionCategory.INGRESS_NETWORKING,
    "traefik": QuestionCategory.INGRESS_NETWORKING,
    "secret": QuestionCategory.SECRETS_MANAGEMENT,
    "keyvault": QuestionCategory.SECRETS_MANAGEMENT,
    "helm": QuestionCategory.HELM_CHARTS,
    "solr": QuestionCategory.STATEFUL_WORKLOADS,
    "zookeeper": QuestionCategory.STATEFUL_WORKLOADS,
    "stateful": QuestionCategory.STATEFUL_WORKLOADS,
    "security": QuestionCategory.SECURITY,
    "monitor": QuestionCategory.MONITORING,
    "prometheus": QuestionCategory.MONITORING,
    "grafana": QuestionCategory.MONITORING,
    "architecture": QuestionCategory.ARCHITECTURE,
    "pattern": QuestionCategory.ARCHITECTURE,
    "kustomize": QuestionCategory.ARCHITECTURE,
}


def _map_category(category_str: str) -> QuestionCategory:
    """Map a category string to QuestionCategory enum."""
    category_lower = category_str.lower()
    for key, cat in CATEGORY_MAPPING.items():
        if key in category_lower:
            return cat
    return QuestionCategory.ARCHITECTURE


def _build_context_summary(arch: ClusterArchitecture) -> str:
    """Build a summary of the cluster architecture for Claude."""
    parts = []

    # Flux Kustomizations
    if arch.flux_kustomizations:
        parts.append("## Flux Kustomizations")
        for k in arch.flux_kustomizations:
            deps = k.spec.get('dependsOn', [])
            dep_str = f" (depends on: {', '.join(d['name'] for d in deps)})" if deps else ""
            parts.append(f"- {k.name}: path={k.spec.get('path', 'N/A')}{dep_str}")

    # Helm Releases
    if arch.helm_releases:
        parts.append("\n## Helm Releases")
        for hr in arch.helm_releases:
            chart = hr.spec.get('chart', {}).get('spec', {}).get('chart', 'unknown')
            parts.append(f"- {hr.name} ({chart}) in {hr.namespace}")

    # Ingresses
    if arch.ingresses:
        parts.append("\n## Ingresses")
        for ing in arch.ingresses:
            hosts = [r.get('host', '') for r in ing.spec.get('rules', [])]
            parts.append(f"- {ing.name}: {', '.join(hosts)}")

    # Custom Resources
    if arch.solr_clouds:
        parts.append("\n## SolrCloud Clusters")
        for s in arch.solr_clouds:
            parts.append(f"- {s.name} ({s.spec.get('replicas', '?')} replicas)")

    if arch.zookeeper_clusters:
        parts.append("\n## ZooKeeper Clusters")
        for z in arch.zookeeper_clusters:
            parts.append(f"- {z.name} ({z.spec.get('replicas', '?')} replicas)")

    # External Secrets
    if arch.external_secrets:
        parts.append("\n## External Secrets")
        for es in arch.external_secrets:
            store = es.spec.get('secretStoreRef', {}).get('name', 'unknown')
            parts.append(f"- {es.name} (from {store})")

    # Cluster Issuers
    if arch.cluster_issuers:
        parts.append("\n## Cert-Manager ClusterIssuers")
        for ci in arch.cluster_issuers:
            solver = "HTTP-01" if ci.spec.get('acme', {}).get('solvers', [{}])[0].get('http01') else "DNS-01"
            parts.append(f"- {ci.name} ({solver})")

    return "\n".join(parts)


def _get_sample_manifests(arch: ClusterArchitecture, focus_area: str = None) -> str:
    """Get sample manifests for context, optionally focused on an area."""
    samples = []
    resources = arch.resources

    if focus_area:
        focus_lower = focus_area.lower()
        # Filter resources by focus area
        filtered = [r for r in resources if
                    focus_lower in r.kind.lower() or
                    focus_lower in r.name.lower() or
                    focus_lower in r.api_version.lower()]
        if filtered:
            resources = filtered

    # Sample up to 5 resources
    sample_resources = random.sample(resources, min(5, len(resources)))

    for res in sample_resources:
        samples.append(f"# {res.kind}: {res.name}")
        samples.append(yaml.dump(res.raw, default_flow_style=False)[:1500])  # Truncate large manifests
        samples.append("---")

    return "\n".join(samples)


def _build_generation_prompt(arch: ClusterArchitecture, count: int,
                             focus_area: str = None,
                             difficulty: str = None) -> str:
    """Build the prompt for question generation."""
    relationships = extract_relationships(arch)

    context_summary = _build_context_summary(arch)
    sample_manifests = _get_sample_manifests(arch, focus_area)

    focus_instruction = ""
    if focus_area:
        focus_instruction = f"\nFocus specifically on: {focus_area}"

    difficulty_instruction = ""
    if difficulty:
        difficulty_instruction = f"\nGenerate {difficulty} difficulty questions."

    return f"""Analyze this Kubernetes GitOps cluster and generate {count} quiz questions.

# Cluster Overview
{context_summary}

# Sample Manifests
```yaml
{sample_manifests}
```

# Key Relationships Found
- Flux dependencies: {json.dumps(relationships.get('flux_dependencies', []), indent=2)}
- Ingress routing: {json.dumps(relationships.get('ingress_to_service', [])[:3], indent=2)}
- TLS certificates: {json.dumps(relationships.get('tls_certificates', []), indent=2)}
- External secrets: {json.dumps(relationships.get('external_secret_refs', []), indent=2)}
{focus_instruction}
{difficulty_instruction}

Generate exactly {count} questions. For each question, respond in this EXACT JSON format:

```json
[
  {{
    "category": "Category name (e.g., FluxCD, TLS, Ingress, Secrets, Helm, Stateful Workloads, Security, Monitoring, Architecture)",
    "difficulty": "easy|medium|hard",
    "question": "The full question text",
    "hints": ["hint 1", "hint 2"],
    "key_concepts": ["concept 1", "concept 2", "concept 3"]
  }}
]
```

Requirements:
1. Questions should test UNDERSTANDING, not just recall
2. Include "what happens if..." and "why is... configured this way" questions
3. Reference specific resources from the manifests
4. Make hints helpful but not give away the answer
5. Key concepts are what a correct answer should mention
6. Mix difficulties unless specified otherwise

Return ONLY the JSON array, no other text."""


async def generate_questions_async(
    arch: ClusterArchitecture,
    count: int = 5,
    focus_area: str = None,
    difficulty: str = None
) -> list[Question]:
    """Generate questions dynamically using Claude."""

    prompt = _build_generation_prompt(arch, count, focus_area, difficulty)

    options = ClaudeAgentOptions(
        system_prompt=GENERATOR_SYSTEM_PROMPT,
        max_turns=1,
    )

    response_text = ""

    async for message in query(prompt=prompt, options=options):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock):
                    response_text += block.text

    return _parse_generated_questions(response_text, arch)


def generate_questions(
    arch: ClusterArchitecture,
    count: int = 5,
    focus_area: str = None,
    difficulty: str = None
) -> list[Question]:
    """Generate questions dynamically using Claude (synchronous wrapper)."""
    return anyio.run(
        generate_questions_async,
        arch, count, focus_area, difficulty
    )


def _parse_generated_questions(response: str, arch: ClusterArchitecture) -> list[Question]:
    """Parse Claude's JSON response into Question objects."""
    questions = []

    # Extract JSON from response (handle markdown code blocks)
    json_str = response
    if "```json" in response:
        start = response.find("```json") + 7
        end = response.find("```", start)
        json_str = response[start:end].strip()
    elif "```" in response:
        start = response.find("```") + 3
        end = response.find("```", start)
        json_str = response[start:end].strip()

    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        # Try to salvage partial JSON
        print(f"Warning: Failed to parse full response, attempting recovery: {e}")
        # Find array brackets
        start = response.find("[")
        end = response.rfind("]") + 1
        if start >= 0 and end > start:
            try:
                data = json.loads(response[start:end])
            except json.JSONDecodeError:
                return questions
        else:
            return questions

    if not isinstance(data, list):
        data = [data]

    for item in data:
        if not isinstance(item, dict):
            continue

        try:
            category = _map_category(item.get("category", "Architecture"))
            difficulty = item.get("difficulty", "medium").lower()
            if difficulty not in ("easy", "medium", "hard"):
                difficulty = "medium"

            # Build context from relevant resources
            question_text = item.get("question", "")
            context = _find_relevant_context(arch, question_text, item.get("category", ""))

            questions.append(Question(
                category=category,
                question=question_text,
                context=context,
                hints=item.get("hints", ["Think about the component relationships"]),
                key_concepts=item.get("key_concepts", []),
                difficulty=difficulty
            ))
        except Exception as e:
            print(f"Warning: Failed to parse question: {e}")
            continue

    return questions


def _find_relevant_context(arch: ClusterArchitecture, question: str, category: str) -> str:
    """Find relevant manifest context for a question."""
    question_lower = question.lower()
    category_lower = category.lower()
    relevant = []

    # Keywords to look for
    keywords = set()

    # Extract potential resource names from question
    for res in arch.resources:
        if res.name.lower() in question_lower:
            keywords.add(res.name.lower())
        if res.kind.lower() in question_lower:
            keywords.add(res.kind.lower())

    # Add category-based keywords
    if "flux" in category_lower or "gitops" in category_lower:
        keywords.update(["kustomization", "gitrepository"])
    if "tls" in category_lower or "cert" in category_lower:
        keywords.update(["clusterissuer", "certificate", "ingress"])
    if "ingress" in category_lower or "network" in category_lower:
        keywords.update(["ingress", "traefik", "service"])
    if "secret" in category_lower:
        keywords.update(["externalsecret", "clustersecretstore"])
    if "helm" in category_lower:
        keywords.update(["helmrelease", "helmrepository"])
    if "solr" in category_lower or "zookeeper" in category_lower or "stateful" in category_lower:
        keywords.update(["solrcloud", "zookeepercluster"])

    # Find matching resources
    for res in arch.resources:
        res_text = f"{res.kind} {res.name}".lower()
        if any(kw in res_text for kw in keywords):
            relevant.append(res)

    # Limit context size
    context_parts = []
    for res in relevant[:3]:
        context_parts.append(f"# {res.kind}: {res.name}")
        context_parts.append(yaml.dump(res.raw, default_flow_style=False))

    if not context_parts:
        # Fallback: provide some general context
        sample = random.sample(arch.resources, min(2, len(arch.resources)))
        for res in sample:
            context_parts.append(f"# {res.kind}: {res.name}")
            context_parts.append(yaml.dump(res.raw, default_flow_style=False))

    return "\n---\n".join(context_parts)
