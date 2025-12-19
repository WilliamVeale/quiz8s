"""Question generation for Kubernetes quiz."""

import random
from dataclasses import dataclass
from enum import Enum
from typing import Any

import yaml

from .parser import ClusterArchitecture, extract_relationships, K8sResource


class QuestionCategory(Enum):
    """Categories of questions."""
    FLUX_GITOPS = "FluxCD / GitOps"
    TLS_CERTIFICATES = "TLS / Cert-Manager"
    INGRESS_NETWORKING = "Ingress / Networking"
    SECRETS_MANAGEMENT = "Secrets Management"
    HELM_CHARTS = "Helm Charts"
    STATEFUL_WORKLOADS = "Stateful Workloads"
    RESOURCE_MANAGEMENT = "Resource Management"
    SECURITY = "Security"
    MONITORING = "Monitoring"
    ARCHITECTURE = "Architecture / Design Patterns"


@dataclass
class Question:
    """Represents a quiz question."""
    category: QuestionCategory
    question: str
    context: str  # Relevant manifest snippets
    hints: list[str]
    key_concepts: list[str]  # What the answer should cover
    difficulty: str  # easy, medium, hard


class QuestionGenerator:
    """Generates conceptual questions from cluster architecture."""

    def __init__(self, arch: ClusterArchitecture):
        self.arch = arch
        self.relationships = extract_relationships(arch)
        self._questions: list[Question] = []
        self._generate_all_questions()

    def _generate_all_questions(self):
        """Generate all possible questions from the architecture."""
        self._generate_flux_questions()
        self._generate_tls_questions()
        self._generate_ingress_questions()
        self._generate_secrets_questions()
        self._generate_helm_questions()
        self._generate_stateful_questions()
        self._generate_security_questions()
        self._generate_architecture_questions()
        self._generate_monitoring_questions()

    def get_questions(self, category: QuestionCategory = None,
                      difficulty: str = None, count: int = None) -> list[Question]:
        """Get questions, optionally filtered."""
        questions = self._questions

        if category:
            questions = [q for q in questions if q.category == category]
        if difficulty:
            questions = [q for q in questions if q.difficulty == difficulty]

        if count and count < len(questions):
            questions = random.sample(questions, count)

        return questions

    def _add_question(self, category: QuestionCategory, question: str,
                      context: str, hints: list[str], key_concepts: list[str],
                      difficulty: str = "medium"):
        """Add a question to the pool."""
        self._questions.append(Question(
            category=category,
            question=question,
            context=context,
            hints=hints,
            key_concepts=key_concepts,
            difficulty=difficulty
        ))

    # =========================================================================
    # FLUX / GITOPS QUESTIONS
    # =========================================================================
    def _generate_flux_questions(self):
        """Generate FluxCD and GitOps related questions."""

        # Dependency ordering
        deps = self.relationships.get('flux_dependencies', [])
        for dep in deps:
            if dep['depends_on']:
                self._add_question(
                    category=QuestionCategory.FLUX_GITOPS,
                    question=f"The '{dep['kustomization']}' Kustomization depends on '{dep['depends_on'][0]}'. "
                             f"What happens if the dependency fails its health checks? Why is this ordering important?",
                    context=self._get_kustomization_context(dep['kustomization']),
                    hints=["Think about what resources the apps layer needs",
                           "Consider operators and CRDs"],
                    key_concepts=["Flux waits for dependencies", "health checks must pass",
                                  "prevents apps from deploying before infrastructure",
                                  "CRDs must exist before custom resources"],
                    difficulty="medium"
                )

        # Flux Kustomization reconciliation
        for kust in self.arch.flux_kustomizations:
            interval = kust.spec.get('interval', '10m')
            prune = kust.spec.get('prune', False)

            self._add_question(
                category=QuestionCategory.FLUX_GITOPS,
                question=f"The '{kust.name}' Kustomization has prune={prune}. "
                         f"What does the 'prune' setting do, and what are the implications "
                         f"if you remove a resource from the Git repository?",
                context=yaml.dump(kust.raw, default_flow_style=False),
                hints=["Think about orphaned resources", "What if you delete a file from Git?"],
                key_concepts=["prune removes resources not in Git", "garbage collection",
                              "prevents orphaned resources in cluster",
                              "prune=false leaves resources when removed from Git"],
                difficulty="medium"
            )

            health_checks = kust.spec.get('healthChecks', [])
            if health_checks:
                self._add_question(
                    category=QuestionCategory.FLUX_GITOPS,
                    question=f"The '{kust.name}' Kustomization defines health checks. "
                             f"Explain how Flux uses these health checks and what happens "
                             f"during a deployment if a health check fails.",
                    context=yaml.dump(kust.raw, default_flow_style=False),
                    hints=["Look at the healthChecks field", "Consider rolling back"],
                    key_concepts=["Flux monitors specified resources", "waits for ready state",
                                  "blocks dependent Kustomizations", "timeout causes failure"],
                    difficulty="hard"
                )

        # GitOps flow question
        self._add_question(
            category=QuestionCategory.FLUX_GITOPS,
            question="Describe the complete GitOps flow: what happens when you push a change "
                     "to the Git repository? Trace the path from Git commit to running pods.",
            context=self._get_all_flux_context(),
            hints=["Start with GitRepository resource", "Think about reconciliation intervals",
                   "Consider the dependency chain"],
            key_concepts=["GitRepository detects changes", "Kustomization reconciles",
                          "applies manifests to cluster", "waits for health checks",
                          "triggers dependent Kustomizations"],
            difficulty="hard"
        )

    # =========================================================================
    # TLS / CERT-MANAGER QUESTIONS
    # =========================================================================
    def _generate_tls_questions(self):
        """Generate TLS and certificate management questions."""

        for issuer in self.arch.cluster_issuers:
            acme = issuer.spec.get('acme', {})
            solvers = acme.get('solvers', [])

            solver_type = "HTTP-01" if solvers and 'http01' in solvers[0] else "DNS-01"

            self._add_question(
                category=QuestionCategory.TLS_CERTIFICATES,
                question=f"The ClusterIssuer '{issuer.name}' uses {solver_type} challenge. "
                         f"Explain step-by-step how cert-manager obtains a TLS certificate "
                         f"when a new Ingress is created with this issuer.",
                context=yaml.dump(issuer.raw, default_flow_style=False),
                hints=["Consider the ACME protocol", "What temporary resources are created?",
                       "How does Let's Encrypt verify domain ownership?"],
                key_concepts=["cert-manager creates Certificate resource",
                              "creates temporary Ingress for challenge",
                              "Let's Encrypt makes HTTP request to /.well-known/acme-challenge",
                              "Traefik routes challenge request",
                              "certificate stored in Secret"],
                difficulty="hard"
            )

            self._add_question(
                category=QuestionCategory.TLS_CERTIFICATES,
                question=f"Why are there both 'letsencrypt-staging' and 'letsencrypt-prod' "
                         f"ClusterIssuers? When should you use each one?",
                context=self._get_issuer_context(),
                hints=["Consider rate limits", "What happens during testing?"],
                key_concepts=["staging has higher rate limits", "staging certs not trusted",
                              "use staging for testing", "production for real certificates",
                              "avoid hitting rate limits during development"],
                difficulty="easy"
            )

        # TLS flow with ingress
        tls_certs = self.relationships.get('tls_certificates', [])
        for cert in tls_certs:
            if cert['issuer']:
                self._add_question(
                    category=QuestionCategory.TLS_CERTIFICATES,
                    question=f"The Ingress '{cert['ingress']}' has the annotation "
                             f"'cert-manager.io/cluster-issuer: {cert['issuer']}'. "
                             f"What role does this annotation play, and where is the "
                             f"certificate ultimately stored?",
                    context=self._get_ingress_context(cert['ingress']),
                    hints=["Think about the secretName in the TLS section",
                           "What watches for this annotation?"],
                    key_concepts=["cert-manager watches Ingress resources",
                                  f"annotation triggers certificate request",
                                  f"certificate stored in secret '{cert['secret']}'",
                                  "Traefik/ingress controller uses secret for TLS"],
                    difficulty="medium"
                )

    # =========================================================================
    # INGRESS / NETWORKING QUESTIONS
    # =========================================================================
    def _generate_ingress_questions(self):
        """Generate ingress and networking questions."""

        # Traffic flow questions
        for ing_svc in self.relationships.get('ingress_to_service', []):
            self._add_question(
                category=QuestionCategory.INGRESS_NETWORKING,
                question=f"Trace the complete network path: how does a request to "
                         f"'https://{ing_svc['host']}{ing_svc['path']}' reach the application? "
                         f"Include all components involved.",
                context=self._get_ingress_and_traefik_context(ing_svc['ingress']),
                hints=["Start from the internet", "Consider the LoadBalancer",
                       "What port translations happen?"],
                key_concepts=["DNS resolves to LoadBalancer IP",
                              "Azure LoadBalancer routes to Traefik",
                              "Traefik terminates TLS",
                              "Ingress rules match host/path",
                              f"routes to Service {ing_svc['service']}",
                              "Service routes to Pod endpoints"],
                difficulty="hard"
            )

        # Traefik specific
        for hr in self.arch.helm_releases:
            if hr.name == 'traefik':
                values = hr.spec.get('values', {})
                ports = values.get('ports', {})
                web = ports.get('web', {})
                redirections = web.get('redirections', {})

                if redirections:
                    self._add_question(
                        category=QuestionCategory.INGRESS_NETWORKING,
                        question="The Traefik configuration shows port 80 (web) redirects to "
                                 "port 443 (websecure). Explain how this redirect works and "
                                 "why it's configured this way.",
                        context=yaml.dump(hr.raw, default_flow_style=False),
                        hints=["Look at the entryPoint configuration",
                               "What HTTP status code is used?"],
                        key_concepts=["HTTP 301/302 redirect", "forces HTTPS",
                                      "security best practice", "permanent redirect to https scheme"],
                        difficulty="medium"
                    )

                service = values.get('service', {})
                lb_ip = service.get('loadBalancerIP')
                if lb_ip:
                    self._add_question(
                        category=QuestionCategory.INGRESS_NETWORKING,
                        question=f"Traefik's LoadBalancer Service has a static IP: {lb_ip}. "
                                 f"Why would you use a static IP instead of a dynamic one? "
                                 f"What would break if the IP changed?",
                        context=yaml.dump(hr.raw, default_flow_style=False),
                        hints=["Think about DNS records", "Consider external dependencies"],
                        key_concepts=["DNS A records point to this IP",
                                      "IP change requires DNS updates",
                                      "DNS propagation takes time",
                                      "stable IP = stable external access"],
                        difficulty="medium"
                    )

    # =========================================================================
    # SECRETS MANAGEMENT QUESTIONS
    # =========================================================================
    def _generate_secrets_questions(self):
        """Generate secrets management questions."""

        ext_secrets = self.relationships.get('external_secret_refs', [])
        for es in ext_secrets:
            self._add_question(
                category=QuestionCategory.SECRETS_MANAGEMENT,
                question=f"The ExternalSecret '{es['name']}' references a {es['store_kind']} "
                         f"named '{es['store']}'. Explain the complete flow: how does a secret "
                         f"in Azure Key Vault become a Kubernetes Secret?",
                context=self._get_external_secrets_context(),
                hints=["Consider the operator pattern", "What authentication is used?",
                       "What creates the K8s Secret?"],
                key_concepts=["external-secrets operator runs in cluster",
                              "ClusterSecretStore connects to Azure Key Vault",
                              "WorkloadIdentity for authentication (no hardcoded creds)",
                              "ExternalSecret defines mapping",
                              "operator creates/updates K8s Secret",
                              "refreshInterval keeps secret in sync"],
                difficulty="hard"
            )

            self._add_question(
                category=QuestionCategory.SECRETS_MANAGEMENT,
                question=f"The ExternalSecret '{es['name']}' has a refreshInterval. "
                         f"What happens if the secret value changes in Azure Key Vault? "
                         f"How long before the application sees the new value?",
                context=self._get_external_secrets_context(),
                hints=["Consider the refresh interval", "Do pods automatically reload?"],
                key_concepts=["operator polls at refreshInterval",
                              "K8s Secret updated automatically",
                              "pods may need restart to see new values",
                              "some apps watch secrets, most don't"],
                difficulty="medium"
            )

        # WorkloadIdentity
        for hr in self.arch.helm_releases:
            if hr.name == 'external-secrets':
                values = hr.spec.get('values', {})
                pod_labels = values.get('podLabels', {})
                if 'azure.workload.identity/use' in pod_labels:
                    self._add_question(
                        category=QuestionCategory.SECRETS_MANAGEMENT,
                        question="The external-secrets operator uses Azure Workload Identity "
                                 "(azure.workload.identity/use: 'true'). Explain how this "
                                 "authentication method works and why it's better than using "
                                 "a Service Principal with a client secret.",
                        context=yaml.dump(hr.raw, default_flow_style=False),
                        hints=["Think about credential rotation", "Where are secrets stored?"],
                        key_concepts=["federated identity - no stored credentials",
                                      "ServiceAccount linked to Azure AD identity",
                                      "Azure issues short-lived tokens",
                                      "no secret rotation needed",
                                      "more secure than client secrets"],
                        difficulty="hard"
                    )

    # =========================================================================
    # HELM CHARTS QUESTIONS
    # =========================================================================
    def _generate_helm_questions(self):
        """Generate Helm-related questions."""

        for helm_info in self.relationships.get('helm_to_repo', []):
            hr = next((h for h in self.arch.helm_releases
                       if h.name == helm_info['release']), None)
            if not hr:
                continue

            values = helm_info.get('values', {})

            # Chart version questions
            chart_spec = hr.spec.get('chart', {}).get('spec', {})
            version = chart_spec.get('version', '')
            if 'x' in version or '>=' in version:
                self._add_question(
                    category=QuestionCategory.HELM_CHARTS,
                    question=f"The HelmRelease '{hr.name}' uses version constraint '{version}'. "
                             f"What does this constraint mean, and what are the trade-offs "
                             f"between pinning exact versions vs using ranges?",
                    context=yaml.dump(hr.raw, default_flow_style=False),
                    hints=["Consider security updates", "What about breaking changes?"],
                    key_concepts=["version ranges auto-update within constraint",
                                  "x allows any patch version",
                                  ">= allows newer versions",
                                  "trade-off: auto-updates vs stability",
                                  "ranges good for security patches",
                                  "exact versions for reproducibility"],
                    difficulty="medium"
                )

            # Values interpretation
            if 'nodeSelector' in values:
                self._add_question(
                    category=QuestionCategory.HELM_CHARTS,
                    question=f"The HelmRelease '{hr.name}' sets nodeSelector to "
                             f"'{values['nodeSelector']}'. What does this accomplish "
                             f"in an AKS cluster, and what happens if no nodes match?",
                    context=yaml.dump(hr.raw, default_flow_style=False),
                    hints=["Think about AKS node pools", "What are system vs user nodes?"],
                    key_concepts=["pods only scheduled on matching nodes",
                                  "user nodes for workloads, system for k8s components",
                                  "pod stays Pending if no match",
                                  "prevents workloads on system node pool"],
                    difficulty="easy"
                )

    # =========================================================================
    # STATEFUL WORKLOADS QUESTIONS
    # =========================================================================
    def _generate_stateful_questions(self):
        """Generate questions about stateful workloads."""

        for zk_client in self.relationships.get('zookeeper_clients', []):
            self._add_question(
                category=QuestionCategory.STATEFUL_WORKLOADS,
                question=f"The SolrCloud '{zk_client['solr_cloud']}' connects to ZooKeeper "
                         f"with chroot '{zk_client['chroot']}'. What is a ZooKeeper chroot "
                         f"and why is it important for running multiple SolrCloud clusters?",
                context=self._get_solr_context(zk_client['solr_cloud']),
                hints=["Think about namespace isolation", "What if two Solr clusters used the same ZK?"],
                key_concepts=["chroot provides namespace isolation",
                              "each SolrCloud sees isolated znode tree",
                              "multiple clusters share single ZK cluster",
                              "prevents data collision between clusters"],
                difficulty="medium"
            )

        for solr in self.arch.solr_clouds:
            spec = solr.spec
            java_mem = spec.get('solrJavaMem', '')
            opts = spec.get('solrOpts', '')

            if java_mem:
                self._add_question(
                    category=QuestionCategory.STATEFUL_WORKLOADS,
                    question=f"The SolrCloud sets solrJavaMem='{java_mem}'. The pod has "
                             f"memory limits higher than the heap. Explain why the container "
                             f"memory limit must be higher than the JVM heap size.",
                    context=yaml.dump(solr.raw, default_flow_style=False),
                    hints=["JVM uses more than just heap", "What about native memory?"],
                    key_concepts=["JVM needs heap + metaspace + stack + native memory",
                                  "off-heap memory for buffers",
                                  "container gets OOMKilled if limit exceeded",
                                  "rule of thumb: limit = heap + 30-50% overhead"],
                    difficulty="medium"
                )

            if 'autoSoftCommit' in opts:
                self._add_question(
                    category=QuestionCategory.STATEFUL_WORKLOADS,
                    question=f"The SolrCloud sets '-Dsolr.autoSoftCommit.maxTime=10000'. "
                             f"Explain what a soft commit is in Solr, how it differs from "
                             f"a hard commit, and why this setting matters for search latency.",
                    context=yaml.dump(solr.raw, default_flow_style=False),
                    hints=["Think about visibility vs durability",
                           "What gets written to disk?"],
                    key_concepts=["soft commit makes documents searchable",
                                  "doesn't fsync to disk",
                                  "hard commit ensures durability",
                                  "10000ms = 10s max until doc is searchable",
                                  "trade-off: latency vs resource usage"],
                    difficulty="hard"
                )

            update_strategy = spec.get('updateStrategy', {})
            if update_strategy.get('method') == 'Managed':
                self._add_question(
                    category=QuestionCategory.STATEFUL_WORKLOADS,
                    question=f"The SolrCloud uses updateStrategy.method='Managed' with "
                             f"maxPodsUnavailable=1. Explain how the Solr Operator performs "
                             f"rolling updates while maintaining search availability.",
                    context=yaml.dump(solr.raw, default_flow_style=False),
                    hints=["Consider replica placement", "What about in-flight queries?"],
                    key_concepts=["operator updates one pod at a time",
                                  "moves replicas before taking pod down",
                                  "ensures all shards have active replicas",
                                  "waits for pod healthy before continuing"],
                    difficulty="hard"
                )

        for zk in self.arch.zookeeper_clusters:
            replicas = zk.spec.get('replicas', 3)
            self._add_question(
                category=QuestionCategory.STATEFUL_WORKLOADS,
                question=f"The ZookeeperCluster has {replicas} replicas. Why is an odd number "
                         f"of replicas important for ZooKeeper, and what's the minimum "
                         f"number needed for the cluster to remain available?",
                context=yaml.dump(zk.raw, default_flow_style=False),
                hints=["Think about quorum", "What's (n/2)+1?"],
                key_concepts=["ZK uses quorum for consistency",
                              f"quorum = {replicas // 2 + 1} nodes",
                              "odd numbers maximize fault tolerance per node",
                              "3 nodes: tolerate 1 failure",
                              "even numbers waste a node"],
                difficulty="medium"
            )

    # =========================================================================
    # SECURITY QUESTIONS
    # =========================================================================
    def _generate_security_questions(self):
        """Generate security-related questions."""

        for hr in self.arch.helm_releases:
            values = hr.spec.get('values', {})
            sec_ctx = values.get('securityContext', {})

            if sec_ctx.get('runAsNonRoot'):
                self._add_question(
                    category=QuestionCategory.SECURITY,
                    question=f"The HelmRelease '{hr.name}' sets runAsNonRoot=true and "
                             f"runAsUser={sec_ctx.get('runAsUser')}. Explain why running "
                             f"containers as non-root is important, even inside a container.",
                    context=yaml.dump(hr.raw, default_flow_style=False),
                    hints=["Think about container escapes", "Defense in depth"],
                    key_concepts=["container isolation not perfect",
                                  "root in container = easier privilege escalation",
                                  "limits damage from container breakout",
                                  "defense in depth principle"],
                    difficulty="medium"
                )

            caps = sec_ctx.get('capabilities', {})
            if 'drop' in caps and 'ALL' in caps['drop']:
                self._add_question(
                    category=QuestionCategory.SECURITY,
                    question=f"The '{hr.name}' container drops ALL Linux capabilities. "
                             f"What are Linux capabilities and why is dropping all of them "
                             f"a security best practice?",
                    context=yaml.dump(hr.raw, default_flow_style=False),
                    hints=["Think about what root can do", "Principle of least privilege"],
                    key_concepts=["capabilities = fine-grained root permissions",
                                  "ALL includes NET_BIND_SERVICE, SYS_ADMIN, etc",
                                  "reduces attack surface",
                                  "container only gets what it needs"],
                    difficulty="hard"
                )

    # =========================================================================
    # ARCHITECTURE QUESTIONS
    # =========================================================================
    def _generate_architecture_questions(self):
        """Generate architecture and design pattern questions."""

        # Base/overlay pattern
        self._add_question(
            category=QuestionCategory.ARCHITECTURE,
            question="This repository uses a base/staging/production directory structure "
                     "with Kustomize. Explain this pattern and how it enables environment-"
                     "specific configuration while minimizing duplication.",
            context=self._get_kustomization_structure(),
            hints=["Think about inheritance", "What goes in base vs overlays?"],
            key_concepts=["base contains common configuration",
                          "overlays patch for environment differences",
                          "reduces duplication",
                          "staging/production can have different replicas, resources, etc",
                          "single source of truth in base"],
            difficulty="medium"
        )

        # Infrastructure vs Apps separation
        self._add_question(
            category=QuestionCategory.ARCHITECTURE,
            question="Why are 'infrastructure' and 'apps' separated into different "
                     "Flux Kustomizations with a dependency between them?",
            context=self._get_all_flux_context(),
            hints=["What does infrastructure include?", "What needs to exist before apps?"],
            key_concepts=["infrastructure: operators, CRDs, ingress controllers",
                          "apps: actual workloads using the infrastructure",
                          "CRDs must exist before custom resources",
                          "operators must be running to reconcile resources",
                          "clear separation of concerns"],
            difficulty="medium"
        )

    # =========================================================================
    # MONITORING QUESTIONS
    # =========================================================================
    def _generate_monitoring_questions(self):
        """Generate monitoring-related questions."""

        for hr in self.arch.helm_releases:
            if hr.name == 'kube-prometheus-stack':
                values = hr.spec.get('values', {})
                prom_spec = values.get('prometheus', {}).get('prometheusSpec', {})

                retention = prom_spec.get('retention', '')
                retention_size = prom_spec.get('retentionSize', '')

                self._add_question(
                    category=QuestionCategory.MONITORING,
                    question=f"Prometheus is configured with retention={retention} and "
                             f"retentionSize={retention_size}. Explain how these two "
                             f"settings interact and which one 'wins' when they conflict.",
                    context=yaml.dump(hr.raw, default_flow_style=False),
                    hints=["What if disk fills up before 30 days?",
                           "Which condition is checked first?"],
                    key_concepts=["retention = time-based limit",
                                  "retentionSize = disk-based limit",
                                  "whichever triggers first wins",
                                  "size limit prevents disk exhaustion",
                                  "time limit ensures fresh data"],
                    difficulty="medium"
                )

                nil_uses = prom_spec.get('serviceMonitorSelectorNilUsesHelmValues', False)
                self._add_question(
                    category=QuestionCategory.MONITORING,
                    question="The Prometheus configuration sets "
                             "serviceMonitorSelectorNilUsesHelmValues=false. "
                             "What does this mean for ServiceMonitor discovery?",
                    context=yaml.dump(hr.raw, default_flow_style=False),
                    hints=["What happens when selector is nil/empty?",
                           "Default behavior vs this setting"],
                    key_concepts=["false = discover ALL ServiceMonitors in cluster",
                                  "true = only ones matching helm release labels",
                                  "enables monitoring resources in any namespace",
                                  "common gotcha: Prometheus doesn't see your ServiceMonitors"],
                    difficulty="hard"
                )

    # =========================================================================
    # HELPER METHODS
    # =========================================================================
    def _get_kustomization_context(self, name: str) -> str:
        """Get YAML context for a Kustomization."""
        for kust in self.arch.flux_kustomizations:
            if kust.name == name:
                return yaml.dump(kust.raw, default_flow_style=False)
        return ""

    def _get_all_flux_context(self) -> str:
        """Get all Flux-related context."""
        parts = []
        for kust in self.arch.flux_kustomizations:
            parts.append(f"# Kustomization: {kust.name}")
            parts.append(yaml.dump(kust.raw, default_flow_style=False))
        return "\n---\n".join(parts)

    def _get_issuer_context(self) -> str:
        """Get ClusterIssuer context."""
        parts = []
        for issuer in self.arch.cluster_issuers:
            parts.append(yaml.dump(issuer.raw, default_flow_style=False))
        return "\n---\n".join(parts)

    def _get_ingress_context(self, name: str) -> str:
        """Get Ingress context."""
        for ing in self.arch.ingresses:
            if ing.name == name:
                return yaml.dump(ing.raw, default_flow_style=False)
        return ""

    def _get_ingress_and_traefik_context(self, ingress_name: str) -> str:
        """Get Ingress and Traefik context together."""
        parts = []
        for ing in self.arch.ingresses:
            if ing.name == ingress_name:
                parts.append(f"# Ingress: {ing.name}")
                parts.append(yaml.dump(ing.raw, default_flow_style=False))
        for hr in self.arch.helm_releases:
            if hr.name == 'traefik':
                parts.append("# Traefik HelmRelease")
                parts.append(yaml.dump(hr.raw, default_flow_style=False))
        return "\n---\n".join(parts)

    def _get_external_secrets_context(self) -> str:
        """Get External Secrets context."""
        parts = []
        for es in self.arch.external_secrets:
            parts.append(yaml.dump(es.raw, default_flow_style=False))
        for res in self.arch.by_kind.get('ClusterSecretStore', []):
            parts.append(yaml.dump(res.raw, default_flow_style=False))
        for hr in self.arch.helm_releases:
            if hr.name == 'external-secrets':
                parts.append(yaml.dump(hr.raw, default_flow_style=False))
        return "\n---\n".join(parts)

    def _get_solr_context(self, name: str) -> str:
        """Get SolrCloud context."""
        for solr in self.arch.solr_clouds:
            if solr.name == name:
                return yaml.dump(solr.raw, default_flow_style=False)
        return ""

    def _get_kustomization_structure(self) -> str:
        """Get a description of the kustomization structure."""
        parts = ["# Directory Structure (conceptual):"]
        parts.append("# infrastructure/")
        parts.append("#   base/       - common infrastructure components")
        parts.append("#   staging/    - staging-specific patches")
        parts.append("#   production/ - production-specific patches")
        parts.append("# apps/")
        parts.append("#   base/       - common application configs")
        parts.append("#   staging/    - staging applications")
        parts.append("#   production/ - production applications")
        return "\n".join(parts)
