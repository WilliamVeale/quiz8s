"""Parse Kubernetes manifests and extract relationships between resources."""

import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any
import yaml


@dataclass
class K8sResource:
    """Represents a Kubernetes resource."""
    api_version: str
    kind: str
    name: str
    namespace: str | None
    file_path: str
    spec: dict[str, Any]
    metadata: dict[str, Any]
    raw: dict[str, Any]

    @property
    def gvk(self) -> str:
        """Get Group/Version/Kind identifier."""
        return f"{self.api_version}/{self.kind}"

    @property
    def full_name(self) -> str:
        """Get fully qualified name."""
        if self.namespace:
            return f"{self.namespace}/{self.name}"
        return self.name


@dataclass
class ClusterArchitecture:
    """Represents the overall cluster architecture extracted from manifests."""
    resources: list[K8sResource] = field(default_factory=list)

    # Indexed lookups
    by_kind: dict[str, list[K8sResource]] = field(default_factory=dict)
    by_namespace: dict[str, list[K8sResource]] = field(default_factory=dict)

    # Relationships
    flux_kustomizations: list[K8sResource] = field(default_factory=list)
    helm_releases: list[K8sResource] = field(default_factory=list)
    helm_repositories: list[K8sResource] = field(default_factory=list)
    ingresses: list[K8sResource] = field(default_factory=list)
    services: list[K8sResource] = field(default_factory=list)
    deployments: list[K8sResource] = field(default_factory=list)
    secrets: list[K8sResource] = field(default_factory=list)
    external_secrets: list[K8sResource] = field(default_factory=list)
    cluster_issuers: list[K8sResource] = field(default_factory=list)

    # Custom resources
    solr_clouds: list[K8sResource] = field(default_factory=list)
    zookeeper_clusters: list[K8sResource] = field(default_factory=list)


def parse_yaml_file(file_path: Path) -> list[dict[str, Any]]:
    """Parse a YAML file, handling multi-document files."""
    docs = []
    with open(file_path, 'r') as f:
        content = f.read()
        for doc in yaml.safe_load_all(content):
            if doc:  # Skip empty documents
                docs.append(doc)
    return docs


def parse_resource(doc: dict[str, Any], file_path: str) -> K8sResource | None:
    """Parse a single Kubernetes resource from a YAML document."""
    if not isinstance(doc, dict):
        return None

    api_version = doc.get('apiVersion', '')
    kind = doc.get('kind', '')
    metadata = doc.get('metadata', {})

    if not api_version or not kind or not metadata:
        return None

    return K8sResource(
        api_version=api_version,
        kind=kind,
        name=metadata.get('name', ''),
        namespace=metadata.get('namespace'),
        file_path=file_path,
        spec=doc.get('spec', {}),
        metadata=metadata,
        raw=doc
    )


def scan_manifests(root_dir: str | Path) -> ClusterArchitecture:
    """Scan a directory for Kubernetes manifests and build architecture model."""
    root_dir = Path(root_dir)
    arch = ClusterArchitecture()

    # Find all YAML files
    yaml_files = list(root_dir.rglob('*.yaml')) + list(root_dir.rglob('*.yml'))

    for yaml_file in yaml_files:
        try:
            docs = parse_yaml_file(yaml_file)
            for doc in docs:
                resource = parse_resource(doc, str(yaml_file))
                if resource:
                    arch.resources.append(resource)

                    # Index by kind
                    if resource.kind not in arch.by_kind:
                        arch.by_kind[resource.kind] = []
                    arch.by_kind[resource.kind].append(resource)

                    # Index by namespace
                    ns = resource.namespace or '_cluster_'
                    if ns not in arch.by_namespace:
                        arch.by_namespace[ns] = []
                    arch.by_namespace[ns].append(resource)

                    # Categorize by type
                    _categorize_resource(arch, resource)
        except Exception as e:
            print(f"Warning: Failed to parse {yaml_file}: {e}")

    return arch


def _categorize_resource(arch: ClusterArchitecture, resource: K8sResource):
    """Categorize a resource into the appropriate list."""
    kind = resource.kind

    if kind == 'Kustomization' and 'toolkit.fluxcd.io' in resource.api_version:
        arch.flux_kustomizations.append(resource)
    elif kind == 'HelmRelease':
        arch.helm_releases.append(resource)
    elif kind == 'HelmRepository':
        arch.helm_repositories.append(resource)
    elif kind == 'Ingress':
        arch.ingresses.append(resource)
    elif kind == 'Service':
        arch.services.append(resource)
    elif kind == 'Deployment':
        arch.deployments.append(resource)
    elif kind == 'Secret':
        arch.secrets.append(resource)
    elif kind == 'ExternalSecret':
        arch.external_secrets.append(resource)
    elif kind == 'ClusterIssuer':
        arch.cluster_issuers.append(resource)
    elif kind == 'SolrCloud':
        arch.solr_clouds.append(resource)
    elif kind == 'ZookeeperCluster':
        arch.zookeeper_clusters.append(resource)


def extract_relationships(arch: ClusterArchitecture) -> dict[str, Any]:
    """Extract relationships between resources for question generation."""
    relationships = {
        'flux_dependencies': [],
        'helm_to_repo': [],
        'ingress_to_service': [],
        'tls_certificates': [],
        'external_secret_refs': [],
        'zookeeper_clients': [],
    }

    # Flux Kustomization dependencies
    for kust in arch.flux_kustomizations:
        deps = kust.spec.get('dependsOn', [])
        if deps:
            relationships['flux_dependencies'].append({
                'kustomization': kust.name,
                'depends_on': [d.get('name') for d in deps],
                'path': kust.spec.get('path', ''),
            })

    # HelmRelease to HelmRepository
    for hr in arch.helm_releases:
        chart_spec = hr.spec.get('chart', {}).get('spec', {})
        source_ref = chart_spec.get('sourceRef', {})
        relationships['helm_to_repo'].append({
            'release': hr.name,
            'namespace': hr.namespace,
            'chart': chart_spec.get('chart', ''),
            'repo': source_ref.get('name', ''),
            'values': hr.spec.get('values', {}),
        })

    # Ingress to backend services
    for ing in arch.ingresses:
        annotations = ing.metadata.get('annotations', {})
        tls = ing.spec.get('tls', [])
        rules = ing.spec.get('rules', [])

        for rule in rules:
            host = rule.get('host', '')
            for path in rule.get('http', {}).get('paths', []):
                backend = path.get('backend', {})
                service = backend.get('service', {})
                relationships['ingress_to_service'].append({
                    'ingress': ing.name,
                    'namespace': ing.namespace,
                    'host': host,
                    'path': path.get('path', '/'),
                    'service': service.get('name', ''),
                    'port': service.get('port', {}).get('number'),
                    'annotations': annotations,
                })

        # TLS configuration
        for tls_config in tls:
            issuer = annotations.get('cert-manager.io/cluster-issuer', '')
            relationships['tls_certificates'].append({
                'ingress': ing.name,
                'hosts': tls_config.get('hosts', []),
                'secret': tls_config.get('secretName', ''),
                'issuer': issuer,
            })

    # External Secrets references
    for es in arch.external_secrets:
        store_ref = es.spec.get('secretStoreRef', {})
        relationships['external_secret_refs'].append({
            'name': es.name,
            'namespace': es.namespace,
            'store': store_ref.get('name', ''),
            'store_kind': store_ref.get('kind', ''),
            'target': es.spec.get('target', {}).get('name', ''),
            'data': es.spec.get('data', []),
        })

    # ZooKeeper clients (SolrCloud)
    for solr in arch.solr_clouds:
        zk_ref = solr.spec.get('zookeeperRef', {})
        conn_info = zk_ref.get('connectionInfo', {})
        relationships['zookeeper_clients'].append({
            'solr_cloud': solr.name,
            'namespace': solr.namespace,
            'zk_connection': conn_info.get('internalConnectionString', ''),
            'chroot': conn_info.get('chroot', ''),
        })

    return relationships


def get_resource_context(arch: ClusterArchitecture, resource_name: str = None,
                         kind: str = None) -> str:
    """Get YAML context for specific resources."""
    context_parts = []

    for res in arch.resources:
        if resource_name and resource_name.lower() not in res.name.lower():
            continue
        if kind and kind.lower() != res.kind.lower():
            continue

        context_parts.append(f"# {res.kind}: {res.full_name}\n# File: {res.file_path}")
        context_parts.append(yaml.dump(res.raw, default_flow_style=False))

    return "\n---\n".join(context_parts)
