// Real node_type values as written by backend/graph/graph_builder.py's
// _ingest_aws / _ingest_azure / _ingest_gcp / _ingest_k8s methods.
// Bucketed into the five UI categories used for icons and heatmap columns.
// Policy and Resource are legitimately empty today - no collector populates
// them yet (see PUNCHLIST known limitation #12) - but the buckets are kept
// so new node types added later have somewhere to land.

export const NODE_TYPE_CATEGORY = {
  aws_user: 'Identity',
  aws_role: 'Role',

  azure_user: 'Identity',
  azure_service_principal: 'Identity',
  azure_managed_identity: 'Identity',
  azure_role_definition: 'Role',

  gcp_service_account: 'ServiceAccount',
  gcp_custom_role: 'Role',
  gcp_builtin_role: 'Role',

  k8s_service_account: 'ServiceAccount',
  k8s_user: 'Identity',
  k8s_group: 'Identity',
  k8s_role: 'Role',
  k8s_cluster_role: 'Role',
}

export function nodeCategory(nodeType) {
  return NODE_TYPE_CATEGORY[nodeType] || 'Resource'
}

// Real cloud_provider values stored on nodes (graph_builder.py always
// writes "k8s", never "kubernetes" - see backend/graph/graph_builder.py:531).
export const PROVIDERS = ['aws', 'azure', 'gcp', 'k8s']
