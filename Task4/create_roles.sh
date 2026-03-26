#!/bin/bash

echo "Создание ролей"
echo "роль cluster-admin уже существует по умолчанию"

cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-viewer
rules:
- apiGroups: [""]
  resources: ["pods","services", "configmaps", "secrets", "nodes", "namespaces"]
  verbs: ["get", "list", "watch"] 
- apiGroups: ["apps"]
  resources: ["deployment", "statefulsets", "replicasets"]
  verbs: ["get", "list", "watch"]
EOF

