#!/bin/bash

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "====================================================================="
echo "   Validating that secure pods can be deployed successfully...      "
echo "====================================================================="
echo

# Определяем директорию скрипта
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Директория с безопасными манифестами (относительно корня Task7)
SECURE_DIR="$SCRIPT_DIR/../secure-manifests"

if [ ! -d "$SECURE_DIR" ]; then
    echo -e "${RED}Error: Directory '$SECURE_DIR' not found.${NC}"
    echo "Current script directory: $SCRIPT_DIR"
    echo "Please ensure the script is in the verify/ subdirectory of Task7"
    exit 1
fi

# Применяем все безопасные манифесты
for manifest in $(ls ${SECURE_DIR}/*.yaml 2>/dev/null); do
    echo "--> Applying secure manifest: $(basename $manifest)"
    if kubectl apply -f $manifest 2>&1; then
        echo -e "    ${GREEN}SUCCESS: Manifest applied successfully.${NC}"
    else
        echo -e "    ${RED}FAILURE: Could not apply manifest.${NC}"
        exit 1
    fi
    echo
done

echo "All secure manifests have been applied. Checking pod status..."
echo

# Проверка статуса подов
kubectl get pods -n audit-zone

echo
echo "Cleaning up resources..."
echo

# Удаляем все безопасные манифесты
for manifest in $(ls ${SECURE_DIR}/*.yaml 2>/dev/null); do
    echo "--> Deleting resources from manifest: $(basename $manifest)"
    kubectl delete -f $manifest --ignore-not-found=true 2>/dev/null
done

echo
echo "====================================================================="
echo -e "${GREEN}Validation successful! All secure pods were deployed and cleaned up.${NC}"
echo "====================================================================="