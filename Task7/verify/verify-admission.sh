#!/bin/bash

# Цвета для вывода
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "====================================================================="
echo " Verifying that insecure pods are BLOCKED by admission controllers... "
echo "====================================================================="
echo

# Определяем директорию скрипта
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Директория с небезопасными манифестами (относительно корня Task7)
INSECURE_DIR="$SCRIPT_DIR/../insecure-manifests"
# Флаг для отслеживания общего результата
OVERALL_SUCCESS=true

# Проверяем, существует ли директория
if [ ! -d "$INSECURE_DIR" ]; then
    echo -e "${RED}Error: Directory '$INSECURE_DIR' not found.${NC}"
    echo "Current script directory: $SCRIPT_DIR"
    echo "Please ensure the script is in the verify/ subdirectory of Task7"
    exit 1
fi

for manifest in $(ls ${INSECURE_DIR}/*.yaml 2>/dev/null); do
    echo "--> Testing manifest: $(basename $manifest)"

    output=$(kubectl apply -f $manifest 2>&1)
    exit_code=$?

    if [ $exit_code -ne 0 ]; then
        echo -e "    ${GREEN}SUCCESS: Pod creation was blocked as expected.${NC}"
        echo "    Reason: $(echo "$output" | tail -n 1)"
    else
        echo -e "    ${RED}FAILURE: Pod was created, but should have been blocked!${NC}"
        OVERALL_SUCCESS=false
        kubectl delete -f $manifest --ignore-not-found=true > /dev/null 2>&1
    fi
    echo
done

echo "====================================================================="
if [ "$OVERALL_SUCCESS" = true ]; then
    echo -e "${GREEN}Verification successful! All insecure pods were correctly blocked.${NC}"
else
    echo -e "${RED}Verification failed! One or more insecure pods were not blocked.${NC}"
    exit 1
fi
echo "====================================================================="