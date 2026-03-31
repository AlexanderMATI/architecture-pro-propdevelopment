
kubectl apply -f 01-create-namespace.yaml

kubectl apply -f gatekeeper/constraint-templates/

kubectl apply -f gatekeeper/constraints/

    ```Bash
    bash ./verify/verify-admission.sh
    ```

    ```Bash
    bash ./verify/validate-security.sh
    ```
