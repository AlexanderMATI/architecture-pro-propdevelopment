#!/bin/bash

create_user() {
    local username=$1
    local group=$2

    echo "Создаю пользователя: $username"

   
    openssl genrsa -out ${username}.key 2048

    openssl req -new -key ${username}.key \
        -out ${username}.csr \
        -subj "/CN=${username}/O=${group}"

  
    openssl x509 -req -in ${username}.csr \
        -CA ~/.minikube/ca.crt \
        -CAkey ~/.minikube/ca.key \
        -CAcreateserial \
        -out ${username}.crt \
        -days 365

  
    kubectl config set-credentials ${username} \
        --client-certificate=${username}.crt \
        --client-key=${username}.key

    kubectl config set-context ${username}-context \
        --cluster=minikube \
        --user=${username} \
        --namespace=default

    echo "Пользователь $username создан успешно"
    echo "---"
}
create_user "kube-admin" "admins"

create_user "kube-viewer" "viewers"