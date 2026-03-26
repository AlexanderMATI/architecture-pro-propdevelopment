#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import argparse
import sys

def check_secret_access(log_entry):
    try:
        ref = log_entry.get('objectRef', {})
        return ref.get('resource') == 'secrets' and log_entry.get('verb') in ['get', 'list']
    except (AttributeError, KeyError):
        return False

def check_kubectl_exec(log_entry):
    try:
        ref = log_entry.get('objectRef', {})
        return log_entry.get('verb') == 'create' and ref.get('subresource') == 'exec'
    except (AttributeError, KeyError):
        return False

def check_privileged_pod_creation(log_entry):
    try:
        ref = log_entry.get('objectRef', {})
        if ref.get('resource') != 'pods' or log_entry.get('verb') != 'create':
            return False

        request_object = log_entry.get('requestObject', {})
        if not request_object:
            return False

        spec = request_object.get('spec', {})
        containers = spec.get('containers', [])
        
        for container in containers:
            security_context = container.get('securityContext', {})
            if security_context.get('privileged') is True:
                return True
    except (AttributeError, KeyError, TypeError):
        return False
    return False

def check_privilege_escalation(log_entry):
    """Проверка на создание RoleBinding с cluster-admin"""
    try:
        ref = log_entry.get('objectRef', {})
        if ref.get('resource') != 'rolebindings' or log_entry.get('verb') != 'create':
            return False
        
        request_object = log_entry.get('requestObject', {})
        if request_object:
            role_ref = request_object.get('roleRef', {})
            if role_ref.get('name') == 'cluster-admin':
                return True
    except (AttributeError, KeyError, TypeError):
        return False
    return False

def check_audit_policy_change(log_entry):
    """Проверка на изменение/удаление политики аудита"""
    try:
        # Проверка по objectRef
        ref = log_entry.get('objectRef', {})
        if 'audit-policy' in str(ref).lower():
            return True
        
        # Проверка по requestURI
        uri = log_entry.get('requestURI', '')
        if 'audit-policy' in uri.lower():
            return True
        
        # Проверка по строке в любом поле (fallback)
        log_str = json.dumps(log_entry).lower()
        if 'audit-policy' in log_str:
            return True
    except (AttributeError, KeyError):
        return False
    return False

def main():
    parser = argparse.ArgumentParser(
        description="Фильтрует лог-файл аудита Kubernetes на предмет подозрительных активностей",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "logfile",
        help="Путь к файлу аудита Kubernetes (в формате JSON lines)"
    )
    args = parser.parse_args()

    suspicious_events = []

    try:
        with open(args.logfile, 'r', encoding='utf-8') as f:
            for line in f:
                raw_line = line.strip()
                if not raw_line:
                    continue

                try:
                    log_entry = json.loads(raw_line)
                except json.JSONDecodeError:
                    continue

                event_info = {
                    'timestamp': log_entry.get('timestamp'),
                    'user': log_entry.get('user', {}).get('username', 'unknown'),
                    'verb': log_entry.get('verb'),
                    'objectRef': log_entry.get('objectRef', {}),
                    'responseStatus': log_entry.get('responseStatus', {}),
                    'requestURI': log_entry.get('requestURI')
                }

                if check_secret_access(log_entry):
                    event_info['type'] = 'SECRET_ACCESS'
                    event_info['reason'] = 'Несанкционированный доступ к секретам'
                    suspicious_events.append(event_info)

                if check_kubectl_exec(log_entry):
                    event_info['type'] = 'ILLEGAL_EXEC'
                    event_info['reason'] = 'kubectl exec в чужом поде'
                    suspicious_events.append(event_info)

                if check_privileged_pod_creation(log_entry):
                    event_info['type'] = 'PRIVILEGED_POD'
                    event_info['reason'] = 'Создание привилегированного пода'
                    suspicious_events.append(event_info)

                if check_privilege_escalation(log_entry):
                    event_info['type'] = 'PRIVILEGE_ESCALATION'
                    event_info['reason'] = 'Создание RoleBinding с правами cluster-admin'
                    suspicious_events.append(event_info)

                if check_audit_policy_change(log_entry):
                    event_info['type'] = 'AUDIT_POLICY_CHANGE'
                    event_info['reason'] = 'Попытка изменения/удаления политики аудита'
                    suspicious_events.append(event_info)

    except FileNotFoundError:
        print(f"Ошибка: Файл логов не найден по пути '{args.logfile}'", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Произошла непредвиденная ошибка: {e}", file=sys.stderr)
        sys.exit(1)

    # Вывод в формате JSON (как требуется в задании)
    print(json.dumps(suspicious_events, indent=2, ensure_ascii=False, default=str))

if __name__ == "__main__":
    main()