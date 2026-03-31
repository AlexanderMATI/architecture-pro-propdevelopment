#!/usr/bin/env python3
import json
import sys

def filter_audit(logfile):
    suspicious = []
    with open(logfile, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except:
                continue
            
            user = event.get('user', {}).get('username', 'unknown')
            verb = event.get('verb')
            obj = event.get('objectRef', {})
            uri = event.get('requestURI', '')
            
            # Доступ к секретам
            if obj.get('resource') == 'secrets' and verb in ['get', 'list']:
                suspicious.append({
                    'timestamp': event.get('timestamp'),
                    'user': user,
                    'verb': verb,
                    'objectRef': obj,
                    'responseStatus': event.get('responseStatus', {}),
                    'type': 'SECRET_ACCESS',
                    'reason': 'Несанкционированный доступ к секретам'
                })
            
            # Привилегированный под
            elif obj.get('resource') == 'pods' and verb == 'create':
                req = event.get('requestObject', {})
                containers = req.get('spec', {}).get('containers', [])
                for c in containers:
                    if c.get('securityContext', {}).get('privileged'):
                        suspicious.append({
                            'timestamp': event.get('timestamp'),
                            'user': user,
                            'verb': verb,
                            'objectRef': obj,
                            'responseStatus': event.get('responseStatus', {}),
                            'type': 'PRIVILEGED_POD',
                            'reason': 'Создание привилегированного пода'
                        })
                        break
            
            # kubectl exec
            elif obj.get('subresource') == 'exec':
                suspicious.append({
                    'timestamp': event.get('timestamp'),
                    'user': user,
                    'verb': verb,
                    'objectRef': obj,
                    'responseStatus': event.get('responseStatus', {}),
                    'type': 'ILLEGAL_EXEC',
                    'reason': 'kubectl exec в чужом поде'
                })
            
            # RoleBinding с cluster-admin
            elif obj.get('resource') == 'rolebindings' and verb == 'create':
                req = event.get('requestObject', {})
                if req.get('roleRef', {}).get('name') == 'cluster-admin':
                    suspicious.append({
                        'timestamp': event.get('timestamp'),
                        'user': user,
                        'verb': verb,
                        'objectRef': obj,
                        'responseStatus': event.get('responseStatus', {}),
                        'type': 'PRIVILEGE_ESCALATION',
                        'reason': 'Создание RoleBinding с правами cluster-admin'
                    })
            
            # Изменение audit policy
            elif 'audit-policy' in uri.lower() or 'audit-policy' in str(obj).lower():
                suspicious.append({
                    'timestamp': event.get('timestamp'),
                    'user': user,
                    'verb': verb,
                    'objectRef': obj,
                    'responseStatus': event.get('responseStatus', {}),
                    'type': 'AUDIT_POLICY_CHANGE',
                    'reason': 'Попытка изменения/удаления политики аудита'
                })
    
    return suspicious

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python filter-audit.py audit.log")
        sys.exit(1)
    
    result = filter_audit(sys.argv[1])
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
