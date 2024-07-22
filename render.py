def generate_kube_config(username, tokens, k8s_api_server_url, certificate_authority_data):
    kube_config = {
        'apiVersion': 'v1',
        'kind': 'Config',
        'clusters': [
            {
                'cluster': {
                    'certificate-authority-data': certificate_authority_data,
                    'server': k8s_api_server_url
                },
                'name': 'kubernetes'
            }
        ],
        'contexts': [
            {
                'context': {
                    'cluster': 'kubernetes',
                    'user': username
                },
                'name': f'{username}-context'
            }
        ],
        'current-context': f'{username}-context',
        'users': [
            {
                'name': username,
                'user': {
                    'token': tokens
                }
            }
        ]
    }

    return kube_config
