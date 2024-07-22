import os
########auth-jwt
KEYCLOAK = 'false'
KEYCLOAK_URL = 'https://keycloak'
REALM_NAME = 'REALM'
CLIENT_ID = 'CLIENT_ID'
CLIENT_SECRET = 'github'
##############auth-jwt


kubeconfig_path = os.getenv('KUBECONFIG_PATH', '/Users/milad/Desktop/k8stoken')
protect_ns=['kube-system','dev']
SA_IN_NS ='default'
k8s_api_server_url= 'test_url'
certificate_authority_data = 'test_cert'
