from config import *
from utils import *
from kubernetes import client,config
from kubernetes.client.models import (
    V1ObjectMeta,
    V1PolicyRule,
    V1Role,
    V1RoleBinding,
    V1RoleRef,
    V1ServiceAccount,
    V1Secret
)

config.load_kube_config(kubeconfig_path)


def check_protected_namespaces(namespaces, protect_ns):

    return any(ns in protect_ns for ns in namespaces)


def create_or_update_role(namespace, role_name, rules):
    rbac_api = client.RbacAuthorizationV1Api()
    role = V1Role(
        metadata=V1ObjectMeta(name=role_name, namespace=namespace),
        rules=rules
    )
    try:
        rbac_api.create_namespaced_role(namespace, role)
    except client.exceptions.ApiException as e:
        if e.status == 409:
            rbac_api.replace_namespaced_role(role_name, namespace, role)
        else:
            log_event('error', f"Error creating/updating role in namespace {namespace}: {str(e)}")
            raise Exception(f'Error creating/updating role in namespace {namespace}: {str(e)}')

def create_or_update_role_binding(namespace, role_name, service_account_name):
    rbac_api = client.RbacAuthorizationV1Api()
    role_binding = V1RoleBinding(
        metadata=V1ObjectMeta(name=f"{service_account_name}-rolebinding", namespace=namespace),
        subjects=[
            {
                'kind': 'ServiceAccount',
                'name': service_account_name,
                'namespace': 'default'  # ServiceAccount in the 'default' namespace
            }
        ],
        role_ref=V1RoleRef(
            kind='Role',
            name=role_name,
            api_group='rbac.authorization.k8s.io'
        )
    )
    try:
        rbac_api.create_namespaced_role_binding(namespace, role_binding)
    except client.exceptions.ApiException as e:
        if e.status == 409:
            rbac_api.replace_namespaced_role_binding(f"{service_account_name}-rolebinding", namespace, role_binding)
        else:
            log_event('error', f"Error creating/updating role binding in namespace {namespace}: {str(e)}")
            raise Exception(f'Error creating/updating role binding in namespace {namespace}: {str(e)}')


def delete_role_binding(namespace, role_binding_name):
    rbac_api = client.RbacAuthorizationV1Api()
    try:
        rbac_api.delete_namespaced_role_binding(role_binding_name, namespace)
    except client.exceptions.ApiException as e:
        if e.status != 404:
            log_event('error', f"Error deleting role binding in namespace {namespace}: {str(e)}")
            raise Exception(f'Error deleting role binding in namespace {namespace}: {str(e)}')


def delete_role(namespace, role_name):
    rbac_api = client.RbacAuthorizationV1Api()
    try:
        rbac_api.delete_namespaced_role(role_name, namespace)
    except client.exceptions.ApiException as e:
        if e.status != 404:
            log_event('error', f"Error deleting role  in namespace {namespace}: {str(e)}")
            raise Exception(f'Error deleting role in namespace {namespace}: {str(e)}')



def create_or_update_service_account(namespace, service_account_name):
    core_api = client.CoreV1Api()
    try:
        core_api.read_namespaced_service_account(service_account_name, namespace)
    except client.exceptions.ApiException as e:
        if e.status == 404:
            service_account = V1ServiceAccount(metadata=V1ObjectMeta(name=service_account_name, namespace=namespace))
            core_api.create_namespaced_service_account(namespace, service_account)
        else:
            log_event('error', f"Error checking/creating service account in namespace{namespace}: {str(e)}")
            raise Exception(f'Error checking/creating service account in namespace {namespace}: {str(e)}')



def generate_or_update_token_for_service_account(service_account_name, namespace):
    core_api = client.CoreV1Api()
    secret_name_prefix = f'{service_account_name}-token'
    secrets = core_api.list_namespaced_secret(namespace)
    token_secret = None

    for secret in secrets.items:
        if secret.type == 'kubernetes.io/service-account-token' and \
                secret.metadata.annotations.get('kubernetes.io/service-account.name') == service_account_name:
            token_secret = secret
            break

    if token_secret:
        token = token_secret.data.get('token')
        if token:
            return token
        else:
            raise Exception("Token not found in the secret data.")

    secret = V1Secret(
        metadata=V1ObjectMeta(
            name=f'{service_account_name}-token',
            annotations={'kubernetes.io/service-account.name': service_account_name}
        ),
        type='kubernetes.io/service-account-token'
    )

    try:
        core_api.create_namespaced_secret(namespace, secret)
        secret_response = core_api.read_namespaced_secret(f'{service_account_name}-token', namespace)
        token = secret_response.data.get('token')
        if token:
            return token
        else:
            raise Exception("Token not found in the secret data.")
    except client.exceptions.ApiException as e:
        if e.status == 409:
            secret_response = core_api.read_namespaced_secret(f'{service_account_name}-token', namespace)
            token = secret_response.data.get('token')
            if token:
                return token
            else:
                raise Exception("Token not found in the secret data.")
        else:
            raise
