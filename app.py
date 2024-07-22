from flask import Flask, request, jsonify
import yaml
from k8s import *
from render import *
from utils import *
from auth import *
import base64

app = Flask(__name__)




@app.route('/update', methods=['POST'])
def update_resources():
    if KEYCLOAK.lower() == 'true':
        if protect_func():
            return protect_func()
    try:
        data = request.json
        namespaces = data.get('namespaces', [])
        role_rules = data.get('role_rules', [])
        user_name = data.get('user_name')

        # Check if namespaces are protected
        if check_protected_namespaces(namespaces, protect_ns):
            log_event.error(f'Update Failure: One or more namespaces are protected. User: {user_name}')
            return jsonify({'error': 'One or more namespaces are protected'}), 400

        if not role_rules or not user_name:
            log_event.error(f'Update Failure: Missing required fields. User: {user_name}')
            return jsonify({'error': 'Missing required fields'}), 400

        # Create or update ServiceAccount in namespace
        create_or_update_service_account(f'{SA_IN_NS}', user_name)

        tokens = {}
        role_rules_objs = [
            V1PolicyRule(
                api_groups=rule.get('api_groups', []),
                resources=rule.get('resources', []),
                verbs=rule.get('verbs', [])
            ) for rule in role_rules
        ]

        # Track existing namespaces for RoleBindings
        existing_namespaces = set()

        # Create or update roles and bindings
        for namespace in namespaces:
            create_or_update_role(namespace, f"{user_name}-role", role_rules_objs)
            create_or_update_role_binding(namespace, f"{user_name}-role", user_name)
            existing_namespaces.add(namespace)

        # Generate or retrieve token for the ServiceAccount
        token = generate_or_update_token_for_service_account(user_name, f'{SA_IN_NS}')
        if not token:
            log_event.error(f'Update Failure: Failed to generate or find token. User: {user_name}')
            return jsonify({'error': 'Failed to generate or find token'}), 500

        tokens[f'{SA_IN_NS}'] = base64.b64decode(token).decode('utf-8')
        kube_config = generate_kube_config(user_name, tokens, certificate_authority_data, k8s_api_server_url)

        if isinstance(kube_config, dict):
            kube_config = yaml.dump(kube_config)

        # Log success
        log_event.info(f'Update Success: User "{user_name}" in namespaces {", ".join(namespaces)}')

        response = {
            'tokens': tokens,
            'kube_config': kube_config
        }

        return jsonify(response), 200

    except Exception as e:
        log_event.error(f'Update Failure: Exception occurred. User: {user_name}. Error: {str(e)}')
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


@app.route('/delete', methods=['POST'])
def delete_resources():
    if KEYCLOAK.lower() == 'true':
        if protect_func():
            return protect_func()
    try:
        data = request.json
        namespaces = data.get('namespaces', [])
        user_name = data.get('user_name')

        if not isinstance(namespaces, list) or not namespaces:
            log_event.error('Delete Failure: Invalid or missing namespaces.')
            return jsonify({'error': 'Invalid or missing namespaces'}), 400

        if not user_name:
            log_event.error('Delete Failure: Missing required fields.')
            return jsonify({'error': 'Missing required fields'}), 400

        # Check if any of the namespaces are protected
        if any(ns in protect_ns for ns in namespaces):
            log_event.error(f'Delete Failure: One or more namespaces are protected. User: {user_name}')
            return jsonify({'error': 'One or more namespaces are protected'}), 400

        for namespace in namespaces:
            # Delete RoleBinding
            role_binding_name = f"{user_name}-rolebinding"
            delete_role_binding(namespace, role_binding_name)

            # Optionally, delete Role
            rbac_api = client.RbacAuthorizationV1Api()
            role_bindings = rbac_api.list_namespaced_role_binding(namespace)
            role_exists = any(rb.metadata.name.startswith(f"{user_name}-role") for rb in role_bindings.items)

            if not role_exists:
                delete_role(namespace, f"{user_name}-role")

        # Log success
        log_event.info(f'Delete Success: User "{user_name}" in namespaces {", ".join(namespaces)}')

        return jsonify({'message': 'Resources deleted successfully'})

    except Exception as e:
        log_event.error(f'Delete Failure: Exception occurred. User: {user_name}. Error: {str(e)}')
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


@app.route('/show_all', methods=['GET'])
def show_all_user_privileges():
    try:
        core_api = client.CoreV1Api()
        rbac_api = client.RbacAuthorizationV1Api()

        # Retrieve all namespaces
        namespaces = core_api.list_namespace()
        privileges = {}

        for ns in namespaces.items:
            namespace = ns.metadata.name
            role_bindings = rbac_api.list_namespaced_role_binding(namespace)
            namespace_privileges = {}

            for rb in role_bindings.items:
                user_name = None
                if rb.subjects:
                    user_name = rb.subjects[0].name

                if user_name:
                    role_name = rb.role_ref.name
                    role = rbac_api.read_namespaced_role(role_name, namespace)
                    rules = []

                    if role and role.rules:
                        for rule in role.rules:
                            rules.append({
                                'api_groups': rule.api_groups,
                                'resources': rule.resources,
                                'verbs': rule.verbs
                            })

                        if user_name not in namespace_privileges:
                            namespace_privileges[user_name] = []

                        namespace_privileges[user_name].append({
                            'role_name': role_name,
                            'rules': rules
                        })

            if namespace_privileges:
                privileges[namespace] = namespace_privileges

        # Log success
        log_event.info('Show all user privileges success.')

        return jsonify({'privileges': privileges})

    except Exception as e:
        log_event.error(f'Show all user privileges Failure: Exception occurred. Error: {str(e)}')
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500




####################auth-start
@app.route('/login', methods=['POST'])
def login():

    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    token_url = f"{KEYCLOAK_URL}/realms/{REALM_NAME}/protocol/openid-connect/token"
    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'password',
        'username': username,
        'password': password
    }

    response = requests.post(token_url, data=data)

    if response.status_code != 200:
        return jsonify({"error": "Invalid credentials"}), 401

    token_data = response.json()
    log_event('info',f'Access by: {username}')
    return jsonify(token_data), 200


@app.route('/refreshtoken', methods=['POST'])
def refresh_token():

    refresh_token = request.json.get('refresh_token')

    if not refresh_token:
        return jsonify({"error": "Refresh token required"}), 400

    token_url = f"{KEYCLOAK_URL}/realms/{REALM_NAME}/protocol/openid-connect/token"
    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token
    }

    response = requests.post(token_url, data=data)

    if response.status_code != 200:
        return jsonify({"error": "Invalid refresh token"}), 401

    token_data = response.json()
    log_event('info',f'Access by refresh token : {refresh_token}')
    return jsonify(token_data), 200


@app.route('/check-token', methods=['GET'])
def check_token():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"error": "Authorization header required"}), 401

    token = auth_header.split(" ")[1]

    is_valid, result = validate_token(token)
    if not is_valid:
        return jsonify(result), 401

    return jsonify({"message": "Token is valid."}), 200

##################################auth-end

if __name__ == '__main__':
    app.run(debug=True)
