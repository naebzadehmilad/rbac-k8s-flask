# rbac-k8s-flask
Kubernetes Access Management API

This Flask application provides endpoints to manage Kubernetes resources by creating, updating, and deleting roles and permissions. It interacts with the Kubernetes API to perform operations based on user requests. The application is designed to handle various types of Kubernetes resources, including Pods, Services, Deployments, ConfigMaps, Namespaces, and more.

Overview
The application exposes three main endpoints:

/update - Updates or creates Kubernetes roles and role bindings.
/delete - Deletes Kubernetes roles and role bindings.
/show_all - Displays all user privileges in the Kubernetes cluster.

If Keycloak is enabled in your configuration (keycloak: true), additional endpoints will be available for handling authentication tasks.
/login
/refresh-token
/check-token


1. /update
Updates or creates Kubernetes roles and role bindings.

Request
Method: POST
Content-Type: application/json

Payload Example:

curl -X POST http://127.0.0.1:5000/update \
     -H "Content-Type: application/json" \
     -d '{
           "namespaces": ["t1", "t2-dev"],
           "role_rules": [
             {
               "api_groups": [""],
               "resources": ["pods", "pods/exec", "services", "deployments", "configmaps", "namespaces", "pods/log", "endpoints", "events" ,"nodes"],
               "verbs": ["get", "list", "watch", "create", "update", "patch", "delete", "deletecollection", "exec"]
             },
             {
               "api_groups": ["apps"],
               "resources": ["statefulsets", "replicasets", "daemonsets","deployments", "ingressroute" , "ingress"],
               "verbs": ["get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"]
             },
             {
               "api_groups": ["batch"],
               "resources": ["cronjobs"],
               "verbs": ["get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"]
             },
             {
               "api_groups": ["storage.k8s.io"],
               "resources": ["storageclasses"],
               "verbs": ["get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"]
             },
             {
               "api_groups": ["networking.k8s.io"],
               "resources": ["ingresses", "ingressclasses", "networkpolicies"],
               "verbs": ["get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"]
             },
             {
               "api_groups": ["traefik.containo.us"],
               "resources": ["ingressroutes"],
               "verbs": ["get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"]
             }
           ],
           "user_name": "milad1"
         }'
چ

Or minimal 

  curl -X POST http://127.0.0.1:5000/update \
     -H "Content-Type: application/json" \
     -d '{
           "namespaces": ["t1", "t2-dev"],
           "role_rules": [
             {
               "api_groups": [""],
               "resources": ["pods", "pods/exec", "services", "deployments", "configmaps", "namespaces", "pods/log", "endpoints", "events", "nodes"],
               "verbs": ["get", "list", "watch", "create", "update", "patch", "delete", "deletecollection", "exec"]
             }
           ],
           "user_name": "milad1"
         }'


Response
  Success: Returns the tokens and kubeconfig in YAML format.
  Error: Returns error message if the request is invalid or an exception .

2.
  /delete
  Deletes Kubernetes roles and role bindings.

Request
Method: POST
Content-Type: application/json

curl -X POST http://127.0.0.1:5000/delete \
     -H "Content-Type: application/json" \
     -d '{
           "namespaces": [ "t1","t2-dev"],
           "user_name": "milad1"
         }'

Response
Success: Returns a message  that resources were deleted successfully.
Error: Returns error message if the request is invalid or an exception .
