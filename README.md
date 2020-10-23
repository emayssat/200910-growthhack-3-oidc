# Growth-hack: Identities spanning GCP and AWS

In this demo, we demonstrate how our identity framework can be used in an heterogeneous environment, including
* How our 'SPIFFE' identity framework can be deployed in a kubernetes environment, such as GKE
* How the identity server, identity agent, and client application communicate with each other in a GKE cluster
* How to configure AWS IAM to use an external identity provider
* How to map connections using OIDC to an IAM role and policy
* How to securely connect a pod with a SPIFFE ID to an AWS resource like a S3 bucket

Let's get started!

Note: This demo is part of a series of 3 demos prepared for growth-hack 2020:
* IAM components - <https://>
* Workload to workload - <https://>
* Multi-cloud with OIDC - <https://>

## Infrastructure overview

In this demo, we will configure a GKE cluster and create AWS resources such as polciy, role, bucket, and an identity provider.
At a high level the infrastructure looks, or rather will look, like this

![gke_aws](./.images/900/gke_aws.png)

Before you get started, you need to make sure to install the dependencies (1) the gloud CLI and (2) the AWS CLI.
In this first part, we will be deploying our GKE cluster using the gcloud command line.

```bash
# Google Cloud Platform CLI (aka gcloud)
wget https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-sdk-308.0.0-darwin-x86_64.tar.gz
tar xvzf google-cloud-sdk-308.0.0-darwin-x86_64.tar.gz
./google-cloud-sdk/install.sh
which gcloud
# ./bin/gcloud
gcloud version
# Google Cloud SDK 308.0.0
# bq 2.0.60
# core 2020.08.28
# gsutil 4.53

gcloud init
# ...

```

Make sure the quotas for this project allow for the creation of your cluster

```bash
gcloud  projects list
# PROJECT_ID              NAME              PROJECT_NUMBER
# paasteurizers           paasteurizers     5692652845

gcloud config set project  paasteurizers
# Updated property [core/project].

gcloud compute project-info describe --project paasteurizers
# ...

gcloud compute regions describe us-west1
# ...
```

## Deploy a GKE cluster

On GCP, we can deploy a GKE kubernetes cluster with just one command!
For our demo, we will be deploying a 3-node cluster in the us-west1-a availability zone.

```bash
gcloud container clusters create --num-nodes 3 --zone us-west1-a  paasteurizers-gke
# NAME               LOCATION    MASTER_VERSION  MASTER_IP        MACHINE_TYPE   NODE_VERSION   NUM_NODES  STATUS
# paasteurizers-gke  us-west1-a  1.15.12-gke.2   104.198.105.169  n1-standard-1  1.15.12-gke.2  3          RUNNING

kubectl get nodes
# NAME                                               STATUS   ROLES    AGE   VERSION
# gke-paasteurizers-gke-default-pool-ce4067d8-2760   Ready    <none>   63s   v1.15.12-gke.2
# gke-paasteurizers-gke-default-pool-ce4067d8-n127   Ready    <none>   63s   v1.15.12-gke.2
# gke-paasteurizers-gke-default-pool-ce4067d8-q920   Ready    <none>   63s   v1.15.12-gke.2
```

## Installation of the identity service in the GKE cluster

The server and agents will be deployed in the newly deployed cluster.
Create a namespace where our identity service will be deployed

```bash
cd ./etc/k8s
kubectl apply -f spire--namespace.yaml
# namespace/spire created
```

The identity server will now be deployed as a stateful-set behind a service.
Indeed, the server is deployed as a stateful-set instead of a k8s deployment because the state of our identity service is saved in the server pod (on disk using sqlite3 to be more specific).
Additionally the configuration of the identity server is passed in the configuration map, aka config-map..
Because the server needs to attest agents, the server's service account needs to have the proper cluster-role attached to its service account.

```bash
cd ./etc/k8s
kubectl apply -f server--service-account.yaml -f server--cluster-role.yaml -f spire-bundle--configmap.yaml
# serviceaccount/spire-server created
# clusterrole.rbac.authorization.k8s.io/spire-server-trust-role created
# clusterrolebinding.rbac.authorization.k8s.io/spire-server-trust-role-binding created
# configmap/spire-bundle created

kubectl apply -f server--configmap.yaml -f server--statefulset.yaml -f server--service.yaml 
# configmap/spire-server created
# statefulset.apps/spire-server created
# service/spire-server created

kubectl get pod,services,statefulset --namespace spire
# NAME                 READY   STATUS    RESTARTS   AGE
# pod/spire-server-0   1/1     Running   0          8m56s
# 
# NAME                   TYPE       CLUSTER-IP     EXTERNAL-IP   PORT(S)          AGE
# service/spire-server   NodePort   10.3.244.251   <none>        8081:31695/TCP   8m56s
# 
# NAME                            READY   AGE
# statefulset.apps/spire-server   1/1     8m56s
```

Install the node-agent as a daemon-set, as a result a pod will be running on each of the kubernetes worker nodes.
The configuration of the agents can be found in the spire-agent configmap.
Note to allow agent to attest the workload on that cluster, the agent needs to have the proper cluster-role attached to its service-account.

```bash
cd ./etc/k8s
kubectl apply -f agent--service-account.yaml -f agent--cluster-role.yaml
# serviceaccount/spire-agent created
# clusterrole.rbac.authorization.k8s.io/spire-agent-cluster-role created
# clusterrolebinding.rbac.authorization.k8s.io/spire-agent-cluster-role-binding created

kubectl apply -f agent--configmap.yaml -f agent--daemonset.yaml
# configmap/spire-agent created
# daemonset.apps/spire-agent created

kubectl get daemonset,pod --namespace spire
# NAME                               DESIRED   CURRENT   READY   UP-TO-DATE   AVAILABLE   NODE SELECTOR   AGE
# daemonset.extensions/spire-agent   3         3         3       3            3           <none>          36m
# 
# NAME                    READY   STATUS    RESTARTS   AGE
# pod/spire-agent-jztjm   1/1     Running   0          36m
# pod/spire-agent-wp4d9   1/1     Running   0          36m
# pod/spire-agent-zvns4   1/1     Running   0          36m
# pod/spire-server-0      1/1     Running   0          52m
```

Note that our cluster has 3 nodes and therefore 3 agent-pods have been deployed, one on each of them.

Have the server attest the agent

```bash
kubectl exec -n spire spire-server-0 -- \
    /opt/spire/bin/spire-server entry create \
    -spiffeID spiffe://example.org/ns/spire/sa/spire-agent \
    -selector k8s_sat:cluster:demo-cluster \
    -selector k8s_sat:agent_ns:spire \
    -selector k8s_sat:agent_sa:spire-agent \
    -node
# Entry ID      : c123c439-1f9a-4b61-a514-b9ed435dbc0b
# SPIFFE ID     : spiffe://example.org/ns/spire/sa/spire-agent
# Parent ID     : spiffe://example.org/spire/server
# TTL           : 3600
# Selector      : k8s_sat:cluster:demo-cluster
# Selector      : k8s_sat:agent_ns:spire
# Selector      : k8s_sat:agent_sa:spire-agent
```

Let's validate the installation by deploying a workload.
Before deploying the workload, let's create a fingerprint/profile for that workload so it can get an identity.

```bash
kubectl exec -n spire spire-server-0 -- \
    /opt/spire/bin/spire-server entry create \
    -spiffeID spiffe://example.org/ns/default/sa/default \        # <== ID to be given under the condition that
    -parentID spiffe://example.org/ns/spire/sa/spire-agent \      # ... the request comes from one of those agent
    -selector k8s:ns:default \                                    # ... the workload is in the default k8s namespace
    -selector k8s:sa:default                                      # ... and using the default service account in that namespace
# Entry ID      : f8534819-3572-47c2-a2a2-3ef56532ea05
# SPIFFE ID     : spiffe://example.org/ns/default/sa/default
# Parent ID     : spiffe://example.org/ns/spire/sa/spire-agent
# TTL           : 3600
# Selector      : k8s:ns:default
# Selector      : k8s:sa:default

cd ./etc/k8s
kubectl apply -f client--deployment.yaml    # <== here we deploy a client application
# deployment.apps/client created

kubectl get pods
# NAME                      READY   STATUS    RESTARTS   AGE
# client-55885875c4-vwh9x   1/1     Running   0          73s
```

Now let's exec into the client application pod, to ascertain it can get an identity

```bash
kubectl exec -it client-55885875c4-vwh9x -- /bin/sh
# ... A TERMINAL IN THE CONTAINER OPENS ...
# /opt/spire #
```

In the terminal

```bash
# THOSE COMMANDS ARE EXECUTED IN THE CLIENT CONTAINER

/opt/spire/bin/spire-agent api fetch x509 -socketPath /run/spire/sockets/agent.sock
# Received 1 svid after 8.258499ms
# 
# SPIFFE ID:		spiffe://example.org/ns/default/sa/default
# SVID Valid After:	2020-09-09 21:55:24 +0000 UTC
# SVID Valid Until:	2020-09-09 22:55:34 +0000 UTC
# CA #1 Valid After:	2020-09-09 20:23:02 +0000 UTC
# CA #1 Valid Until:	2020-09-10 20:23:12 +0000 UTC
```

As demonstated in an earlier demo, any process running in this container can access the agent and get the identity 'spiffe://example.org/ns/default/sa/default'

## Adding an OIDC service provider to our identity service

Now that our identity service has been configured in the gke cluster, we are now going to tweak its configuration and insert an OIDC service in the spire-server pod

```bash
cd ./etc/oidc-aws
kubectl apply -f server--configmap.yaml -f oidc-discovery-provider--configmap.yaml -f server--statefulset.yaml
# configmap/spire-server configured
# configmap/oidc-discovery-provider created
# statefulset.apps/spire-server configured

kubectl get pods -n spire -l app=spire-server -o jsonpath='{.items[*].spec.containers[*].name}{"\n"}'
# spire-server spire-oidc
```

As you can see, we have deployed in our cluster an OIDC service that will be exposed to AWS through an ingress gateway.

```bash
cd ./eetc/oidc-aws
kubectl apply -f server-oidc--service.yaml -f ingress.yaml
# service/spire-oidc created
# ingress.extensions/spire-ingress created 

kubectl get service -n spire spire-oidc
# NAME         TYPE           CLUSTER-IP    EXTERNAL-IP    PORT(S)         AGE
# spire-oidc   LoadBalancer   10.3.252.90   34.82.78.168   443:31824/TCP   55s
```

Now let's update our route53 hosted zone accordingly

```bash
dig oidc-discovery.paasteurizers.com +short
34.82.78.168
```

The above DNS entry will allow AWS to validate the JWT, identity of our client application.

```
kubectl get ingress -A
# NAMESPACE   NAME            HOSTS                              ADDRESS         PORTS     AGE
# spire       spire-ingress   oidc-discovery.paasteurizers.com   35.227.222.59   80, 443   6m33s

```

![openid_configuration](./.images/640/openid_configuration.png)

and check that the JWKS public key is available at the following URI

![openid_jwks_uri](./.images/640/openid_jwks_uri.png)

Now our identity service that is running in our GKE cluster can interface with a 3rd party service, such as AWS, using an OIDC provider.

## On the AWS side ...

Let's create a S3 object, which our client application running in GKE will try to access.
We must first create a private AWS S3 bucket. Our bucket is named '529733180916-paasteurizers'

![aws_create_bucket.png](./.images/640/aws_create_bucket.png)

The second step is to dump a file in the newly-created bucket. We have named that file 'test.txt'

![aws_ls_bucket.png](./.images/640/aws_ls_bucket.png)

or with the command line

```bash
# sudo pip3 install awscli
# aws configure

aws s3 ls 529733180916-paasteurizers
2020-09-09 16:55:14         79 test.txt
```

WE have now created the AWS resource that our pod running on GKE will try to access.
At this point, access is blocked because the bucket is a private bucket.
Going forward, we will still keep that bucket as private, but we allow AWS to validate our SPIFFE identities using an OpenID Connector (OIDC).

### Create an OpenID Provider in AWS 

Create an openid connect provider in AWS, and points its to our spire-openid service running in out GKE cluster.
The AWS IAM service will be able to connect with our identity provider thanks to the DNS entry created earlier.

![aws_openid_connect.png](./.images/640/aws_openid_connect.png)

Validate its configuration from the command line

```bash
aws iam list-open-id-connect-providers --output table --query "OpenIDConnectProviderList"
-------------------------------------------------------------------------------
|                         ListOpenIDConnectProviders                          |
+-----------------------------------------------------------------------------+
|                                     Arn                                     |
+-----------------------------------------------------------------------------+
|  arn:aws:iam::529733180916:oidc-provider/oidc-discovery.paasteurizers.com   |   <== MAKE SURE THERE IS NO TRAILING SLASH (i.e ...com/) !
+-----------------------------------------------------------------------------+

aws iam get-open-id-connect-provider --open-id-connect-provider-arn arn:aws:iam::529733180916:oidc-provider/oidc-discovery.paasteurizers.com --output table
-------------------------------------------------------------------
|                    GetOpenIDConnectProvider                     |
+---------------------------+-------------------------------------+
|        CreateDate         |                 Url                 |
+---------------------------+-------------------------------------+
|  2020-09-10T09:34:53.046Z |  oidc-discovery.paasteurizers.com   |    <== Entry point to the OIDC process running in our cluster
+---------------------------+-------------------------------------+
||                         ClientIDList                          ||
|+---------------------------------------------------------------+|
||  mys3                                                         ||   <== audience
|+---------------------------------------------------------------+|
||                        ThumbprintList                         ||
|+---------------------------------------------------------------+|
||  e6a3b45b062d509b3382282d196efe97d5956ccb                     ||   <== https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc_verify-thumbprint.html
|+---------------------------------------------------------------+|
```

Now we are about to attach a policy to the workload that connects through OIDC.
Here is the content of the IAM policy.

```bash
cd ./etc/iam
cat policy.json
# {
#   "Version": "2012-10-17",
#   "Statement": [
#     {
#       "Sid": "VisualEditor0",
#       "Effect": "Allow",
#       "Action": [
#         "s3:PutAccountPublicAccessBlock",
#         "s3:GetAccountPublicAccessBlock",
#         "s3:ListAllMyBuckets",
#         "s3:ListJobs",
#         "s3:CreateJob",
#         "s3:HeadBucket"
#       ],
#       "Resource": "*"
#     },
#     {
#       "Sid": "VisualEditor1",
#       "Effect": "Allow",                               <== Allow ...
#       "Action": "s3:*",                                ... any S3 operation
#       "Resource": [                                    ... on
#         "arn:aws:s3:::529733180916-paasteurizers",     ... the bucket or
#         "arn:aws:s3:::529733180916-paasteurizers/*",   ... its content
#         "arn:aws:s3:*:*:job/*"
#       ]
#     }
#   ]
# }
```

Now we create a managed IAM policy with the above policy-document.
We will name this policy 'oidc-federation-test-policy'.

```bash
aws iam create-policy --policy-name oidc-federation-test-policy --policy-document file://./policy.json
# {
#     "Policy": {
#         "PolicyName": "oidc-federation-test-policy",
#         "PolicyId": "ANPAXWVUO3X2NZMWMO3MF",
#         "Arn": "arn:aws:iam::529733180916:policy/oidc-federation-test-policy",
#         "Path": "/",
#         "DefaultVersionId": "v1",
#         "AttachmentCount": 0,
#         "PermissionsBoundaryUsageCount": 0,
#         "IsAttachable": true,
#         "CreateDate": "2020-09-10T09:03:55Z",
#         "UpdateDate": "2020-09-10T09:03:55Z"
#     }
# }
```

Create an AWS IAM Role for the Identity Provider

![aws_iam_create_role_1](./.images/900/aws_iam_create_role_1.png)

Attach the policy we created above (oidc-federation-test-policy)

![aws_iam_create_role_2_policy](./.images/900/aws_iam_create_role_2_policy.png)

and name the role oidc-federation-test-role

![aws_iam_create_role_4_review](./.images/900/aws_iam_create_role_4_review.png)

Check the configuration from the command line

```bash
aws iam get-role --role-name oidc-federation-test-role
# {
#     "Role": {
#         "Path": "/",
#         "RoleName": "oidc-federation-test-role",
#         "RoleId": "AROAXWVUO3X2NGRXJPV6H",
#         "Arn": "arn:aws:iam::529733180916:role/oidc-federation-test-role",
#         "CreateDate": "2020-09-10T09:14:58Z",
#         "AssumeRolePolicyDocument": {
#             "Version": "2012-10-17",
#             "Statement": [
#                 {
#                     "Effect": "Allow",
#                     "Principal": {
#                         "Federated": "arn:aws:iam::529733180916:oidc-provider/oidc-discovery.paasteurizers.com"
#                     },
#                     "Action": "sts:AssumeRoleWithWebIdentity",
#                     "Condition": {
#                         "StringEquals": {
#                             "oidc-discovery.paasteurizers.com:aud": "mys3"
#                         }
#                     }
#                 }
#             ]
#         },
#         "MaxSessionDuration": 3600,
#         "RoleLastUsed": {}
#     }
# }
```

Let's edit the trust relationship by clicking on the blue button and add our spiffe IDs in the condition statement

![aws_iam_edit_role_1_button](./.images/640/aws_iam_edit_role_1_button.png)

We can add an additional condition to the JWT having an audience equal to mys3.
Now the subject (sub) must be the spiffe ID of our client JWT as issued by our spire-server .

![aws_iam_edit_role_2_sub_spiffeid](./.images/900/aws_iam_edit_role_2_sub_spiffeid.png)

Let's check the configuration with the command line

```bash
aws iam get-role --role-name oidc-federation-test-role --query "Role.AssumeRolePolicyDocument.Statement[0].Condition"
# {
#     "StringEquals": {
#         "oidc-discovery.paasteurizers.com:aud": "mys3",
#         "oidc-discovery.paasteurizers.com:sub": "spiffe://example.org/ns/default/sa/default"
#     }
# }
```

## Final validation

Let's ascertain that the spiffe ID for our client application has already been created

```bash
kubectl exec -n spire spire-server-0 -c spire-server -it -- \
    /opt/spire/bin/spire-server entry show \
    -registrationUDSPath  /run/spire/sockets/registration.sock  \
    -spiffeID spiffe://example.org/ns/default/sa/default \
    -parentID spiffe://example.org/ns/spire/sa/spire-agent \
    -selector k8s:ns:default -selector k8s:sa:default
# Found 1 entry                                             <== Yes, the entry already exists
# Entry ID      : f8534819-3572-47c2-a2a2-3ef56532ea05
# SPIFFE ID     : spiffe://example.org/ns/default/sa/default
# Parent ID     : spiffe://example.org/ns/spire/sa/spire-agent
# TTL           : 3600
# Selector      : k8s:ns:default
# Selector      : k8s:sa:default
```

```bash
cd ./etc/k8s
kubectl apply -f client--deployment.yaml        <== We can always try to reinstall our application ...
# deployment.apps/client unchanged              ... but it was created earlier!

kubectl get pods
# NAME                      READY   STATUS    RESTARTS   AGE
# client-55885875c4-vwh9x   1/1     Running   0          2h
```

Let's exec into the client pod

```bash
kubectl exec -it $(kubectl get pods -o jsonpath={'.items[*]'.metadata.name}) -- /bin/sh
# /opt/spire #
```

Let's check the connection with the spire-server by getting a certificate

```bash
# THOSE COMMANDS ARE EXECUTED IN THE CLIENT CONTAINER
# kubectl exec -it $(kubectl get pods -o jsonpath={'.items[*]'.metadata.name}) -- /bin/sh

/opt/spire/bin/spire-agent api fetch x509 -socketPath /run/spire/sockets/agent.sock
# Received 1 svid after 11.711169ms
# SPIFFE ID:		spiffe://example.org/ns/default/sa/default
# SVID Valid After:	2020-09-10 04:41:46 +0000 UTC
# SVID Valid Until:	2020-09-10 05:41:56 +0000 UTC
# CA #1 Valid After:	2020-09-09 20:23:02 +0000 UTC
# CA #1 Valid Until:	2020-09-09 20:23:12 +0000 UTC
# CA #2 Valid After:	2020-09-09 23:09:31 +0000 UTC
# CA #2 Valid Until:	2020-09-10 23:09:41 +0000 UTC
```

... but for this connection we will need a JWT instead ... with the right audience (mys3)!

```bash
# THOSE COMMANDS ARE EXECUTED IN THE CLIENT CONTAINER
# kubectl exec -it $(kubectl get pods -o jsonpath={'.items[*]'.metadata.name}) -- /bin/sh

/opt/spire/bin/spire-agent api fetch jwt -audience mys3 -socketPath /run/spire/sockets/agent.sock
# token(spiffe://example.org/ns/default/sa/default):
# 	eyJhbGciOiJSUzI1NiIsImtpZCI6IlJYckd3aFIyeDJscUVBUWZPcFgxcXBiczE0cnd6dFlHIiwidHlwIjoiSldUIn0.eyJhdWQiOlsibXlzMyJdLCJleHAiOjE1OTk2Mjc2MTAsImlhdCI6MTU5OTYyNzMxMCwiaXNzIjoiaHR0cHM6Ly9vaWRjLWRpc2NvdmVyeS5wYWFzdGV1cml6ZXJzLmNvbSIsInN1YiI6InNwaWZmZTovL2V4YW1wbGUub3JnL25zL2RlZmF1bHQvc2EvZGVmYXVsdCJ9.ePF6wZ4GXSCI4TzD2B4gHfhPfkMTcgehc1IJXlvqpJyCPcOkY28MOe0GOwtnEAszJ_zlabddExd551UbK2Wmogc1YsR63A6JEfWeJo2v18lyjlaEDDzsHUD30EAUzVqGX0lJDxMXQHPODSZqT4iphZeBdCWco1NSdmgxjuitrh_qml0FH4_PF7SchjWfIwgqmlEcr0NSk4pl9aSjHH1CA2L1TGjO08ed2jfcF5-U41X5CQc0Bclkeyt7iSaXSny7VEixgCIpZOgC1WyeqiowXh23cfmFOJtXj4uMIdcDXLmwPgxup4FDnB-YLSLO5LRdQ9HOpponSd3iWBvcpe-Mmg
# bundle(spiffe://example.org):
# 	{
#     "keys": [
#         {
#             "use": "jwt-svid",
#             "kty": "RSA",
#             "kid": "jgYCaxHchIiscPga25PtQIOC22SSjFIs",
#             "n": "qj1bYQSF6N0H7s9kR8_L1cZQukTlpR6BN2xTTY9aIrS8bL6AgMhdhwHp07dWg6gl_t7fqiNyCpIBgZIkrGZY98WM7sZBDyE5hrsW_xvcN_3UMBfmVMHHakmmR17ANpi7fjzHcKzBc-rH3L36ySytkylYfC9ULnZrH0O159vHxhO_zhnpKnl33vsjKZvBo7b4BLXbJ3KDOTg7Z4Hf8hfpwywkGz0E2VB0NtsWfOk5-l9n3OidhYqtzQFCBJf4t1-pRAXnwGh_4VEafDtq_7o5ajIlEv6fhiL78KUxL1xS0unKP0cx60LnJENFJp__4FGgUxOE637hMYcN-qnIbOGspw",
#             "e": "AQAB"
#         },
#         {
#             "use": "jwt-svid",
#             "kty": "RSA",
#             "kid": "RXrGwhR2x2lqEAQfOpX1qpbs14rwztYG",
#             "n": "z7d-asRIHsdZfty_GziGGP2lWWVr1p68tQWsQD4B6TLTwDwlrY4pj6ops09Ops5Gk8vBXzJJZ7edZncG7KljVwYQFpLPK6py52NcDlyde2geAZI9kj1288oG6LHs8Actg0lamncRpJZyIAx_qrACVCXHSxme3QGYRkw_c1DWRteRGjeBoIpwnvnS64fzREuppkF2YzStJwWpWUGXC2jDuIBnZI4VDV0VpL0vrwi-ncxFqyWo4sJbgUS9A0O80MK4sKlc9QFNwKOhpgdvM8NTScdUFU5mRlQUc0SjJlxl8Ngo4cMIVW5fQCNVRNpU5issfX56IywbNVP95kmu2F0VUQ",
#             "e": "AQAB"
#         }
#     ]
# }

/opt/spire/bin/spire-agent api fetch jwt -audience mys3 -socketPath /run/spire/sockets/agent.sock | sed '2!d' | sed 's/[[:space:]]//g'
# eyJhbGciOiJSUzI1NiIsImtpZCI6IlJYckd3aFIyeDJscUVBUWZPcFgxcXBiczE0cnd6dFlHIiwidHlwIjoiSldUIn0.eyJhdWQiOlsibXlzMyJdLCJleHAiOjE1OTk2Mjc2MTAsImlhdCI6MTU5OTYyNzMxMCwiaXNzIjoiaHR0cHM6Ly9vaWRjLWRpc2NvdmVyeS5wYWFzdGV1cml6ZXJzLmNvbSIsInN1YiI6InNwaWZmZTovL2V4YW1wbGUub3JnL25zL2RlZmF1bHQvc2EvZGVmYXVsdCJ9.ePF6wZ4GXSCI4TzD2B4gHfhPfkMTcgehc1IJXlvqpJyCPcOkY28MOe0GOwtnEAszJ_zlabddExd551UbK2Wmogc1YsR63A6JEfWeJo2v18lyjlaEDDzsHUD30EAUzVqGX0lJDxMXQHPODSZqT4iphZeBdCWco1NSdmgxjuitrh_qml0FH4_PF7SchjWfIwgqmlEcr0NSk4pl9aSjHH1CA2L1TGjO08ed2jfcF5-U41X5CQc0Bclkeyt7iSaXSny7VEixgCIpZOgC1WyeqiowXh23cfmFOJtXj4uMIdcDXLmwPgxup4FDnB-YLSLO5LRdQ9HOpponSd3iWBvcpe-Mmg

```

If we decode this JWT, we see

![jwt_io_jwtspire](./.images/900/jwt_io_jwtspire.png)

Note the value of the audience (aud), subject (sub), and issuer (iss).

... and try to access the S3 object in our bucket using OIDC

```bash
# THOSE COMMANDS ARE EXECUTED IN THE CLIENT CONTAINER
# kubectl exec -it $(kubectl get pods -o jsonpath={'.items[*]'.metadata.name}) -- /bin/sh

/opt/spire/bin/spire-agent api fetch jwt -audience mys3 -socketPath /run/spire/sockets/agent.sock | sed '2!d' | sed 's/[[:space:]]//g' > jwt.txt
ls -al jwt.txt
# -rw-r--r--    1 root     root           636 Sep 10 05:17 jwt.txt

apk add --no-cache python py-pip                # <== Let's install the AWS CLI in the client application container
pip install awscli
aws --version
# aws-cli/1.18.134 Python/2.7.18 Linux/4.19.112+ botocore/1.17.57
```

and NOW let's try to access the S3 resource

```bash
# THOSE COMMANDS ARE EXECUTED IN THE CLIENT CONTAINER
# kubectl exec -it $(kubectl get pods -o jsonpath={'.items[*]'.metadata.name}) -- /bin/sh

export AWS_WEB_IDENTITY_TOKEN_FILE=./jwt.txt
export AWS_ROLE_ARN=arn:aws:iam::529733180916:role/oidc-federation-test-role
aws s3 cp s3://529733180916-paasteurizers/test.txt test.txt
download: s3://529733180916-paasteurizers/test.txt to ./test.txt
```

Hurray, we have succeeded at downloading the file. Just in case, let's check its content

```bash
# THOSE COMMANDS ARE EXECUTED IN THE CLIENT CONTAINER
# kubectl exec -it $(kubectl get pods -o jsonpath={'.items[*]'.metadata.name}) -- /bin/sh

cat test.txt
# Growth hack Team: PaaSteurizers
# 
# This file is stored on S3 in a private bucket
```

## Conclusion

In this iteration, we learned

1. How to deploy our identity service in kubernetes, including
  * how to install the gcloud command line
  * how to deploy a GKE cluster with a single command line
  * how to deploy our identity service using a stateful-set
  * how to deploy agents on each of our worker nodes using a daemon-set
  * how to deploy a client application and fetch an identity
  * how to extend our identity service on k8s with an OIDC identity provider

2. How to configure AWS to use our SPIFFE identities, including
  * how to store a file-object in a newly-created S3 bucket
  * how to create an IAM role/policy to access this S3 object
  * how to create an OIDC connector in IAM
  * how to connect our identity provider to the AWS OIDC connector
  
Finally we were able to have an client application pod running in GKE access a private resource on AWS using OIDC.
In other words, we were able to demonstrate that our identity service can work in heterogenous environments.
  
Enjoy! 
