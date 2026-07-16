apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-shim
  namespace: ${TENANT}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: auth-shim
  template:
    metadata:
      labels:
        app: auth-shim
    spec:
      containers:
        - name: auth-shim
          image: ai-assistant-auth-shim:latest
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: 8081
          env:
            - name: SHIM_JWT_ISSUER
              value: ${JWT_ISSUER}
            - name: SHIM_BACKEND_AUDIENCE
              value: wazuh-ai-backend.lab
            - name: SHIM_INDEXER_AUDIENCE
              value: wazuh-indexer.lab
            - name: SHIM_TTL_SECONDS
              value: "600"
            - name: SHIM_REQUIRED_ROLE
              value: wazuh_ai_analyst
            - name: SHIM_ENVS_FILE
              value: /config/environments.yaml
            - name: SHIM_INDEXER_VERIFY_SSL
              value: "false"
          volumeMounts:
            - name: keys
              mountPath: /keys
              readOnly: true
            - name: envs
              mountPath: /config
              readOnly: true
      volumes:
        - name: keys
          secret:
            secretName: jwt-keys
            items:
              - key: jwt-private.pem
                path: jwt-private.pem
        - name: envs
          configMap:
            name: auth-shim-envs
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: auth-shim-envs
  namespace: ${TENANT}
data:
  environments.yaml: |
    - env_id: ${TENANT}
      indexer_url: https://${HOST_GW}:9200
      indexer_ca_path: ""
---
apiVersion: v1
kind: Service
metadata:
  name: auth-shim
  namespace: ${TENANT}
spec:
  type: NodePort
  selector:
    app: auth-shim
  ports:
    - port: 8081
      targetPort: 8081
      nodePort: ${SHIM_NODEPORT}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tool-service
  namespace: ${TENANT}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: tool-service
  template:
    metadata:
      labels:
        app: tool-service
    spec:
      containers:
        - name: tool-service
          image: ai-assistant-tool-service:latest
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: 8080
          env:
            - name: WAI_TENANT
              value: ${TENANT}
            - name: WAI_JWT_ISSUER
              value: ${JWT_ISSUER}
            - name: WAI_JWT_AUDIENCE
              value: wazuh-ai-backend.lab
            - name: WAI_INDEXER_URL
              value: https://${HOST_GW}:9200
            - name: WAI_INDEXER_VERIFY_SSL
              value: "false"
            - name: WAI_LLM_PROVIDER
              value: ${WAI_LLM_PROVIDER}
            - name: WAI_LLM_BASE_URL
              value: http://${HOST_GW}:11434/v1
            - name: WAI_MODEL_ROUTER
              value: ${WAI_MODEL_ROUTER}
            - name: WAI_MODEL_ANALYSIS
              value: ${WAI_MODEL_ANALYSIS}
            - name: WAI_LANE0_ENABLED
              value: "${WAI_LANE0_ENABLED}"
            - name: WAI_LANE0_THRESHOLD
              value: "0.80"
            - name: WAI_EMBED_BASE_URL
              value: http://${HOST_GW}:11434/v1
            - name: WAI_EMBED_MODEL
              value: ${WAI_EMBED_MODEL}
            - name: WAI_EVIDENCE_CACHE_TTL
              value: "${WAI_EVIDENCE_CACHE_TTL}"
            - name: WAI_LANE2_ENABLED
              value: "true"
            - name: WAI_MAX_OUTPUT_TOKENS
              value: "2048"
            - name: WAI_STREAMING
              value: "true"
          volumeMounts:
            - name: pubkey
              mountPath: /keys/jwt-public.pem
              subPath: jwt-public.pem
              readOnly: true
      volumes:
        - name: pubkey
          secret:
            secretName: jwt-keys
            items:
              - key: jwt-public.pem
                path: jwt-public.pem
---
apiVersion: v1
kind: Service
metadata:
  name: tool-service
  namespace: ${TENANT}
spec:
  type: NodePort
  selector:
    app: tool-service
  ports:
    - port: 8080
      targetPort: 8080
      nodePort: ${SVC_NODEPORT}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: tenant-isolation
  namespace: ${TENANT}
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
  ingress:
    # Pod-to-pod inside the tenant namespace.
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ${TENANT}
    # NodePort from the host (non-pod CIDR); blocks cross-namespace pod traffic.
    - from:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 10.244.0.0/16
      ports:
        - protocol: TCP
          port: 8080
        - protocol: TCP
          port: 8081
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ${TENANT}
    - to:
        - ipBlock:
            cidr: ${HOST_GW}/32
      ports:
        - protocol: TCP
          port: 9200
        - protocol: TCP
          port: 11434
