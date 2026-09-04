{{/*
Name helpers. Components build fullnames from wazuh.fullname so one release
owns a consistent set of objects (manager-master/worker, indexer, dashboard).
*/}}

{{- define "wazuh.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "wazuh.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "wazuh.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "wazuh.manager.master.fullname" -}}
{{- printf "%s-manager-master" (include "wazuh.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "wazuh.manager.worker.fullname" -}}
{{- printf "%s-manager-worker" (include "wazuh.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "wazuh.indexer.fullname" -}}
{{- printf "%s-indexer" (include "wazuh.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "wazuh.dashboard.fullname" -}}
{{- printf "%s-dashboard" (include "wazuh.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "wazuh.agent.fullname" -}}
{{- printf "%s-agent" (include "wazuh.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Labels. wazuh.labels is the full recommended set. wazuh.selectorLabels stays
minimal because it feeds .spec.selector.matchLabels (immutable after create)
and must never include chart/app version.
*/}}

{{- define "wazuh.labels" -}}
helm.sh/chart: {{ include "wazuh.chart" . }}
{{ include "wazuh.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: wazuh
{{- end }}

{{- define "wazuh.selectorLabels" -}}
app.kubernetes.io/name: {{ include "wazuh.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* Per-component labels: include with (dict "context" $ "component" "indexer") */}}

{{- define "wazuh.component.labels" -}}
{{ include "wazuh.labels" .context }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{- define "wazuh.component.selectorLabels" -}}
{{ include "wazuh.selectorLabels" .context }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/*
Image ref. Pass component image config plus root context so global registry
and chart appVersion apply:
  {{- include "wazuh.image" (dict "context" $ "image" .Values.indexer.image) }}
*/}}

{{- define "wazuh.image" -}}
{{- $registry := .image.registry | default .context.Values.global.imageRegistry -}}
{{- $tag := .image.tag | default .context.Values.global.imageTag | default .context.Chart.AppVersion -}}
{{- if $registry -}}
{{- printf "%s/%s:%s" $registry .image.repository $tag -}}
{{- else -}}
{{- printf "%s:%s" .image.repository $tag -}}
{{- end -}}
{{- end }}

{{- define "wazuh.imagePullSecrets" -}}
{{- $secrets := concat .Values.global.imagePullSecrets .Values.imagePullSecrets | uniq -}}
{{- if $secrets }}
imagePullSecrets:
{{- range $secrets }}
  - name: {{ . }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Shared SA name. OpenShift needs per-component accounts (different SCCs), so
prefer wazuh.component.serviceAccountName for workloads.
*/}}
{{- define "wazuh.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "wazuh.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end }}

{{/* Shared object names referenced from multiple templates. */}}

{{- define "wazuh.credentialsSecretName" -}}
{{- .Values.credentials.existingSecret | default (printf "%s-credentials" (include "wazuh.fullname" .)) -}}
{{- end }}

{{- define "wazuh.indexerCertsSecretName" -}}
{{- if eq .Values.certs.mode "existing" -}}
{{- required "certs.existingIndexerSecret is required when certs.mode=existing" .Values.certs.existingIndexerSecret -}}
{{- else -}}
{{- printf "%s-indexer-certs" (include "wazuh.fullname" .) -}}
{{- end -}}
{{- end }}

{{- define "wazuh.dashboardCertsSecretName" -}}
{{- if eq .Values.certs.mode "existing" -}}
{{- required "certs.existingDashboardSecret is required when certs.mode=existing" .Values.certs.existingDashboardSecret -}}
{{- else -}}
{{- printf "%s-dashboard-certs" (include "wazuh.fullname" .) -}}
{{- end -}}
{{- end }}

{{- define "wazuh.managerClusterServiceName" -}}
{{- printf "%s-cluster" (include "wazuh.fullname" .) -}}
{{- end }}

{{- define "wazuh.managerServiceName" -}}
{{- printf "%s-manager" (include "wazuh.fullname" .) -}}
{{- end }}

{{- define "wazuh.managerEventsServiceName" -}}
{{- printf "%s-events" (include "wazuh.fullname" .) -}}
{{- end }}

{{- define "wazuh.indexerHeadlessServiceName" -}}
{{- printf "%s-indexer-nodes" (include "wazuh.fullname" .) -}}
{{- end }}

{{- define "wazuh.indexerServiceName" -}}
{{- printf "%s-indexer" (include "wazuh.fullname" .) -}}
{{- end }}

{{/*
Internal indexer URL. Uses the ClusterIP service on purpose. Upstream points
components at a LoadBalancer-typed indexer service and hairpins traffic through
a cloud LB.
*/}}
{{- define "wazuh.indexerUrl" -}}
{{- printf "https://%s.%s.svc:%d" (include "wazuh.indexerServiceName" .) .Release.Namespace (int .Values.indexer.service.port) -}}
{{- end }}

{{/*
Master pod FQDN for ossec.conf cluster peer and dashboard API. Namespace is
templated in. Hardcoding it is why moving out of the `wazuh` namespace silently
breaks cluster formation. See ../../../cluster-debugging.md
*/}}
{{- define "wazuh.managerMasterFqdn" -}}
{{- printf "%s-0.%s.%s" (include "wazuh.manager.master.fullname" .) (include "wazuh.managerClusterServiceName" .) .Release.Namespace -}}
{{- end }}

{{/*
true when workers exist. With zero workers the master keeps 1514 and the
events Service must select the master. Both master.conf and worker.conf share
the same <remote> block, so the master listens on 1514 either way.
*/}}
{{- define "wazuh.hasWorkers" -}}
{{- if gt (int .Values.manager.worker.replicas) 0 -}}true{{- end -}}
{{- end }}

{{- define "wazuh.storageClass" -}}
{{- $class := .class | default .context.Values.global.storageClass -}}
{{- if $class }}
storageClassName: {{ $class | quote }}
{{- end }}
{{- end }}

{{/*
Per-component ServiceAccount, required for OpenShift SCCs and cloud IAM role
bindings that attach per component.
*/}}
{{- define "wazuh.component.serviceAccountName" -}}
{{- if .context.Values.serviceAccount.create -}}
{{- printf "%s-%s" (include "wazuh.fullname" .context) .component | trunc 63 | trimSuffix "-" -}}
{{- else -}}
default
{{- end -}}
{{- end }}

{{/*
Credentials resolved once per render and cached on .Values so every template
agrees. Precedence: explicit values.yaml, then an existing Secret key (upgrades never
rotate), then a fresh random string. `lookup` is empty during `helm template` / `--dry-run`,
so dry runs show new passwords; a real install reuses cluster state.
*/}}
{{- define "wazuh.creds" -}}
{{- if not (hasKey .Values "_wazuhCreds") -}}
  {{- $existing := lookup "v1" "Secret" .Release.Namespace (include "wazuh.credentialsSecretName" .) -}}
  {{- $old := dict -}}
  {{- if and $existing $existing.data -}}
    {{- $old = $existing.data -}}
  {{- end -}}
  {{- $resolve := dict -}}
  {{- $pairs := list
      (dict "key" "indexer-password"   "val" .Values.credentials.indexer.password)
      (dict "key" "dashboard-password" "val" .Values.credentials.dashboard.password)
      (dict "key" "api-password"       "val" .Values.credentials.api.password)
      (dict "key" "authd.pass"         "val" .Values.credentials.authdPassword)
      (dict "key" "cluster-key"        "val" .Values.credentials.clusterKey)
  -}}
  {{- range $p := $pairs -}}
    {{- $v := $p.val -}}
    {{- if not $v -}}
      {{- if hasKey $old $p.key -}}
        {{- $v = b64dec (index $old $p.key) -}}
      {{- else if eq $p.key "cluster-key" -}}
        {{- /* cluster key length must be exactly 32 chars */ -}}
        {{- $v = randAlphaNum 32 -}}
      {{- else -}}
        {{- $v = randAlphaNum 24 -}}
      {{- end -}}
    {{- end -}}
    {{- $_ := set $resolve $p.key $v -}}
  {{- end -}}
  {{- $_ := set $resolve "indexer-username" .Values.credentials.indexer.username -}}
  {{- $_ := set $resolve "dashboard-username" .Values.credentials.dashboard.username -}}
  {{- $_ := set $resolve "api-username" .Values.credentials.api.username -}}
  {{- $_ := set .Values "_wazuhCreds" $resolve -}}
{{- end -}}
{{- end }}

{{/*
bcrypt for internal_users.yml. Sprig htpasswd returns "user:$2a$10$...", so strip
the username prefix.
*/}}
{{- define "wazuh.bcrypt" -}}
{{- htpasswd "u" . | trimPrefix "u:" -}}
{{- end }}

{{/*
Cert material, resolved once per render and cached like credentials. One CA
plus four leaves using the filenames Wazuh images expect: node, admin,
filebeat, dashboard.
*/}}
{{- define "wazuh.certs" -}}
{{- if not (hasKey .Values "_wazuhCerts") -}}
  {{- $existing := lookup "v1" "Secret" .Release.Namespace (printf "%s-indexer-certs" (include "wazuh.fullname" .)) -}}
  {{- $dashExisting := lookup "v1" "Secret" .Release.Namespace (printf "%s-dashboard-certs" (include "wazuh.fullname" .)) -}}
  {{- if and $existing $existing.data (hasKey $existing.data "node.pem") -}}
    {{- $out := dict -}}
    {{- range $k, $v := $existing.data -}}
      {{- $_ := set $out $k (b64dec $v) -}}
    {{- end -}}
    {{- if and $dashExisting $dashExisting.data (hasKey $dashExisting.data "cert.pem") -}}
      {{- $_ := set $out "dashboard-http.pem" (b64dec (index $dashExisting.data "cert.pem")) -}}
      {{- $_ := set $out "dashboard-http-key.pem" (b64dec (index $dashExisting.data "key.pem")) -}}
    {{- end -}}
    {{- $_ := set .Values "_wazuhCerts" $out -}}
  {{- else -}}
    {{- $ns := .Release.Namespace -}}
    {{- $indexerSvc := include "wazuh.indexerServiceName" . -}}
    {{- $indexerHeadless := include "wazuh.indexerHeadlessServiceName" . -}}
    {{- $clusterSvc := include "wazuh.managerClusterServiceName" . -}}
    {{- $dashSvc := include "wazuh.dashboard.fullname" . -}}
    {{- $names := list "indexer" $indexerSvc $indexerHeadless
        (printf "%s.%s" $indexerSvc $ns) (printf "%s.%s.svc" $indexerSvc $ns)
        (printf "%s.%s.svc.cluster.local" $indexerSvc $ns)
        (printf "*.%s.%s.svc.cluster.local" $indexerHeadless $ns)
        (printf "*.%s" $indexerHeadless)
        "localhost" -}}
    {{- range $i := until (int .Values.indexer.replicas) -}}
      {{- $pod := printf "%s-%d" (include "wazuh.indexer.fullname" $) $i -}}
      {{- $names = append $names $pod -}}
      {{- $names = append $names (printf "%s.%s" $pod $indexerHeadless) -}}
      {{- $names = append $names (printf "%s.%s.%s.svc.cluster.local" $pod $indexerHeadless $ns) -}}
    {{- end -}}
    {{- $names = concat $names .Values.certs.extraDnsNames -}}
    {{- $dashNames := list $dashSvc (printf "%s.%s" $dashSvc $ns) (printf "%s.%s.svc" $dashSvc $ns) (printf "%s.%s.svc.cluster.local" $dashSvc $ns) "localhost" -}}
    {{- range $h := .Values.dashboard.ingress.hosts -}}
      {{- $dashNames = append $dashNames $h.host -}}
    {{- end -}}
    {{- $dashNames = concat $dashNames .Values.certs.extraDnsNames -}}
    {{- $mgrNames := list (include "wazuh.managerServiceName" .) (include "wazuh.managerMasterFqdn" .) (printf "*.%s.%s.svc.cluster.local" $clusterSvc $ns) "localhost" -}}
    {{- $mgrNames = concat $mgrNames .Values.certs.extraDnsNames -}}
    {{- $ips := concat (list "127.0.0.1") .Values.certs.extraIpAddresses -}}
    {{- $days := int .Values.certs.duration -}}
    {{- $ca := genCA "wazuh-root-ca" (int .Values.certs.caDuration) -}}
    {{- $node := genSignedCert "indexer" $ips $names $days $ca -}}
    {{- $admin := genSignedCert "admin" nil nil $days $ca -}}
    {{- $filebeat := genSignedCert "filebeat" $ips $mgrNames $days $ca -}}
    {{- $dashboard := genSignedCert "dashboard" $ips $dashNames $days $ca -}}
    {{- $out := dict
        "root-ca.pem" $ca.Cert
        "node.pem" $node.Cert "node-key.pem" $node.Key
        "admin.pem" $admin.Cert "admin-key.pem" $admin.Key
        "filebeat.pem" $filebeat.Cert "filebeat-key.pem" $filebeat.Key
        "dashboard.pem" $dashboard.Cert "dashboard-key.pem" $dashboard.Key
        "dashboard-http.pem" $dashboard.Cert "dashboard-http-key.pem" $dashboard.Key -}}
    {{- $_ := set .Values "_wazuhCerts" $out -}}
  {{- end -}}
{{- end -}}
{{- end }}

{{/*
DNs the indexer trusts. These must match the certificate subjects. Chart-generated certs
are CN-only; wazuh-certs-tool.sh uses the full upstream subject, so set
certs.subject.* with certs.mode=existing.
*/}}
{{- define "wazuh.adminDn" -}}
{{- .Values.certs.subject.adminDn | default "CN=admin" -}}
{{- end }}

{{- define "wazuh.nodesDn" -}}
{{- .Values.certs.subject.nodesDn | default "CN=indexer" -}}
{{- end }}

{{/*
Pod anti-affinity. soft = prefer spread; hard = refuse co-schedule (Pending when
nodes < replicas).
*/}}
{{- define "wazuh.antiAffinity" -}}
{{- $mode := .mode -}}
{{- if eq $mode "hard" }}
podAntiAffinity:
  requiredDuringSchedulingIgnoredDuringExecution:
    - topologyKey: kubernetes.io/hostname
      labelSelector:
        matchLabels:
          {{- include "wazuh.component.selectorLabels" (dict "context" .context "component" .component) | nindent 10 }}
{{- else if eq $mode "soft" }}
podAntiAffinity:
  preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      podAffinityTerm:
        topologyKey: kubernetes.io/hostname
        labelSelector:
          matchLabels:
            {{- include "wazuh.component.selectorLabels" (dict "context" .context "component" .component) | nindent 12 }}
{{- end }}
{{- end }}

{{/*
Cert volumes/mounts. helm/existing secrets use upstream Wazuh filenames;
cert-manager writes tls.crt / tls.key / ca.crt. Branching stays here so
workloads stay readable. defaultMode 0600 matches upstream; fsGroup lets the
non-root user read the volume.
*/}}

{{- define "wazuh.indexerCertVolumes" -}}
{{- if eq .Values.certs.mode "helm" }}
- name: indexer-certs-src
  secret:
    secretName: {{ include "wazuh.indexerCertsSecretName" . }}
    defaultMode: 0600
- name: indexer-certs
  emptyDir: {}
{{- else if eq .Values.certs.mode "cert-manager" }}
- name: indexer-node-certs
  secret:
    secretName: {{ include "wazuh.fullname" . }}-indexer-node-tls
    defaultMode: 0600
- name: indexer-admin-certs
  secret:
    secretName: {{ include "wazuh.fullname" . }}-indexer-admin-tls
    defaultMode: 0600
{{- else }}
- name: indexer-certs
  secret:
    secretName: {{ include "wazuh.indexerCertsSecretName" . }}
    defaultMode: 0600
{{- end }}
{{- end }}

{{- define "wazuh.indexerCertMounts" -}}
{{- $base := "/usr/share/wazuh-indexer/config/certs" }}
{{- if eq .Values.certs.mode "helm" }}
{{- /* Directory is the emptyDir filled by the PKCS#8 init container. */}}
- name: indexer-certs
  mountPath: {{ $base }}
  readOnly: true
{{- else if eq .Values.certs.mode "cert-manager" }}
- name: indexer-node-certs
  mountPath: {{ $base }}/node.pem
  subPath: tls.crt
  readOnly: true
- name: indexer-node-certs
  mountPath: {{ $base }}/node-key.pem
  subPath: tls.key
  readOnly: true
- name: indexer-node-certs
  mountPath: {{ $base }}/root-ca.pem
  subPath: ca.crt
  readOnly: true
- name: indexer-admin-certs
  mountPath: {{ $base }}/admin.pem
  subPath: tls.crt
  readOnly: true
- name: indexer-admin-certs
  mountPath: {{ $base }}/admin-key.pem
  subPath: tls.key
  readOnly: true
{{- else }}
{{- range $f := list "node.pem" "node-key.pem" "root-ca.pem" "admin.pem" "admin-key.pem" }}
- name: indexer-certs
  mountPath: {{ $base }}/{{ $f }}
  subPath: {{ $f }}
  readOnly: true
{{- end }}
{{- end }}
{{- end }}

{{/*
Init container: rewrite indexer keys to PKCS#8.

Helm genSignedCert (sprig) only emits PKCS#1 ("BEGIN RSA PRIVATE KEY").
OpenSearch security loads pemkey_filepath via Netty SslContext.toPrivateKey,
which expects PKCS8EncodedKeySpec and fails on PKCS#1 with
"Neither RSA, DSA nor EC worked". Wazuh images have no openssl, so a separate
image is used solely for that binary.

Only certs.mode=helm needs this. wazuh-certs-tool.sh and cert-manager
(privateKey.encoding: PKCS8) already produce PKCS#8 and mount secrets
directly. Conversion is still gated by a header check.
*/}}
{{- define "wazuh.pkcs8InitContainer" -}}
- name: normalise-key-format
  image: {{ include "wazuh.image" (dict "context" . "image" .Values.certs.pkcs8InitImage) }}
  imagePullPolicy: {{ .Values.certs.pkcs8InitImage.pullPolicy }}
  command:
    - /bin/bash
    - -c
    - |
      set -eu
      cp -r /certs-src/. /certs/
      for key in node-key.pem admin-key.pem; do
        if head -n 1 "/certs/$key" | grep -q "BEGIN RSA PRIVATE KEY"; then
          openssl pkcs8 -topk8 -nocrypt -in "/certs-src/$key" -out "/certs/$key"
        fi
        chmod 0400 "/certs/$key"
      done
  securityContext:
    runAsUser: 1000
    runAsGroup: 1000
  resources:
    requests:
      cpu: 50m
      memory: 64Mi
    limits:
      cpu: 200m
      memory: 128Mi
  volumeMounts:
    - name: indexer-certs-src
      mountPath: /certs-src
      readOnly: true
    - name: indexer-certs
      mountPath: /certs
{{- end }}

{{- define "wazuh.managerCertVolumes" -}}
{{- if eq .Values.certs.mode "cert-manager" }}
- name: filebeat-certs
  secret:
    secretName: {{ include "wazuh.fullname" . }}-filebeat-tls
    defaultMode: 0600
{{- else }}
- name: filebeat-certs
  secret:
    secretName: {{ include "wazuh.indexerCertsSecretName" . }}
    defaultMode: 0600
{{- end }}
{{- end }}

{{- define "wazuh.managerCertMounts" -}}
{{- if eq .Values.certs.mode "cert-manager" }}
- name: filebeat-certs
  mountPath: /etc/ssl/root-ca.pem
  subPath: ca.crt
  readOnly: true
- name: filebeat-certs
  mountPath: /etc/ssl/filebeat.pem
  subPath: tls.crt
  readOnly: true
- name: filebeat-certs
  mountPath: /etc/ssl/filebeat.key
  subPath: tls.key
  readOnly: true
{{- else }}
- name: filebeat-certs
  mountPath: /etc/ssl/root-ca.pem
  subPath: root-ca.pem
  readOnly: true
- name: filebeat-certs
  mountPath: /etc/ssl/filebeat.pem
  subPath: filebeat.pem
  readOnly: true
- name: filebeat-certs
  mountPath: /etc/ssl/filebeat.key
  subPath: filebeat-key.pem
  readOnly: true
{{- end }}
{{- end }}

{{- define "wazuh.dashboardCertVolumes" -}}
{{- if eq .Values.certs.mode "cert-manager" }}
- name: dashboard-certs
  secret:
    secretName: {{ include "wazuh.fullname" . }}-dashboard-tls
    defaultMode: 0600
{{- else }}
- name: dashboard-certs
  secret:
    secretName: {{ include "wazuh.dashboardCertsSecretName" . }}
    defaultMode: 0600
{{- end }}
{{- end }}

{{- define "wazuh.dashboardCertMounts" -}}
{{- $base := "/usr/share/wazuh-dashboard/certs" }}
{{- if eq .Values.certs.mode "cert-manager" }}
- name: dashboard-certs
  mountPath: {{ $base }}/cert.pem
  subPath: tls.crt
  readOnly: true
- name: dashboard-certs
  mountPath: {{ $base }}/key.pem
  subPath: tls.key
  readOnly: true
- name: dashboard-certs
  mountPath: {{ $base }}/root-ca.pem
  subPath: ca.crt
  readOnly: true
{{- else }}
{{- range $f := list "cert.pem" "key.pem" "root-ca.pem" }}
- name: dashboard-certs
  mountPath: {{ $base }}/{{ $f }}
  subPath: {{ $f }}
  readOnly: true
{{- end }}
{{- end }}
{{- end }}

{{/*
Env shared by both manager StatefulSets (indexer, filebeat TLS, cluster key).
API credentials stay master-only.
*/}}
{{- define "wazuh.managerEnv" -}}
- name: INDEXER_URL
  value: {{ include "wazuh.indexerUrl" . | quote }}
- name: INDEXER_USERNAME
  valueFrom:
    secretKeyRef:
      name: {{ include "wazuh.credentialsSecretName" . }}
      key: indexer-username
- name: INDEXER_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "wazuh.credentialsSecretName" . }}
      key: indexer-password
- name: FILEBEAT_SSL_VERIFICATION_MODE
  value: "full"
- name: SSL_CERTIFICATE_AUTHORITIES
  value: /etc/ssl/root-ca.pem
- name: SSL_CERTIFICATE
  value: /etc/ssl/filebeat.pem
- name: SSL_KEY
  value: /etc/ssl/filebeat.key
- name: WAZUH_CLUSTER_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "wazuh.credentialsSecretName" . }}
      key: cluster-key
{{- end }}

{{/*
Manager PVC subPath layout, matching the paths listed in the image's
permanent_data.env.
Anything else is regenerated from the image on each start.
*/}}
{{- define "wazuh.managerDataMounts" -}}
{{- $claim := .claim }}
{{- range $path := list "api/configuration" "etc" "logs" "queue" "var/multigroups" "integrations" "active-response/bin" "agentless" "wodles" }}
- name: {{ $claim }}
  mountPath: /var/ossec/{{ $path }}
  subPath: wazuh/var/ossec/{{ $path }}
{{- end }}
- name: {{ $claim }}
  mountPath: /etc/filebeat
  subPath: filebeat/etc/filebeat
- name: {{ $claim }}
  mountPath: /var/lib/filebeat
  subPath: filebeat/var/lib/filebeat
{{- end }}
