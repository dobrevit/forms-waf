{{/*
Expand the name of the chart.
*/}}
{{- define "forms-waf.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "forms-waf.fullname" -}}
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

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "forms-waf.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "forms-waf.labels" -}}
helm.sh/chart: {{ include "forms-waf.chart" . }}
{{ include "forms-waf.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "forms-waf.selectorLabels" -}}
app.kubernetes.io/name: {{ include "forms-waf.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
OpenResty labels
*/}}
{{- define "forms-waf.openresty.labels" -}}
{{ include "forms-waf.labels" . }}
app.kubernetes.io/component: openresty
{{- end }}

{{- define "forms-waf.openresty.selectorLabels" -}}
{{ include "forms-waf.selectorLabels" . }}
app.kubernetes.io/component: openresty
{{- end }}

{{/*
HAProxy labels
*/}}
{{- define "forms-waf.haproxy.labels" -}}
{{ include "forms-waf.labels" . }}
app.kubernetes.io/component: haproxy
{{- end }}

{{- define "forms-waf.haproxy.selectorLabels" -}}
{{ include "forms-waf.selectorLabels" . }}
app.kubernetes.io/component: haproxy
{{- end }}

{{/*
Create the name of the service account for OpenResty
*/}}
{{- define "forms-waf.openresty.serviceAccountName" -}}
{{- if .Values.openresty.serviceAccount.create }}
{{- default (printf "%s-openresty" (include "forms-waf.fullname" .)) .Values.openresty.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.openresty.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the service account for HAProxy
*/}}
{{- define "forms-waf.haproxy.serviceAccountName" -}}
{{- if .Values.haproxy.serviceAccount.create }}
{{- default (printf "%s-haproxy" (include "forms-waf.fullname" .)) .Values.haproxy.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.haproxy.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Redis host (FQDN for reliable DNS resolution)
*/}}
{{- define "forms-waf.redis.host" -}}
{{- if .Values.redis.enabled }}
{{- printf "%s-redis-master.%s.svc.cluster.local" .Release.Name .Release.Namespace }}
{{- else }}
{{- .Values.externalRedis.host }}
{{- end }}
{{- end }}

{{/*
Redis port
*/}}
{{- define "forms-waf.redis.port" -}}
{{- if .Values.redis.enabled }}
{{- 6379 }}
{{- else }}
{{- .Values.externalRedis.port | default 6379 }}
{{- end }}
{{- end }}

{{/*
HAProxy headless service name
*/}}
{{- define "forms-waf.haproxy.headlessServiceName" -}}
{{- printf "%s-haproxy-headless" (include "forms-waf.fullname" .) }}
{{- end }}

{{/*
Backend service name
*/}}
{{- define "forms-waf.backend.serviceName" -}}
{{- if .Values.backend.externalService.enabled }}
{{- .Values.backend.externalService.host }}
{{- else }}
{{- printf "%s-backend" (include "forms-waf.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Backend service port
*/}}
{{- define "forms-waf.backend.servicePort" -}}
{{- if .Values.backend.externalService.enabled }}
{{- .Values.backend.externalService.port }}
{{- else }}
{{- .Values.backend.mock.service.port | default 8080 }}
{{- end }}
{{- end }}

{{/*
Admin UI labels
*/}}
{{- define "forms-waf.adminUI.labels" -}}
{{ include "forms-waf.labels" . }}
app.kubernetes.io/component: admin-ui
{{- end }}

{{- define "forms-waf.adminUI.selectorLabels" -}}
{{ include "forms-waf.selectorLabels" . }}
app.kubernetes.io/component: admin-ui
{{- end }}

{{/*
Create the name of the service account for Admin UI
*/}}
{{- define "forms-waf.adminUI.serviceAccountName" -}}
{{- if .Values.adminUI.serviceAccount }}
{{- if .Values.adminUI.serviceAccount.create }}
{{- default (printf "%s-admin-ui" (include "forms-waf.fullname" .)) .Values.adminUI.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.adminUI.serviceAccount.name }}
{{- end }}
{{- else }}
{{- "default" }}
{{- end }}
{{- end }}

{{/*
Generic service account name (fallback to default)
*/}}
{{- define "forms-waf.serviceAccountName" -}}
{{- "default" }}
{{- end }}

{{/*
Image pull secrets
*/}}
{{- define "forms-waf.imagePullSecrets" -}}
{{- if .Values.global.imagePullSecrets }}
imagePullSecrets:
{{- range .Values.global.imagePullSecrets }}
  - name: {{ . }}
{{- end }}
{{- end }}
{{- end }}
