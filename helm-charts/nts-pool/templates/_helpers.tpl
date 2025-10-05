{{/*
Expand the name of the chart.
*/}}
{{- define "nts-pool.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "nts-pool.fullname" -}}
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
{{- define "nts-pool.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "nts-pool.labels" -}}
helm.sh/chart: {{ include "nts-pool.chart" . }}
{{ include "nts-pool.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "nts-pool.selectorLabels" -}}
app.kubernetes.io/name: {{ include "nts-pool.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "nts-pool.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "nts-pool.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "nts-pool.management-env" -}}
- name: NTSPOOL_CONFIG_UPDATER_SECRET
  valueFrom:
    secretKeyRef:
      {{- toYaml .Values.management.configUpdaterSecretRef | nindent 6 }}
- name: NTSPOOL_DATABASE_URL
  valueFrom:
    secretKeyRef:
      {{- toYaml .Values.management.databaseUrlSecretRef | nindent 6 }}
- name: DATABASE_URL
  valueFrom:
    secretKeyRef:
      {{- toYaml .Values.management.databaseUrlSecretRef | nindent 6 }}
- name: NTSPOOL_JWT_SECRET
  valueFrom:
    secretKeyRef:
      {{- toYaml .Values.management.jwtKeySecretRef | nindent 6 }}
- name: NTSPOOL_SMTP_URL
  valueFrom:
    secretKeyRef:
      {{- toYaml .Values.management.smtpUrlSecretRef | nindent 6 }}
- name: NTSPOOL_COOKIE_SECRET
  valueFrom:
    secretKeyRef:
      {{- toYaml .Values.management.cookieSecretRef | nindent 6 }}
- name: NTSPOOL_BASE_SHARED_SECRET
  valueFrom:
    secretKeyRef:
      {{- toYaml .Values.management.baseSharedSecretRef | nindent 6 }}
- name: NTSPOOL_BASE_SECRET_INDEX
  value: "0"
- name: NTSPOOL_MAIL_FROM_ADDRESS
  value: "{{ .Values.management.mailFromAddress }}"
- name: NTSPOOL_BASE_URL
  value: "{{ .Values.management.baseUrl }}"
- name: NTSPOOL_POOLKE_NAME
  value: "{{ .Values.ke.domainName }}"
- name: NTSPOOL_MONITOR_RESULT_BATCHSIZE
  value: "{{ .Values.monitor.resultBatchsize }}"
- name: NTSPOOL_MONITOR_RESULT_BATCHTIME
  value: "{{ .Values.monitor.resultBatchtime }}"
- name: NTSPOOL_MONITOR_UPDATE_INTERVAL
  value: "{{ .Values.monitor.updateInterval }}"
- name: NTSPOOL_MONITOR_PROBE_INTERVAL
  value: "{{ .Values.monitor.probeInterval }}"
- name: NTSPOOL_MONITOR_NTS_TIMEOUT
  value: "{{ .Values.monitor.ntsTimeout }}"
- name: NTSPOOL_MONITOR_NTP_TIMEOUT
  value: "{{ .Values.monitor.ntpTimeout }}"
- name: NTSPOOL_GEOLOCATION_DB
  value: "/opt/geodb/geodb.mmdb"
- name: RUST_BACKTRACE
  value: "1"
{{- end }}
