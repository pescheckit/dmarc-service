{{- define "dmarc-service.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "dmarc-service.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "dmarc-service.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "dmarc-service.labels" -}}
app.kubernetes.io/name: {{ include "dmarc-service.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "dmarc-service.selectorLabels" -}}
app.kubernetes.io/name: {{ include "dmarc-service.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "dmarc-service.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}

{{- define "dmarc-service.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "dmarc-service.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Whether the chart renders its own Secret */}}
{{- define "dmarc-service.needsOwnSecret" -}}
{{- if or .Values.database.url (and .Values.backup.s3Url (not .Values.backup.existingSecret)) (and .Values.metrics.token (not .Values.metrics.existingSecret)) (and (not .Values.auth.existingSecret) (or .Values.auth.apiToken .Values.auth.ingestToken .Values.auth.sessionSecret)) -}}true{{- end -}}
{{- end -}}

{{/* Metrics environment, shared by every process that serves them.

Enabling metrics without a token stops the install rather than publishing
the tenant list; allowUnauthenticated is the deliberate way past it. */}}
{{- define "dmarc-service.metricsEnv" -}}
{{- if .Values.metrics.enabled }}
{{- if and (not .Values.metrics.token) (not .Values.metrics.existingSecret) (not .Values.metrics.allowUnauthenticated) }}
{{- fail "metrics.enabled needs metrics.token or metrics.existingSecret. These metrics name your tenants and domains and show which of them have no working DMARC record. Set metrics.allowUnauthenticated=true only if the port is unreachable from anywhere untrusted." }}
{{- end }}
- name: METRICS_ENABLED
  value: "true"
- name: METRICS_PORT
  value: {{ .Values.metrics.port | quote }}
- name: METRICS_LABELS
  value: {{ .Values.metrics.labels | quote }}
- name: METRICS_DNS_INTERVAL
  value: {{ .Values.metrics.dnsInterval | quote }}
{{- if or .Values.metrics.token .Values.metrics.existingSecret }}
- name: METRICS_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ .Values.metrics.existingSecret | default (include "dmarc-service.fullname" .) }}
      key: {{ .Values.metrics.secretKey }}
{{- else }}
- name: METRICS_ALLOW_UNAUTHENTICATED
  value: "true"
{{- end }}
{{- end }}
{{- end -}}

{{/* Container port for the metrics listener */}}
{{- define "dmarc-service.metricsPort" -}}
{{- if .Values.metrics.enabled }}
- name: metrics
  containerPort: {{ .Values.metrics.port }}
{{- end }}
{{- end -}}

{{/* Environment shared by web, smtp (direct) and migrate */}}
{{- define "dmarc-service.coreEnv" -}}
- name: REPORT_HOST
  value: {{ .Values.reportHost | quote }}
- name: EXTERNAL_URL
  value: {{ .Values.externalUrl | quote }}
- name: TENANCY_MODE
  value: {{ .Values.tenancy.mode | quote }}
- name: CONTROL_PLANE_ENABLED
  value: {{ .Values.controlPlane.enabled | quote }}
{{- if .Values.database.existingSecret }}
- name: DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.database.existingSecret }}
      key: {{ .Values.database.secretKey }}
{{- else if .Values.database.url }}
- name: DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "dmarc-service.fullname" . }}
      key: DATABASE_URL
{{- else }}
- name: DATABASE_URL
  value: "sqlite:////data/dmarc.db"
{{- end }}
{{- if .Values.auth.existingSecret }}
- name: API_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ .Values.auth.existingSecret }}
      key: API_TOKEN
      optional: true
- name: INGEST_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ .Values.auth.existingSecret }}
      key: INGEST_TOKEN
      optional: true
- name: SESSION_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ .Values.auth.existingSecret }}
      key: SESSION_SECRET
      optional: true
{{- else }}
{{- if .Values.auth.apiToken }}
- name: API_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ include "dmarc-service.fullname" . }}
      key: API_TOKEN
{{- end }}
{{- if .Values.auth.ingestToken }}
- name: INGEST_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ include "dmarc-service.fullname" . }}
      key: INGEST_TOKEN
{{- end }}
{{- if .Values.auth.sessionSecret }}
- name: SESSION_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ include "dmarc-service.fullname" . }}
      key: SESSION_SECRET
{{- end }}
{{- end }}
{{- end -}}

{{/* Volume + mount for the SQLite fallback */}}
{{- define "dmarc-service.dataVolume" -}}
{{- if and (not .Values.database.existingSecret) (not .Values.database.url) .Values.persistence.enabled }}
- name: data
  persistentVolumeClaim:
    claimName: {{ include "dmarc-service.fullname" . }}-data
{{- end }}
{{- end -}}

{{- define "dmarc-service.dataVolumeMount" -}}
{{- if and (not .Values.database.existingSecret) (not .Values.database.url) .Values.persistence.enabled }}
- name: data
  mountPath: /data
{{- end }}
{{- end -}}
