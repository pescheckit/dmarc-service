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
{{- if or .Values.database.url (and (not .Values.auth.existingSecret) (or .Values.auth.apiToken .Values.auth.ingestToken)) -}}true{{- end -}}
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
