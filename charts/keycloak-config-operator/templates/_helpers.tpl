{{/*
Expand the name of the chart.
*/}}
{{- define "keycloak-config-operator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "keycloak-config-operator.fullname" -}}
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
{{- define "keycloak-config-operator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "keycloak-config-operator.labels" -}}
helm.sh/chart: {{ include "keycloak-config-operator.chart" . }}
{{ include "keycloak-config-operator.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: clouddicted-keycloak-config-operator
{{- end }}

{{/*
Selector labels
*/}}
{{- define "keycloak-config-operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "keycloak-config-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "keycloak-config-operator.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "keycloak-config-operator.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Rules for namespace-scoped objects managed by the operator.
*/}}
{{- define "keycloak-config-operator.namespacedRules" -}}
- apiGroups:
    - ""
  resources:
    - secrets
  verbs:
    - get
    - create
    - patch
- apiGroups:
    - ""
  resources:
    - events
  verbs:
    - create
    - patch
- apiGroups:
    - keycloak.clouddicted.com
  resources:
    - keycloaktargets
    - keycloakrealms
    - keycloakclients
    - keycloakroles
    - keycloakclientscopes
    - keycloakprotocolmappers
  verbs:
    - get
    - list
    - watch
    - patch
    - update
- apiGroups:
    - keycloak.clouddicted.com
  resources:
    - keycloaktargets/status
    - keycloakrealms/status
    - keycloakclients/status
    - keycloakroles/status
    - keycloakclientscopes/status
    - keycloakprotocolmappers/status
  verbs:
    - get
    - patch
    - update
- apiGroups:
    - keycloak.clouddicted.com
  resources:
    - keycloaktargets/finalizers
    - keycloakrealms/finalizers
    - keycloakclients/finalizers
    - keycloakroles/finalizers
    - keycloakclientscopes/finalizers
    - keycloakprotocolmappers/finalizers
  verbs:
    - patch
    - update
{{- end }}
