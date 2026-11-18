{{/*
Common labels.
*/}}
{{- define "sonushield.labels" -}}
app.kubernetes.io/name: {{ include "sonushield.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "sonushield.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "sonushield.fullname" -}}
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

{{- define "sonushield.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sonushield.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
The config source in use: "secret", "configmap", "inline", or "".
Fails the render when more than one source is set.
*/}}
{{- define "sonushield.configSource" -}}
{{- $n := 0 }}
{{- if .Values.existingSecret }}{{ $n = add $n 1 }}{{ end }}
{{- if .Values.existingConfigMap }}{{ $n = add $n 1 }}{{ end }}
{{- if .Values.config }}{{ $n = add $n 1 }}{{ end }}
{{- if gt $n 1 }}{{ fail "Set exactly one config source: config, existingConfigMap, or existingSecret." }}{{ end }}
{{- if .Values.existingSecret }}secret
{{- else if .Values.existingConfigMap }}configmap
{{- else if .Values.config }}inline
{{- else }}{{ "" }}
{{- end }}
{{- end }}

{{/*
The pinned image reference. The tag is required: an empty tag
fails the render rather than floating to :latest.
*/}}
{{- define "sonushield.image" -}}
{{- printf "%s:%s" .Values.image.repository (required "image.tag must be set to a pinned release tag (see values.yaml)." .Values.image.tag) }}
{{- end }}
