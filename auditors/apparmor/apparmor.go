package apparmor

import (
	"fmt"
	"strings"

	"github.com/elliotxx/kubeaudit"
	"github.com/elliotxx/kubeaudit/pkg/fix"
	"github.com/elliotxx/kubeaudit/pkg/k8s"
	"github.com/elliotxx/kubeaudit/pkg/override"
)

const Name = "apparmor"

const (
	// AppArmorAnnotationMissing occurs when the apparmor annotation is missing
	AppArmorAnnotationMissing = "AppArmorAnnotationMissing"
	// AppArmorDisabled occurs when the apparmor annotation is set to the unconfined value
	AppArmorDisabled = "AppArmorDisabled"
	// AppArmorDisabled occurs when the apparmor annotation is set to a bad value
	AppArmorBadValue = "AppArmorBadValue"
	// AppArmorInvalidAnnotation occurs when the apparmor annotation key refers to a container which doesn't exist. This will
	// prevent the manifest from being applied to a cluster with AppArmor enabled.
	AppArmorInvalidAnnotation = "AppArmorInvalidAnnotation"
)

// As of Jan 14, 2020 these constants are not in the K8s API package, but once they are they should be replaced
// https://github.com/kubernetes/kubernetes/blob/master/pkg/security/apparmor/helpers.go#L25
const (
	// The prefix to an annotation key specifying a container profile.
	ContainerAnnotationKeyPrefix = "container.apparmor.security.beta.kubernetes.io/"

	// The profile specifying the runtime default.
	ProfileRuntimeDefault = "runtime/default"
	// The profile specifying the unconfined profile.
	ProfileUnconfined = "unconfined"
	// The prefix for specifying profiles loaded on the node.
	ProfileNamePrefix = "localhost/"
)

const OverrideLabel = "allow-disabled-apparmor"

// AppArmor implements Auditable
type AppArmor struct{}

func New() *AppArmor {
	return &AppArmor{}
}

// Audit checks that AppArmor is enabled for all containers
func (a *AppArmor) Audit(resource k8s.Resource, _ []k8s.Resource) ([]*kubeaudit.AuditResult, error) {
	var auditResults []*kubeaudit.AuditResult
	var containerNames []string

	for _, container := range k8s.GetContainers(resource) {
		containerName := container.Name
		containerNames = append(containerNames, containerName)
		auditResult := auditContainer(container, resource)
		auditResult = applyDisabledOverride(auditResult, containerName, resource)
		if auditResult != nil {
			auditResults = append(auditResults, auditResult)
		}
	}

	auditResults = append(auditResults, auditPodAnnotations(resource, containerNames)...)

	return auditResults, nil
}

func auditContainer(container *k8s.ContainerV1, resource k8s.Resource) *kubeaudit.AuditResult {
	annotations := k8s.GetAnnotations(resource)
	containerAnnotation := getContainerAnnotation(container)

	if isAppArmorAnnotationMissing(containerAnnotation, annotations) {
		return &kubeaudit.AuditResult{
			Auditor:  Name,
			Rule:     AppArmorAnnotationMissing,
			Severity: kubeaudit.Error,
			Message:  fmt.Sprintf("AppArmor annotation missing. The annotation '%s' should be added.", containerAnnotation),
			Metadata: kubeaudit.Metadata{
				"Container":         container.Name,
				"MissingAnnotation": containerAnnotation,
			},
			PendingFix: &fix.ByAddingPodAnnotation{
				Key:   containerAnnotation,
				Value: ProfileRuntimeDefault,
			},
		}
	}

	if isAppArmorDisabled(containerAnnotation, annotations) {
		var rule string
		if isAppArmorUnconfined(containerAnnotation, annotations) {
			rule = AppArmorDisabled
		} else {
			rule = AppArmorBadValue
		}
		
		return &kubeaudit.AuditResult{
			Auditor:  Name,
			Rule:     rule,
			Message:  fmt.Sprintf("AppArmor is disabled. The apparmor annotation should be set to '%s' or start with '%s'.", ProfileRuntimeDefault, ProfileNamePrefix),
			Severity: kubeaudit.Error,
			Metadata: kubeaudit.Metadata{
				"Container":       container.Name,
				"Annotation":      containerAnnotation,
				"AnnotationValue": getProfileName(containerAnnotation, annotations),
			},
			PendingFix: &fix.BySettingPodAnnotation{
				Key:   containerAnnotation,
				Value: ProfileRuntimeDefault,
			},
		}
	}

	return nil
}

func applyDisabledOverride(auditResult *kubeaudit.AuditResult, containerName string, resource k8s.Resource) *kubeaudit.AuditResult {
	if auditResult == nil || auditResult.Rule != AppArmorDisabled {
		return auditResult
	}
	return override.ApplyOverride(auditResult, Name, containerName, resource, OverrideLabel)
}

func auditPodAnnotations(resource k8s.Resource, containerNames []string) []*kubeaudit.AuditResult {
	var auditResults []*kubeaudit.AuditResult
	for annotationKey, annotationValue := range k8s.GetAnnotations(resource) {
		if !strings.HasPrefix(annotationKey, ContainerAnnotationKeyPrefix) {
			continue
		}
		containerName := strings.Split(annotationKey, "/")[1]
		if !contains(containerNames, containerName) {
			auditResults = append(auditResults, &kubeaudit.AuditResult{
				Auditor:  Name,
				Rule:     AppArmorInvalidAnnotation,
				Severity: kubeaudit.Error,
				Message:  fmt.Sprintf("AppArmor annotation key refers to a container that doesn't exist. Remove the annotation '%s: %s'.", annotationKey, annotationValue),
				Metadata: kubeaudit.Metadata{
					"Container":  containerName,
					"Annotation": fmt.Sprintf("%s: %s", annotationKey, annotationValue),
				},
				PendingFix: &fix.ByRemovingPodAnnotations{
					Keys: []string{annotationKey},
				},
			})
		}
	}
	return auditResults
}

func isAppArmorAnnotationMissing(apparmorAnnotation string, annotations map[string]string) bool {
	_, ok := annotations[apparmorAnnotation]
	return !ok
}

func isAppArmorDisabled(apparmorAnnotation string, annotations map[string]string) bool {
	profileName, ok := annotations[apparmorAnnotation]
	return !ok || profileName != ProfileRuntimeDefault && !strings.HasPrefix(profileName, ProfileNamePrefix)
}

func isAppArmorUnconfined(apparmorAnnotation string, annotations map[string]string) bool {
	profileName, ok := annotations[apparmorAnnotation]
	return ok && profileName == ProfileUnconfined
}

func getContainerAnnotation(container *k8s.ContainerV1) string {
	return ContainerAnnotationKeyPrefix + container.Name
}

func getProfileName(apparmorAnnotation string, annotations map[string]string) string {
	profileName := annotations[apparmorAnnotation]
	return profileName
}

func contains(arr []string, val string) bool {
	for _, arrVal := range arr {
		if arrVal == val {
			return true
		}
	}
	return false
}
