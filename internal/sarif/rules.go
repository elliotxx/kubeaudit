package sarif

import (
	"github.com/elliotxx/kubeaudit/auditors/apparmor"
	"github.com/elliotxx/kubeaudit/auditors/asat"
	"github.com/elliotxx/kubeaudit/auditors/capabilities"
	"github.com/elliotxx/kubeaudit/auditors/deprecatedapis"
	"github.com/elliotxx/kubeaudit/auditors/hostns"
	"github.com/elliotxx/kubeaudit/auditors/image"
	"github.com/elliotxx/kubeaudit/auditors/limits"
	"github.com/elliotxx/kubeaudit/auditors/mounts"
	"github.com/elliotxx/kubeaudit/auditors/netpols"
	"github.com/elliotxx/kubeaudit/auditors/nonroot"
	"github.com/elliotxx/kubeaudit/auditors/privesc"
	"github.com/elliotxx/kubeaudit/auditors/privileged"
	"github.com/elliotxx/kubeaudit/auditors/rootfs"
	"github.com/elliotxx/kubeaudit/auditors/seccomp"
)

var allAuditors = map[string]string{
	apparmor.Name:       "Finds containers that do not have AppArmor enabled",
	asat.Name:           "Finds containers where the deprecated SA field is used or with a mounted default SA",
	capabilities.Name:   "Finds containers that do not drop the recommended capabilities or add new ones",
	deprecatedapis.Name: "Finds any resource defined with a deprecated API version",
	hostns.Name:         "Finds containers that have HostPID, HostIPC or HostNetwork enabled",
	image.Name:          "Finds containers which do not use the desired version of an image (via the tag) or use an image without a tag",
	limits.Name:         "Finds containers which exceed the specified CPU and memory limits or do not specify any",
	mounts.Name:         "Finds containers that have sensitive host paths mounted",
	netpols.Name:        "Finds namespaces that do not have a default-deny network policy",
	nonroot.Name:        "Finds containers allowed to run as root",
	privesc.Name:        "Finds containers that allow privilege escalation",
	privileged.Name:     "Finds containers running as privileged",
	rootfs.Name:         "Finds containers which do not have a read-only filesystem",
	seccomp.Name:        "Finds containers running without seccomp",
}
