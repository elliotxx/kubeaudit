package fix

import (
	"testing"

	"github.com/elliotxx/kubeaudit"
	"github.com/elliotxx/kubeaudit/pkg/k8s"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
)

func TestFix(t *testing.T) {
	cases := []struct {
		testName    string
		pendingFix  kubeaudit.PendingFix
		preFix      func(resource k8s.Resource)
		assertFixed func(t *testing.T, resource k8s.Resource)
	}{
		{
			testName:   "BySettingPodAnnotation",
			pendingFix: &BySettingPodAnnotation{Key: "mykey", Value: "myvalue"},
			preFix:     func(resource k8s.Resource) {},
			assertFixed: func(t *testing.T, resource k8s.Resource) {
				annotations := k8s.GetAnnotations(resource)
				assert.NotNil(t, annotations)
				val, ok := annotations["mykey"]
				assert.True(t, ok)
				assert.Equal(t, "myvalue", val)
			},
		},
		{
			testName:   "ByAddingPodAnnotation",
			pendingFix: &ByAddingPodAnnotation{Key: "mykey", Value: "myvalue"},
			preFix:     func(resource k8s.Resource) {},
			assertFixed: func(t *testing.T, resource k8s.Resource) {
				annotations := k8s.GetAnnotations(resource)
				assert.NotNil(t, annotations)
				val, ok := annotations["mykey"]
				assert.True(t, ok)
				assert.Equal(t, "myvalue", val)
			},
		},
		{
			testName:   "ByRemovingPodAnnotations",
			pendingFix: &ByRemovingPodAnnotations{Keys: []string{"mykey", "mykey2"}},
			preFix: func(resource k8s.Resource) {
				k8s.GetPodObjectMeta(resource).SetAnnotations(map[string]string{"mykey": "myvalue", "mykey2": "myvalue2"})
			},
			assertFixed: func(t *testing.T, resource k8s.Resource) {
				annotations := k8s.GetAnnotations(resource)
				_, ok := annotations["mykey"]
				assert.False(t, ok)
				_, ok2 := annotations["mykey2"]
				assert.False(t, ok2)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.testName, func(t *testing.T) {
			resource := &k8s.PodV1{Spec: v1.PodSpec{}}
			tc.preFix(resource)
			assert.NotEmpty(t, tc.pendingFix.Plan())
			tc.pendingFix.Apply(resource)
			tc.assertFixed(t, resource)
		})
	}
}
