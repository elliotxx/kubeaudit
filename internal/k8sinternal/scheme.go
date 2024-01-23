package k8sinternal

import (
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	serializer "k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	kubescheme "k8s.io/client-go/kubernetes/scheme"
)

var (
	scheme             = kubescheme.Scheme
	codecs             = serializer.NewCodecFactory(scheme)
	localSchemeBuilder = runtime.SchemeBuilder{
		apiextensionsv1.AddToScheme,
		apiextensionsv1beta1.AddToScheme,
	}
)

// AddToScheme adds localScheme to Scheme
var addToScheme = localSchemeBuilder.AddToScheme

func init() {
	v1.AddToGroupVersion(scheme, schema.GroupVersion{Version: "v1"})
	utilruntime.Must(addToScheme(scheme))
}
