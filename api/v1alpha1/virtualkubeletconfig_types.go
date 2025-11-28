/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeadm "sigs.k8s.io/cluster-api/api/bootstrap/kubeadm/v1beta2"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

type VirtualKubelet struct {
	Url  string   `json:"url,omitempty"`
	Args []string `json:"args,omitempty"`
}

// VirtualKubeletConfigSpec defines the desired state of VirtualKubeletConfig
// +kubebuilder:validation:MinProperties=1
type VirtualKubeletConfigSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	VirtualKubelet VirtualKubelet `json:"virtualKubelet"`

	// Users specifies extra users to add
	// +optional
	Users []kubeadm.User `json:"users,omitempty"`

	// Files specifies extra files to be passed to user_data upon creation.
	// +optional
	Files []kubeadm.File `json:"files,omitempty"`

	// Commands specifies extra commands to run before kubeadm runs
	// +optional
	Commands []string `json:"commands,omitempty"`

	// Format specifies the output format of the bootstrap data
	// +optional
	Format kubeadm.Format `json:"format,omitempty"`
}

// Default defaults a KubeadmConfigSpec.
func (c *VirtualKubeletConfigSpec) Default() {
	if c.Format == "" {
		c.Format = kubeadm.CloudConfig
	}

}

// VirtualKubeletConfigStatus defines the observed state of VirtualKubeletConfig
// +kubebuilder:validation:MinProperties=1
type VirtualKubeletConfigStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	// Ready indicates the BootstrapData field is ready to be consumed
	// +optional
	Ready bool `json:"ready"`

	// DataSecretName is the name of the secret that stores the bootstrap data script.
	// +optional
	DataSecretName *string `json:"dataSecretName,omitempty"`

	// initialization provides observations of the VirtualKubeletConfig initialization process.
	// +optional
	Initialization VirtualKubeletConfigInitializationStatus `json:"initialization,omitempty,omitzero"`
}

// +kubebuilder:validation:MinProperties=1
type VirtualKubeletConfigInitializationStatus struct {
	// dataSecretCreated is true when the Machine's boostrap secret is created.
	// +optional
	DataSecretCreated bool `json:"dataSecretCreated,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// VirtualKubeletConfig is the Schema for the virtualkubeletconfigs API
type VirtualKubeletConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VirtualKubeletConfigSpec   `json:"spec,omitempty"`
	Status VirtualKubeletConfigStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// VirtualKubeletConfigList contains a list of VirtualKubeletConfig
type VirtualKubeletConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VirtualKubeletConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VirtualKubeletConfig{}, &VirtualKubeletConfigList{})
}
