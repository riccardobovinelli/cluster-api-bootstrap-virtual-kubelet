# Cluster API Bootstrap Provider Virtual Kubelet for non-Kubernetes Management

The *Cluster API Bootstrap Provider Virtual Kubelet (CABPV)* is a custom Cluster API (CAPI) bootstrap provider designed to enable the provisioning and lifecycle management of non-Kubernetes nodes, such as Slurm-based HPC clusters, through the Virtual Kubelet interface.

## Getting Started
You’ll need a Kubernetes cluster to run against. You can use [KIND](https://sigs.k8s.io/kind) to get a local cluster for testing, or run against a remote cluster.
**Note:** Your controller will automatically use the current context in your kubeconfig file (i.e. whatever cluster `kubectl cluster-info` shows).

### Running on the cluster
1. Install Instances of Custom Resources:

```sh
kubectl apply -f config/samples/
```

2. Build and push your image to the location specified by `IMG`:

```sh
make docker-build docker-push IMG=<some-registry>/cluster-api-bootstrap-virtual-kubelet:tag
```

3. Deploy the controller to the cluster with the image specified by `IMG`:

```sh
make deploy IMG=<some-registry>/cluster-api-bootstrap-virtual-kubelet:tag
```

### Uninstall CRDs
To delete the CRDs from the cluster:

```sh
make uninstall
```

### Undeploy controller
UnDeploy the controller from the cluster:

```sh
make undeploy
```


### Test It Out
1. Install the CRDs into the cluster:

```sh
make install
```

2. Run your controller (this will run in the foreground, so switch to a new terminal if you want to leave it running):

```sh
make run
```

**NOTE:** You can also run this in one step by running: `make install run`

### Modifying the API definitions
If you are editing the API definitions, generate the manifests such as CRs or CRDs using:

```sh
make manifests
```

**NOTE:** Run `make --help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

# How to Contribute

## Certificate of Origin

By contributing to this project you agree to the Developer Certificate of Origin
(DCO). This document was created by the Linux Kernel community and is a simple
statement that you, as a contributor, have the legal right to make the
contribution. See the [DCO](DCO) file for details.

### Git commit Sign-off

Commit message should contain signed off section with full name and email. For example:

 ```text
  Signed-off-by: John Doe <jdoe@example.com>
 ```

When making commits, include the `-s` flag and `Signed-off-by` section
will be automatically added to your commit message. If you want GPG
signing too, add the `-S` flag alongside `-s`.

```bash
  # Signing off commit
  git commit -s

  # Signing off commit and also additional signing with GPG
  git commit -s -S
```
