# Packaging: charts, images, and the digest pin

cozyplane ships as **four Helm charts under `chart/`**, consumed straight out of
this git repository by Cozystack — no OCI artifact, no vendoring into the
`cozystack/cozystack` tree. This document covers the two things that are not
obvious from reading the charts: **how a cluster consumes them**, and **where the
container images come from and how their digest pins stay honest**.

## 1. The four charts

| Chart | What it is | Namespace |
|---|---|---|
| `chart/cozyplane` | The CNI: agent DaemonSet, controller Deployment, the `local.sdn.cozystack.io` CRDs (FabricIP), RBAC, the VPCBinding export policy | `cozy-cozyplane` |
| `chart/cozyplane-kpr` | Kube-proxy replacement: socket-LB service load balancing, importing Cilium's LB control plane with no Cilium agent ([kube-proxy-replacement.md](kube-proxy-replacement.md)) | `cozy-cozyplane` |
| `chart/cozyplane-apiserver` | The aggregated API server for `sdn.cozystack.io` (the tenant group) plus its dedicated etcd ([control-plane.md](control-plane.md), [api-groups.md](api-groups.md)) | `cozy-cozyplane` |
| `chart/cozyplane-cilium-crds` | The `cilium.io/v2` policy CRDs, **inert**. Nothing enforces them; stock Cozystack charts embed `CiliumNetworkPolicy` / `CiliumClusterwideNetworkPolicy` objects and fail to install when the CRDs are absent | `cozy-system` |

None of them depends on `cozy-lib` or any other chart library, and none has a
`charts/` directory. That is a requirement, not an accident: the `PackageSource`
manifests declare no `libraries`, so a library dependency would break rendering.
Each must render standalone:

```sh
helm template cozyplane            chart/cozyplane            -f chart/cozyplane/values.yaml -f chart/cozyplane/values-talos.yaml
helm template cozyplane-kpr        chart/cozyplane-kpr        -f chart/cozyplane-kpr/values.yaml -f chart/cozyplane-kpr/values-talos.yaml
helm template cozyplane-apiserver  chart/cozyplane-apiserver  -f chart/cozyplane-apiserver/values.yaml
helm template cozyplane-cilium-crds chart/cozyplane-cilium-crds
```

The `version:` in each `Chart.yaml` is `0.0.0` and means nothing — the chart is
addressed by git commit, so the commit *is* the version.

## 2. How a cluster consumes them

`packages/packagesources/` holds two ready-to-apply Cozystack manifests:

- **`networking.yaml`** — a Flux `GitRepository` pointing at this repo, plus the
  `cozyplane.networking` `PackageSource`: cilium-crds, then the CNI, then kpr.
  It has **no `dependsOn`**, because it is the CNI: it installs ahead of
  cert-manager and everything else, since nothing can be scheduled until it is up.
- **`apiserver.yaml`** — the `cozyplane.apiserver` `PackageSource`, sequenced
  *after* cert-manager, the etcd-operator and the storage layer, because the
  aggregated API server needs `Certificate`s, an `EtcdCluster` and a
  `StorageClass`. One `PackageSource` cannot hold both positions, which is the
  only reason there are two files.

The `GitRepository` lives in `networking.yaml` only; one source object serves
both. Its `ref` carries `branch: main` and **no `commit`** — a repository that
pinned a commit to itself could never be updated in place. A cluster that wants
a fixed build stamps `commit: <sha>` onto its own copy of that object.

`valuesFiles` are ordered: the Cozystack operator applies the **first** with
strategy `Overwrite` and **every later one** with `Merge`. That is why
`values-talos.yaml` must stay a separate file — its contents (notably
`kubeApiServer: {host: localhost, port: 7445}`, Talos's KubePrism, which the
hostNetwork agent dials during bootstrap before any service proxy exists) are
wrong off Talos and must never become chart defaults.

`apiserver.yaml`'s `dependsOn` names `blockstor.storage`. A cluster running the
stock storage package must change that one line to `cozystack.linstor`;
otherwise the PackageSource waits forever on a package that never appears.

## 3. Where the images are built

Two images, and they are **not** built the same way.

### `ghcr.io/lllamnyp/cozyplane` — CI-built, multi-arch, reproducible

Built and pushed by [`.github/workflows/release.yml`](../.github/workflows/release.yml)
on every push to `main` (and on `v*` tags), for `linux/amd64` and `linux/arm64`,
from the repository root `Dockerfile`. It carries the agent, the CNI plugin, the
controller, the aggregated apiserver, the gateway and the responder — one image,
six binaries. Tags: `main`, `main-<short-sha>`, and semver on tags. The workflow
prints the resulting digest into the run's job summary.

The build is **digest-reproducible** ([#4](../../issues/4)): attestations off
(`provenance: false`, `sbom: false` — their manifests embed run metadata and land
in the index), `SOURCE_DATE_EPOCH=0` plus `rewrite-timestamp=true` to pin layer
and config timestamps, digest-pinned base images, `-trimpath -buildvcs=false` on
every `go build`, and apt byproducts removed in the same layer. The same source
tree therefore always produces the same index digest.

### `ghcr.io/lllamnyp/cozyplane-kpr` — hand-built, amd64 only

Built from `kpr/` with `kpr/Dockerfile`, which expects a **pre-built binary**
rather than compiling from source:

```sh
CGO_ENABLED=0 go -C kpr build -o kpr/cozyplane-kpr .
docker build -t ghcr.io/lllamnyp/cozyplane-kpr:<tag> -f kpr/Dockerfile kpr
docker push ghcr.io/lllamnyp/cozyplane-kpr:<tag>
```

**There is no CI job for this image.** It is pushed by hand, it is `linux/amd64`
only, and it is not reproducible. Both known gaps: an arm64 cluster cannot run
`cozyplane-kpr` today, and the digest can only be refreshed by someone with a
push credential running the commands above. Fixing this means a multi-stage
`kpr/Dockerfile` and a second job in `release.yml`; it has not been done because
`kpr/` pulls Cilium's ~394-module tree and the from-source image build is slow.

## 4. The digest pin, and why it isn't circular

Three `values.yaml` files pin an image by digest:

| File | Image |
|---|---|
| `chart/cozyplane/values.yaml` | `ghcr.io/lllamnyp/cozyplane` |
| `chart/cozyplane-apiserver/values.yaml` | `ghcr.io/lllamnyp/cozyplane` (the same pin — keep them equal) |
| `chart/cozyplane-kpr/values.yaml` | `ghcr.io/lllamnyp/cozyplane-kpr` |

Because a cluster tracks a **commit** of this repository, the digest recorded at
that commit must be a build of *that same commit*. Written out, that looks
circular: writing the digest into `values.yaml` creates a new commit, whose build
would presumably have a different digest, which would then need writing in, and
so on.

It is not circular, for one reason: **`chart/` does not reach the image.** The
final stage of the `Dockerfile` copies only compiled binaries out of the build
stage; charts, docs and manifests are in the build context but contribute nothing
to any layer of the published image. Combined with the reproducibility measures
above — in particular `-buildvcs=false`, without which the embedded commit hash
made every commit produce a different binary — a commit that changes only
`values.yaml` rebuilds to **exactly the digest it just pinned**. The loop
converges after one step:

1. Land the source change on `main`. CI publishes an image; note its digest `D`.
2. Write `D` into the `values.yaml` files and land that as a second commit.
3. CI rebuilds. Because nothing that reaches the image changed, the digest is
   still `D` — so commit 2's pin *is* a build of commit 2. That is the commit to
   hand a cluster.

This is checkable after the fact, and it holds today: `main-e1f36dd` (a datapath
fix) and `main-b10baf0` (a docs-only commit on top of it) both resolve to
`sha256:79866d68…`.

For `cozyplane-kpr` the same argument does not apply — the image is not
reproducible — so the rule there is weaker and manual: rebuild and push whenever
anything under `kpr/` changes, then pin the digest the push reported.

### Refreshing a pin

```sh
# the digest CI published for a commit (anonymous; no docker login needed)
TOK=$(curl -s "https://ghcr.io/token?scope=repository:lllamnyp/cozyplane:pull&service=ghcr.io" \
      | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
curl -sI -H "Authorization: Bearer $TOK" \
     -H "Accept: application/vnd.oci.image.index.v1+json" \
     "https://ghcr.io/v2/lllamnyp/cozyplane/manifests/main-<short-sha>" \
  | grep -i docker-content-digest
```

The same request with no `Authorization` header at all is what a cluster does, so
running it that way also confirms the **anonymous pullability** the charts rely
on: neither image needs an `imagePullSecret`, and both packages must stay public.

### Pin status

Verified 2026-08-25 against ghcr.io, anonymously:

- `ghcr.io/lllamnyp/cozyplane@sha256:681e37c0d8f919829879bb74eb0419b8a0c7b43694ff94904d3935bc0eb22a0c`
  — an OCI index with `linux/amd64` + `linux/arm64`, and the current `main` /
  `main-17b707f` build.
- `ghcr.io/lllamnyp/cozyplane-kpr@sha256:425693919d8a4f24daea9629548180ef5cef72dece4d31bf5b6505a671147766`
  — `linux/amd64` only, pushed 2026-07-18 (tag `spn`) from the `kpr/` tree as of
  commit `72e72df`, which is still the tip state of `kpr/`.
