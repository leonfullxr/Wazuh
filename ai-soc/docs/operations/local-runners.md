# Local offline runners

## Prepare and validate

Use the locked `uv.lock`, `dev/toolchain.lock.json`, and local caches to prepare a checkout:

```sh
make bootstrap
make ci-check
```

`make bootstrap` prepares the locked Python and platform tools, the digest-pinned linux/amd64
protocol images, and an anonymous-credential uv cache from `https://pypi.org/simple`. The image
cache manifest binds its bytes to `uv.lock`. Acceptance commands run offline. Docker is configured
with `build/private/docker-config` and Buildx with `build/private/buildx-config`; the runner uses
only the named task builder and never selects or changes the default builder.

`make compose-check` runs the uniquely named local protocol Compose project and its harness tests.
`make infra-check` checks Terraform formatting, provider initialization from the prepared cache,
validation, TFLint, and offline policy fixtures. It does not apply infrastructure.

`make live-boot-check` builds the service image, starts DynamoDB Local and ADOT from the
fixture Compose file, uses a labelled S3Mock local stand-in for production-style S3 pack
delivery (`s3://` plus `SOC_S3_ENDPOINT_URL`), runs the image read-only with the ECS tmpfs
size, probes `/health/live` and `/health/ready`, and asserts invalid sealed config and pack
digests fail container startup. It is not AWS validation and does not replace live
qualification gates.

The entrypoint smoke sends a schema-valid authenticated `/v1/fetches/page` request with a
sealed local cursor and requires a returned indexer row. The container uses a local HTTPS
indexer stand-in under the sealed private hostname, with its certificate trusted through the
injected site CA; the runner fails unless the stand-in records the search. A local KMS Sign
protocol stand-in supplies the indexer token. Bedrock Converse is not exercised by local
runners; its private endpoint and model access are only available in the AWS qualification
environment.

The admission-runtime integration suite also includes a `LOCAL-ONLY` authenticated REST
page request backed by a local indexer protocol stand-in. It drives the application's page
route and the real bounded indexer adapter through one fetch; this covers the private
indexer transport without invoking Bedrock Converse.

## OCI reproducibility

`make test-e2e` builds the pinned UI into `ui/dist`. Then run:

```sh
make image-reproducibility
```

The runner makes three clean linux/amd64 OCI builds using the digest-pinned local bases, the
named BuildKit v0.33.1 builder, `--pull=false`, `--no-cache`, and `--network=none`. It fixes
`SERVICE_SHA`, `CONTENT_SHA`, and `SOURCE_DATE_EPOCH`; creates independent source contexts with
different file mtimes; and enables BuildKit timestamp rewriting. The first two image config and
layer digests must match. It builds and verifies two distinct synthetic content packs with the
locked content CLI. The third build uses the second pack's actual commit and pack digest; both
must change the image config while the service layer digests remain equal. The content pack is a
provenance input and is not baked into the service image.

The runner requires at least 2 GiB free on `/dev/shm`, creates a unique `soc-image-repro-*`
scratch directory there, and places build contexts and all three OCI export temporaries there.
It prunes only its uniquely named Buildx builder after each completed export. After verifying both
clean builds and the changed-pack control, it inventories tmpfs inputs, copies the OCI archives to
the durable per-run directory, checks each copied SHA-256, records the Buildx metadata and identities,
and removes only that inventoried scratch directory. An incomplete run leaves its tmpfs path recorded
in `tmpfs-scratch.json` and does not claim image reproducibility. Durable evidence is under a unique
directory in `build/evidence/image-repro/`.

The generated uv cache and OCI archives are local evidence and are not committed. A missing cache
or local image is a preparation failure: run `make bootstrap` before offline acceptance. No cloud
credentials, customer endpoints, image pushes, or Terraform apply are used.
