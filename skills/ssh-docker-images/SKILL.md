---
description: List local docker images on the remote, with optional server-side filters
---

# `ssh_docker_images`

**Tier:** read-only | **Group:** `docker` | **Tags:** `{safe, read, group:docker}`

Runs `docker images --format '{{json .}}'`, parses per-image JSON. Filter kwargs
(`reference`, `dangling`, `label`) map directly to Docker's `--filter KEY=VALUE`
flags. Filters are validated before any SSH connection is opened.

## Inputs

| name | type | required | notes |
|---|---|---|---|
| `host` | str | yes | Alias from hosts.toml |
| `include_labels` | bool | no | Default False; True emits each image's `Labels` field (can be very large on OCI-tagged images) |
| `reference` | str or None | no | Glob-style image reference match. See reference format below |
| `dangling` | bool or None | no | `True` = untagged images only (`<none>:<none>`); `False` = tagged images only; `None` = no filter |
| `label` | str or None | no | Bare key or key=value. Same format as `ssh_docker_ps` label filter |

## Filter details

**`reference`** -- Matches image name (repository + optional tag). Supports Docker's
glob syntax:

- Exact: `"nginx:1.21"` -- one specific image.
- Tag glob: `"nginx:*"` -- all tags for nginx.
- Org glob: `"ghcr.io/org/*:*"` -- all images from a registry org and any tag.
- Digest: `"alpine@sha256:abc123"` -- pin to a digest.

Regex: `[A-Za-z0-9._/:*?@-]{1,256}`. The `*` and `?` are Docker glob wildcards
passed verbatim to the daemon (not shell-expanded). Shell metacharacters (`;`, `|`,
`` ` ``, `$`, `&`, `>`, space, newline) are rejected.

**`dangling`** -- Renders as `--filter dangling=true` or `--filter dangling=false`
(lowercase). Pydantic handles Python `bool` coercion. Use `dangling=True` to find
orphan layers left behind by image rebuilds; use `dangling=False` to list only images
that still have at least one tag.

**`label`** -- Two forms:
- Bare key: `"builder"` -- matches any image that has the label, regardless of value.
- Key=value: `"builder=ci"` -- exact value match.

Key regex: `[A-Za-z0-9._/-]{1,128}`. The `/` means Kubernetes-style label keys work:
`app.kubernetes.io/name`. Value regex: `[A-Za-z0-9._:/=+-]{1,256}`. Shell
metacharacters rejected.

## Argv ordering (deterministic)

```
docker images --format {{json .}}
  [--filter reference=<reference>]
  [--filter dangling=true|false]
  [--filter label=<label>]
```

## Returns

`ExecResult` plus:

- `images`: list of `{Repository, Tag, ID, Size, CreatedSince, ...}`.

## When to call it

- Before `ssh_docker_pull` to check what's already cached.
- Before `ssh_docker_prune` (`scope="image"`) to preview what'll go.
- Capacity check -- find big/unused images.
- Audit: `dangling=True` to find orphan layers before a prune.

## When NOT to call it

- To list running containers -- use `ssh_docker_ps`.

## Examples

List all images:

```python
ssh_docker_images(host="docker1")
```

Find all tags of the `nginx` image:

```python
ssh_docker_images(host="docker1", reference="nginx:*")
```

Find all images from a specific registry org (any tag):

```python
ssh_docker_images(host="docker1", reference="ghcr.io/org/*:*")
```

Find dangling (untagged) images before pruning:

```python
ssh_docker_images(host="docker1", dangling=True)
```

Combine `reference` + `dangling` + `label`:

```python
ssh_docker_images(host="docker1", reference="nginx:*", dangling=False, label="builder")
```

## Common failures

- `ValueError: reference filter ...` -- shell metacharacter in the reference string.
  Check for spaces, semicolons, backticks, `$`, newlines.
- `exit_code != 0` + "permission denied" -- SSH user not in `docker` group.

## Related

- [`ssh_docker_pull`](../ssh-docker-pull/SKILL.md)
- [`ssh_docker_rmi`](../ssh-docker-rmi/SKILL.md)
- [`ssh_docker_prune`](../ssh-docker-prune/SKILL.md)
- [`ssh_docker_ps`](../ssh-docker-ps/SKILL.md)
