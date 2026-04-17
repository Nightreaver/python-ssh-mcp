---
description: Apply a unified diff to a remote file atomically
---

# `ssh_patch`

**Tier:** low-access | **Group:** `file-ops` | **Tags:** `{low-access, group:file-ops}`

Download -> apply unified diff via the pure-Python `unidiff` library ->
write to `<path>.ssh-mcp-tmp.<hex>` -> `posix_rename` over the original. Mode
preserved. **No fuzzy matching** -- every context line and removal line must
match exactly, or the whole patch is rejected with no file changes.

Single-file diffs only. The `--- a/...` / `+++ b/...` headers are read but
not enforced against `path` (the caller knows which file they're targeting).

## Inputs

| name | type | required | notes |
|---|---|---|---|
| `host` | str | yes | Alias or hostname |
| `path` | str | yes | Absolute path to the target file |
| `unified_diff` | str | yes | A unified diff string (single file) |

## Returns

```json
{
  "host": "web01.example.com",
  "path": "/etc/app/config.yml",
  "success": true,
  "bytes_written": 1842,
  "message": "3 hunk(s) applied"
}
```

## When to call it

- You have a multi-hunk change to apply (multiple separated edits in one file).
- You want to apply the output of `git diff` or `diff -u`.
- The change is structural enough that single-string `ssh_edit` calls would be brittle.

## When NOT to call it

- The diff touches more than one file -> rejected. Apply each file separately.
- You only have one localized string change -- `ssh_edit` is simpler.
- The file is binary -- patch is text-only.

## Example

```python
diff = """\
--- a/config.yml
+++ b/config.yml
@@ -3,1 +3,1 @@
-port: 8080
+port: 9090
@@ -10,1 +10,1 @@
-debug: false
+debug: true
"""
ssh_patch(host="web01", path="/etc/app/config.yml", unified_diff=diff)
```

## Common failures

- `WriteError: context mismatch at line N` -- a context line doesn't match
  what's actually in the file. Re-`ssh_sftp_download`, regenerate the diff.
- `WriteError: removal mismatch at line N` -- a `-` line doesn't match the
  actual line. Same fix.
- `WriteError: diff touches N files; exactly one expected` -- split per file.
- `WriteError: invalid unified diff: ...` -- malformed input. Inspect with
  `unidiff` locally first.

## Related

- [`ssh_edit`](../ssh-edit/SKILL.md) -- single-string replacement; simpler when applicable.
- [`ssh_upload`](../ssh-upload/SKILL.md) -- when re-writing the whole file is easier than patching.
- [`ssh_sftp_download`](../ssh-sftp-download/SKILL.md) -- read current contents to regenerate the diff.
