# Publishing Checklist

Use this checklist before pushing the repository to GitHub.

## Remove Local Artifacts

Do not publish:

- original LK images
- patched LK images
- `.bin` firmware dumps
- analysis directories generated from real devices
- server logs
- private secrets
- customer data
- cached patched LK files
- `__pycache__`

## Verify The Tree

From the repository root:

```bash
python -m py_compile lk_auto_patch.py lk_keygen.py lk_patch_partition.py lk_repack_signed.py lk_static_analyzer.py
```

List files:

```bash
git status --short
```

Check for firmware files:

```bash
git status --short
```

Manually confirm there are no `.img`, `.bin`, `.new`, `.patched`, or analysis output directories.

## Recommended Git Ignore Rules

The included `.gitignore` blocks common generated artifacts, firmware images, cache directories, and analysis output.

## Choose A License

This prepared copy does not assign an open-source license. Add a license before publishing if you want to grant reuse rights.

Common choices:

- MIT for permissive reuse
- Apache-2.0 for permissive reuse with patent language
- GPL-3.0 for copyleft distribution
- no license / all rights reserved for public code viewing without reuse rights

## Public README Review

Before publishing, review:

- safety and authorization notice,
- supported presets,
- known risks,
- no hardcoded production secret,
- no customer-specific paths.

