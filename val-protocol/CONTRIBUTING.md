# Contributing

Contributions should preserve the current compatibility-first approach.

## Guidelines

- Keep changes narrowly scoped.
- Do not include firmware images, patched images, or device dumps.
- Add analyzer evidence when supporting a new LK family.
- Preserve AArch64 and ARM32 Thumb behavior unless the change is explicitly architecture-specific.
- Run `python -m py_compile` before submitting changes.
- Update documentation when CLI options or presets change.

## New Device Support

For a new LK family, include:

- architecture reported by the analyzer,
- `summary.txt` excerpts without private identifiers,
- which preset was tested,
- whether `Result: VALID` was produced,
- whether runtime serial detection points to the correct getter.

