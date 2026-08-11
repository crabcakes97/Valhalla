# Analysis Outputs

`lk_static_analyzer.py` writes a structured analysis directory. These files are useful when adding support for a new LK.

## `summary.txt`

Human-readable summary:

- source file
- input type
- LK base address
- LK size and VA range
- architecture
- number of decoded instructions
- number of string hits and cross references
- best flow candidates
- best FRP checker
- best key validator
- partition erase operations
- runtime serial source

## `strings.txt`

Target string hits and surrounding printable context.

## `xrefs.txt`

String cross references with nearby instructions.

## `flow_candidates.json`

Ranked unlock-flow candidates. Each candidate includes:

- start and end address
- score
- matched strings
- calls
- branches
- string references

## `frp_checkers.json`

Detected FRP/OEM checker candidates. Useful evidence includes:

- FRP-related strings
- caller relationship from the unlock flow
- structural instructions around the last-byte FRP/OEM check

## `key_validators.json`

Detected key validator candidates. Useful evidence includes:

- hash validation strings
- result-return patterns
- comparison loops
- caller failure edges leading to the code-validation failure path

## `serialno_runtime.json`

Runtime serial source candidate. Important fields:

- `hw_get_serialno_string`
- `hw_get_serialno_string_file_offset`
- `generic_prop_get_string`
- `xrefs`
- `calls`
- `cache_candidates`
- `confidence`

If the runtime serial source is wrong, generated keys will fail or the device may reset when the command is executed. Always inspect this file when adding a new device family.

## `partition_erases/`

Unlock-flow erase operation details. The preset logic uses these to identify where partition names such as `metadata`, `userdata`, `nvdata`, or `md_udc` appear in the unlock flow.

## `*.asm` Files

Assembly reports are written for important candidates. These are meant for manual auditing before trusting a new pattern.

