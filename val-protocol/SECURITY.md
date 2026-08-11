# Security Policy

## Intended Use

This project is intended for authorized device repair, bootloader research, interoperability testing, and recovery workflows on devices owned by the operator or serviced with explicit permission.

Do not use this project against devices you do not own or do not have authorization to service.

## Reporting Issues

When reporting a security issue, do not include:

- customer identifiers,
- device serial numbers,
- IMEI values,
- private service secrets,
- proprietary firmware dumps,
- patched production images.

Share only the minimum metadata needed to reproduce the issue.

## Secrets

Never commit production secrets. The examples use placeholder values such as `YourSecret`; replace them only in private deployment environments.

