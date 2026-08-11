# Acknowledgements

This project would not exist without the prior public work from the Motorola/MTK bootloader research community.

## Projects Used As References

- [kasnria001/pwnage24mtk](https://github.com/kasnria001/pwnage24mtk)

  Reference implementation and tooling for MTK bootloader patching, image rehashing, signing-related workflows, and practical Motorola/MTK research patterns.

- [R0rt1z2/liblk](https://github.com/R0rt1z2/liblk)

  LK/LKS parsing work that informed the local `liblk` parser used to extract Motorola LK subimages and metadata.

- [R0rt1z2/lkpatcher](https://github.com/R0rt1z2/lkpatcher)

  Prior LK patching research and implementation ideas that helped guide the initial approach for Motorola LK binary modification.

## Note

This repository contains additional analysis logic, pattern matching, runtime serial key derivation, preset automation, and Motorola-specific flow handling built during later research. Credit above does not imply endorsement by the original authors.

Before publishing, review the licenses of the referenced projects and make sure this repository's final license and attribution terms are compatible with any copied or derived code.

