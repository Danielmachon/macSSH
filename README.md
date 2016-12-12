# macSSH v2 Client/Server implementation

macSSH is a lightweight client/server implementation of the SSH v2 protocol, written entirely in C. SSH has no external dependencies.

macSSH is inspired by Dropbear, but written entirely from scratch. it is meant as an alternative to Dropbear on low-end unix platforms.

macSSH uses a modified and project-embedded version of libtommath for bignum-arithmetic and libtomcrypt for cryptography.

macSSH has an extensive tracing feature that can be enabled by a switch. If enabled, this feature will trace print initialization, key-exchange/renegotiation and other protocol related steps, so that the end user has a better understanding of what goes on behind the curtain.

macSSH follows the Linux kernel coding style (see the CODING_STYLE document)
