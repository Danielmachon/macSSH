# SSH v2 Client/Server implementation

SSH is a lightweight client/server implementation of the SSH v2 protocol, written entirely in C. SSH has no external or dynamic dependencies and links statically against bundled tomcrypt and tommath at compile time.

SSH is inspired by Dropbear, but written entirely from scratch. it is meant as an alternative to Dropbear on low-end unix platforms.

DMA-SSH follows the Linux kernel coding style (see CODING_STYLE)
