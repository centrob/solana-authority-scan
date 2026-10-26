# Security

## Reporting a vulnerability in this tool

Please report a vulnerability in `solana-authority-scan` privately, by email to
**security@centrob.co**. Do not open a public issue or pull request for it.

Useful to include: the version (`solana-authority-scan --version`), what you ran, what
happened, and what you expected.
Once a fix is released, the advisory credits you unless you ask otherwise.

In scope, for example:

- any way the tool could sign, send or simulate a transaction, or read or store a key;
- the RPC URL, or a part of it, appearing in output, errors or files;
- account data that makes a decoder panic, allocate without bound, or report a wrong
  authority, threshold, time lock or proposal state;
- output written inside a git work tree, through a symlink, or outside the directory
  given;
- a dependency that brings in signing or sending code.

## Supported versions

The latest release receives security fixes.

## Weaknesses in other people's programs

This tool reports on programs you name. If it shows a weakness in a program that is not
yours, tell that program's owner privately through their published security contact,
and please do not publish results that name a program, multisig or team as weak.
