# Security

## Report a vulnerability

Do not open a public issue for a security problem. Use the private report form of this repository on GitHub: the
Security tab, then "Report a vulnerability". Only the maintainers can read what you send there.

Say what is affected, the version or commit, and how to reproduce it. A request, a configuration or a short script
that shows the problem helps most.

This repository is the WAF agent without its detection engine. Reports about the proxy (request smuggling, parsing differences with the upstream), the control link, memory safety, crashes and ways to make the agent pass a request without inspecting it are in scope. A request that the detection engine fails to recognise as an attack is also welcome here, privately, although the engine itself is not in this repository.

We answer every report, tell you whether we can reproduce it, and tell you when a fix is released. Please give us
the chance to release a fix before you publish details.

## Versions

Fixes go into the latest release and into `main`.
