# Security

This repository is a teaching prototype. It has not been audited, and it is not
meant to run in production or to protect real data. In particular:

- every token is signed with one shared demo secret, so anyone with the secret
  can act as anyone;
- OpenBao runs in dev mode with a well-known root token and keeps its keys in
  memory;
- services talk over plain HTTP, with no NetworkPolicy.

[docs/design.md](docs/design.md#what-a-production-version-needs) lists what a
production version would need.

If you find a flaw in the *design*, something that would still be wrong once
those shortcuts were fixed, please open an issue. It is exactly the kind of thing
this repo exists to teach.
