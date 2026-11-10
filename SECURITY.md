# Security

This is a demo. Nobody has audited it, and it isn't meant to run in production or
protect real data. A few things in particular make it unsafe as-is:

- every token is signed with one shared demo secret, so anyone who has the
  secret can act as anyone;
- OpenBao runs in dev mode with a well-known root token and keeps its keys in
  memory;
- services talk to each other over plain HTTP, with no NetworkPolicy.

[docs/design.md](docs/design.md#what-a-production-version-needs) has the list of
what a production version would need.

If you find a flaw in the *design*, something that would still be wrong once
those shortcuts were fixed, please open an issue. I'd like to hear about it.
