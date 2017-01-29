# Rocket Authentication Demo

See [this blogpost](https://skinkade.github.io/rocket-auth-demo/).

To get this working, you need PostgreSQL set up, and run:

```bash
echo DATABASE_URL=postgres://user:pass@host/site > .env
head -c16 /dev/urandom > secret.key
cargo install diesel
diesel migration run
```

`wizard.png` is the 2FA QR code for the default admin user, for testing purposes.