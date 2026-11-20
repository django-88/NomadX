# Publishing checklist

This folder is a clean distribution copy with a small, unpublished history on
`main` and a `v0.1.0` tag. The original development tree is kept outside the
repository.

## 1. Create the GitHub repository

Create an empty **public** repository named `NomadX` on GitHub. Do not add a
README, license, or `.gitignore`; this folder already has them.

With the GitHub CLI:

```bash
gh auth login
gh repo create NomadX --public --source=. --remote=origin --push
```

With plain Git, add the remote and push:

```bash
git remote add origin git@github.com:django-88/NomadX.git
git push -u origin main
```

HTTPS works too:

```bash
git remote add origin https://github.com/django-88/NomadX.git
git push -u origin main
```

## 2. Repository settings

- Set the description to: `Zig-native Windows x64 agent for Mythic`
- Add topics: `mythic`, `zig`, `red-team`, `adversary-emulation`, `c2`,
  `windows`, `bof`
- Upload `docs/assets/nomad-social.png` as the social preview
- Enable private vulnerability reporting (see `SECURITY.md`)
- Keep the default branch as `main`

## 3. Before every push

```bash
zig build test
python3 -m pytest -q
git status
```

Do not commit:

- live C2 URLs, API tokens, AES keys, or UUIDs
- built payloads, crash dumps, or sandbox reports
- customer names, hostnames, or IP addresses
- `.toolchain/`, `.zig-cache/`, `zig-out/`, or `dist/`

The checked-in `src/agent_config.json` and `src/agent_config.enc` are sanitized
placeholders and must stay that way.

## 4. If you need to change the commit author

The initial commit is authored as `Peter Tamas <peter.tamas@protonmail.ch>`.
To use a different identity before the first push:

```bash
git config user.name "Your Name"
git config user.email "you@example.com"
git commit --amend --reset-author --no-edit
```
