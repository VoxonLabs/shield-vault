# Setup Notes

## Rust

Official install command:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup toolchain install stable --profile minimal
rustup component add rustfmt clippy
rustc --version
cargo --version
```

This workspace was verified with:

```text
rustc 1.95.0
cargo 1.95.0
```

## Current Rust Checks

```bash
cargo fmt --all
cargo test --workspace
cargo clippy --workspace --all-targets
```

## CI

GitHub Actions runs the Rust quality gate on pushes to `main` and pull requests:

```bash
cargo fmt --all --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## Later Tauri Linux Dependencies

For Ubuntu/Debian-like systems, check the current Tauri v2 docs before installing. The commonly documented package set includes:

```bash
sudo apt update
sudo apt install -y \
  build-essential \
  curl \
  wget \
  file \
  libssl-dev \
  libwebkit2gtk-4.1-dev \
  libxdo-dev \
  libayatana-appindicator3-dev \
  librsvg2-dev
```

Only install Tauri dependencies when starting the desktop phase.

