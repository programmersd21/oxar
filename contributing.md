# contributing

## building

```sh
cargo build --workspace
cargo test --workspace
```

for python:

```sh
pip install -e ".[dev]"
maturin develop
pytest tests/python
```

## pull requests

one logical change per commit. commit messages follow conventional commits. code
is formatted with `cargo fmt` and `ruff`, and `cargo clippy --all-targets
--all-features -- -d warnings` passes. new public behaviour needs a test and, if
it is a file, an entry in the format support matrix.

## style

comments explain why, never what. code, docs, errors and commits are plain,
specific and free of promotional language. no em dashes, emojis or exclamation
marks in tracked text.
