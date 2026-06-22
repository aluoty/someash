# someash

A fast, universal hashing tool with support for **25+ hash algorithms**. Hash strings, files, and stdin — verify checksums — choose your output format.

## Usage

```text
someash [OPTIONS] [STRINGS]...
```

### Modes

| Mode | Example |
|------|---------|
| **Hash strings** | `someash --algorithm sha256 "hello" "world"` |
| **Hash files** | `someash -a md5 -f file1.bin -f file2.bin` |
| **Hash stdin** | `echo "data" \| someash -a blake3` |
| | `someash -a xxh64 --stdin < data.bin` |
| **Verify checksums** | `someash -a sha256 --check SHA256SUMS` |
| **List algorithms** | `someash --list` |

### Options

| Flag | Description |
|------|-------------|
| `-a`, `--algorithm` | Hash algorithm (default: `sha256`) |
| `-f`, `--file` | File(s) to hash |
| `--stdin` | Read from stdin explicitly |
| `--format` | Output format: `hex` (default) or `base64` |
| `-l`, `--list` | List all available algorithms |
| `--check` | Verify checksums from a sums-file |
| `-h`, `--help` | Print help |
| `-V`, `--version` | Print version |

### Examples

```bash
# Hash a string with SHA-256
someash -a sha256 "hello world"

# Hash with multiple algorithms
someash -a md5 "hello"
someash -a blake3 "hello"

# Hash a file
someash -a sha256 -f document.pdf

# Hash multiple files
someash -a sha256 -f file1.txt -f file2.txt

# Pipe data via stdin
cat file.bin | someash -a sha256

# Base64 output
someash -a sha256 --format base64 "hello"

# Generate checksums file and verify
someash -a sha256 -f file.bin > file.sha256
someash -a sha256 --check file.sha256

# List all algorithms
someash --list
```

## Algorithms

| Algorithm | Output size | Crate |
|-----------|-------------|-------|
| `fnv32` | 4 B | built-in |
| `fnv64` | 8 B | built-in |
| `fnv128` | 16 B | built-in |
| `sha1` | 20 B | `sha1` |
| `sha224` | 28 B | `sha2` |
| `sha256` | 32 B | `sha2` |
| `sha384` | 48 B | `sha2` |
| `sha512` | 64 B | `sha2` |
| `sha512-224` | 28 B | `sha2` |
| `sha512-256` | 32 B | `sha2` |
| `md5` | 16 B | `md-5` |
| `blake2b` | 64 B | `blake2` |
| `blake2b-256` | 32 B | `blake2` |
| `blake2b-384` | 48 B | `blake2` |
| `blake2b-512` | 64 B | `blake2` |
| `blake2s` | 32 B | `blake2` |
| `blake2s-256` | 32 B | `blake2` |
| `blake3` | 32 B | `blake3` |
| `crc32` | 4 B | `crc` |
| `crc32c` | 4 B | `crc` |
| `crc64-ecma` | 8 B | `crc` |
| `crc64-iso` | 8 B | `crc` |
| `xxh32` | 4 B | `xxhash-rust` |
| `xxh64` | 8 B | `xxhash-rust` |
| `xxh3-64` | 8 B | `xxhash-rust` |
| `xxh3-128` | 16 B | `xxhash-rust` |

## Build

```bash
cargo build --release
```

The binary will be at `target/release/someash`.

## Checksum file format

Compatible with standard Unix `sha256sum` / `md5sum` format:

```
<hash>  <filename>
<hash> <filename>
```

Lines starting with `#` or `;` are skipped.

## License

[See LICENSE](LICENSE)
