<p align="center">
<img src="https://raw.githubusercontent.com/itsrishub/logster/refs/heads/main/assets/logster.png" alt="image" />
</p>

# logster

[![GitHub release](https://img.shields.io/github/release/itsrishub/logster.svg)](https://github.com/itsrishub/logster/releases) [![GitHub Actions](https://img.shields.io/github/actions/workflow/status/itsrishub/logster/release.yml?branch=main)](https://github.com/itsrishub/logster/actions) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=flat&logo=rust&logoColor=white)](https://www.rust-lang.org/)

A powerful, high-performance log analysis tool written in Rust. Logster helps you search, filter, and extract insights from various log formats.

## Installation

### Download Pre-built Binaries

Download the latest release for your platform from the [releases page](https://github.com/itsrishub/logster/releases).

Available for:
- Linux (x86_64, ARM64)
- macOS (Intel, Apple Silicon)
- Windows (x86_64)

### Build from Source

#### Rust Version

Prerequisites:
- [Rust](https://www.rust-lang.org/tools/install) 1.70 or higher

```bash
# Clone the repository
git clone https://github.com/itsrishub/logster.git
cd logster

# Build release version
cargo build --release

# The binary will be at ./target/release/logster
```

For cross-platform builds:

```bash
# Linux x86_64
cargo build --release --target x86_64-unknown-linux-gnu

# Linux ARM64
cargo build --release --target aarch64-unknown-linux-gnu

# macOS Intel
cargo build --release --target x86_64-apple-darwin

# macOS Apple Silicon
cargo build --release --target aarch64-apple-darwin

# Windows
cargo build --release --target x86_64-pc-windows-msvc
```

## Usage

### Basic Commands

```bash
# Analyze log files and show statistics
logster /var/log/apache2/access.log --stats

# Search for specific patterns
logster /var/log/nginx/*.log --search "404|500" --case-sensitive

# Extract errors and warnings
logster /var/log/syslog --errors

# Filter by time range
logster app.log --start-time "2024-01-01T00:00:00Z" --end-time "2024-01-02T00:00:00Z"

# Export results to JSON
logster access.log --search "bot" --export results.json --export-format json
```

### Advanced Examples

#### Analyze Multiple Files
```bash
logster /var/log/apache2/access.log* /var/log/nginx/*.log --stats
```

#### Group Logs by IP Address
```bash
logster access.log --group-by "(\d+\.\d+\.\d+\.\d+)"
```

#### Extract Errors and Export to CSV
```bash
logster application.log --errors --export errors.csv --export-format csv
```

#### Complex Time-based Analysis
```bash
logster server.log \
  --start-time "2024-01-15T09:00:00Z" \
  --end-time "2024-01-15T17:00:00Z" \
  --search "timeout|connection reset" \
  --stats
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `files` | Log files to analyze (required) |
| `--search PATTERN` | Search for pattern in logs |
| `--errors` | Extract errors and warnings |
| `--stats` | Show comprehensive statistics |
| `--start-time TIME` | Filter logs from this time (ISO format) |
| `--end-time TIME` | Filter logs until this time (ISO format) |
| `--export FILE` | Export results to file |
| `--export-format FORMAT` | Export format: json, csv, or text (default: json) |
| `--group-by PATTERN` | Group logs by regex pattern |
| `--case-sensitive` | Enable case-sensitive search |

## Output Examples

### Statistics Output
```
==================================================
LOG STATISTICS
==================================================
Total log entries: 150234
Files processed: 3
Errors/Warnings: 423

Log formats detected:
  apache_combined: 100543
  nginx: 45234
  json: 4457

Top HTTP status codes:
  200: 120543
  404: 15234
  500: 523

Top IP addresses:
  192.168.1.100: 5234 requests
  10.0.0.50: 3421 requests
```

### Error Extraction Output
```
Found 156 errors/warnings:
  [ERROR] Database connection timeout at 2024-01-15 10:23:45
  [WARNING] High memory usage detected (85%)
  [CRITICAL] Service health check failed
  ... and 153 more errors/warnings
```

## Project Structure

```
logster/
├── src/
│   └── main.rs          # Rust implementation
├── Cargo.toml           # Rust dependencies
├── build.bash           # Build script
├── .github/
│   └── workflows/
│       └── release.yml  # GitHub Actions workflow
└── README.md
```

### Development

```bash
# Run tests
cargo test

# Run with debug output
RUST_LOG=debug cargo run -- test.log --stats

# Format code
cargo fmt

# Run clippy
cargo clippy
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see below for details:

```
MIT License

Copyright (c)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Support

- [Report bugs](https://github.com/itstishub/logster/issues)
- [Request features](https://github.com/xy0ke/logster/issues)
