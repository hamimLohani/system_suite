# 💻 System Suite

> Terminal-based system maintenance, telemetry monitoring, and optimization toolkit — like `htop` + `ncdu` + `speedtest` + package manager in a single unified, zero-dependency CLI.

[![CI](https://github.com/hamimLohani/system_suite/actions/workflows/ci.yml/badge.svg)](https://github.com/hamimLohani/system_suite/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/hamimLohani/system_suite?style=flat-square&color=blue)](https://github.com/hamimLohani/system_suite/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)
[![Shell](https://img.shields.io/badge/bash-4.0%2B-informational?style=flat-square&logo=gnubash)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20BSD-lightgrey?style=flat-square)](https://github.com/hamimLohani/system_suite)
[![Homebrew](https://img.shields.io/badge/homebrew-hamimlohani%2Ftap-orange?style=flat-square&logo=homebrew)](https://github.com/hamimLohani/homebrew-tap)

```text
 ╔══════════════════════════════════════════════════════════════════════════════╗
 ║                             System Suite v1.3.1                              ║
 ║                                macOS :: arm64                                ║
 ║                       Created By :: Md Inzamamul Lohani                      ║
 ╚══════════════════════════════════════════════════════════════════════════════╝

 [1]  System Info Dashboard          [8]  Battery Health Monitor
 [2]  Process Monitor & Killer       [9]  Log Analyzer
 [3]  Disk Cleanup (Dry-Run / Yes)   [10] Check System Alerts
 [4]  Package Manager Updates        [11] View Suite Logs
 [5]  Network Speed Test (Native)    [12] Interactive File Finder (fzf)
 [6]  Network Latency Check          [13] Time, Calendar & Uptime
 [7]  Service Manager (systemd/launchd) [14] Create / Edit File (nvim)

 [0]  Exit
```

> 📺 **Watch the Walkthrough Demo**: [YouTube Demonstration](https://youtu.be/W2TKm4A-wA8)

---

## ✨ Key Features

### 🖥️ System Telemetry & Monitoring
| Feature | Details |
|---|---|
| **System Info Dashboard** | Complete telemetry view: CPU cores, memory utilization, mount capacity, network interfaces, IP addresses, and kernel version |
| **Process Monitor & Killer** | Interactive process inspection with `htop` (or fallback to formatted `ps`), with PID filtering and graceful termination |
| **Battery Health & Cycles** | Real-time cycle count, battery capacity, temperature, and charging status (`system_profiler` on macOS, `upower` on Linux) |
| **Threshold Alerts** | Automated warning indicators when disk usage, CPU temperature, or load exceed safe boundaries |

### 🧹 Storage & Safe Deep Cleanup
| Feature | Details |
|---|---|
| **Conservative Guardrails** | Never nukes root (`/`), `$HOME`, `/tmp`, or `/var/log` directly. Only cleans contents of safe application caches |
| **Developer Cache Cleaning** | Discovers and sweeps caches for `npm`, `yarn`, `gradle`, `cargo`, `maven`, `go/pkg/mod`, and Docker temporary files |
| **Browser & App Caches** | Purges cache artifacts for Chrome, Firefox, and Safari without touching preferences or saved sessions |
| **Preview Dry-Run** | Run `--dry-run` to inspect target directories and calculated reclaimable space before taking any action |

### 📦 Universal Package Maintenance
| Feature | Details |
|---|---|
| **Multi-Manager Support** | Native integration with `brew`, `apt`, `dnf`, `yum`, `pacman`, `zypper`, `pkg`, `xbps`, and `apk` |
| **Automated Upgrades** | Single command checks and updates all active package managers across the host system |
| **Orphan & Cache Sweep** | Purges unneeded dependencies, cached tarballs, and orphaned packages safely |

### 🌐 Network Performance & Speed Benchmarks
| Feature | Details |
|---|---|
| **Native Speed Tests** | Automatically leverages the fastest platform tool: Apple `networkQuality` on macOS 12+, `speedtest-cli`, or `fast-cli` |
| **Zero-Dependency Fallback** | Embedded `curl`-based bandwidth testing against low-latency CDN edge nodes if third-party tools are absent |
| **DNS Latency Matrix** | Parallel latency and reachability benchmarks against Cloudflare (1.1.1.1), Google (8.8.8.8), and Quad9 |

### 📁 File Discovery, Services & Backups
| Feature | Details |
|---|---|
| **Fuzzy File Search** | Interactive recursive search powered by `fzf` with integrated file previews, clipboard path copying, and Neovim integration |
| **Service Control** | Inspect, start, stop, and restart background daemons (`launchctl` on macOS, `systemctl` on Linux) |
| **Automated Backups** | Compressed `.tar.gz` archiving with checksum cataloging and customizable source folders via `BACKUP_SOURCES` |

---

## 🚀 Installation

### Option 1: Homebrew (macOS & Linux) — Recommended

```sh
brew tap hamimlohani/tap
brew install system-suite
```

Upgrade anytime:
```sh
brew upgrade system-suite
```

### Option 2: Standalone One-Liner (Zero Sudo Required)

Install the latest release directly to `/usr/local/bin` (or `~/.local/bin`):

```sh
curl -sSfL https://raw.githubusercontent.com/hamimLohani/system_suite/main/install.sh | sh
```

### Option 3: Debian / Ubuntu (`.deb` Package)

Download and install the official Debian package from the [Releases page](https://github.com/hamimLohani/system_suite/releases):

```sh
# Fetch latest .deb and install
curl -LO https://github.com/hamimLohani/system_suite/releases/latest/download/system-suite_1.3.1_all.deb
sudo dpkg -i system-suite_1.3.1_all.deb
```

### Option 4: From Source (with `make`)

```sh
git clone https://github.com/hamimLohani/system_suite.git
cd system_suite
make install          # installs binary to ~/.local/bin, man pages, and completions
```

---

## 🖥️ Usage

### Interactive Menu
Simply run without arguments:
```sh
system-suite
```

### Non-Interactive / Automation Mode (CLI & Cron)
Run individual commands directly without interactive prompts:

```sh
# System information dashboard
system-suite info

# Preview cleanup targets without touching any files
system-suite cleanup --dry-run

# Run safe cleanup in batch/cron mode
system-suite cleanup --yes

# Check and update all system package managers
system-suite update --yes

# Create a timestamped compressed backup
system-suite backup --yes

# Run network bandwidth and latency tests
system-suite speed

# Process monitor snapshot
system-suite monitor

# Battery health and charge cycle diagnostics
system-suite battery

# System services overview
system-suite service

# Audit log viewer
system-suite logs

# Current time, calendar, and uptime
system-suite time
```

### Shell Autocompletions

Tab-complete commands and options in your terminal:

```sh
# Zsh completion
system-suite completion zsh > ~/.zsh/completions/_system-suite

# Bash completion
system-suite completion bash > /etc/bash_completion.d/system-suite
```

### UNIX Manual Pages

```sh
# View formatted manual
man system-suite

# Or export roff man page
system-suite man man/
```

---

## ⚙️ Configuration & Environment

| Variable | Default | Description |
|---|---|---|
| `SYSTEM_SUITE_DISK_PATH` | `$HOME` (or `/`) | Target path/mount point used for capacity telemetry and disk alerts |
| `BACKUP_SOURCES` | `"$HOME/Documents $HOME/Projects"` | Space-delimited directories included in automated backups |
| `NO_COLOR` | `""` | Set to `1` or true to disable ANSI colors (auto-detected when piped) |
| `SYSTEM_SUITE_INSTALL_DIR` | `/usr/local/bin` | Override install target for `install.sh` |
| `SYSTEM_SUITE_NO_SUDO` | `0` | Set to `1` in `install.sh` to strictly install to `~/.local/bin` without `sudo` |

### System Locations
- **Configuration**: `~/.config/system_suite/`
- **Data & Metrics**: `~/.local/share/system_suite/`
- **Operational Logs**: `~/.local/share/system_suite/system_suite.log`
- **Backup Archives**: `~/.local/share/system_suite/backups/`

---

## 🏗️ Developer Tooling (`Makefile`)

The repository includes a comprehensive, self-documenting `Makefile` for streamlined development:

```sh
# Display all available targets
make help

# Validate script syntax and permissions
make build

# Run unit and integration smoke tests
make test

# Simulate bare CI environment
make test-ci

# Run ShellCheck with project rules
make lint

# Run lint + tests (CI gate)
make check

# Install binary, man page, and completions locally
make install

# Cleanly uninstall from system
make uninstall

# Build local Debian package
make deb

# Package release tarball + SHA256 checksums into dist/
make dist

# Tag and push version release
make tag VERSION=v1.3.1
```

---

## 🧪 Continuous Integration & Testing

| Environment | Checks Performed | Status |
|---|---|---|
| `ubuntu-latest` | ShellCheck linting · Smoke tests · Bare CI test · Dist packaging | ✅ Active |
| `macos-latest` | ShellCheck linting · macOS smoke tests · Path validation | ✅ Active |
| `release.yml` | Pre-flight tests · `.deb` build · Release archive · SHA256 checksums | ✅ Tag-triggered |

Run local quality checks before pushing:
```sh
make check
```

---

## 📁 Repository Structure

```text
system_suite/
├── Makefile                     Self-documenting developer targets (build, test, lint, install, dist)
├── README.md                    Project showcase and documentation
├── LICENSE                      MIT License
├── UPDATING.md                  Step-by-step release playbook
├── install.sh                   POSIX one-liner curl installer
├── system_suite.sh              Main executable toolkit script
├── .shellcheckrc                Linting rules and suppression filters
├── .github/
│   └── workflows/
│       ├── ci.yml               Automated matrix testing (macOS & Ubuntu)
│       └── release.yml          Tag push → test → debian pkg → tarball → release
├── completions/
│   ├── system-suite.bash        Native Bash completion script
│   └── system-suite.zsh         Native Zsh completion script
├── man/
│   └── system-suite.1           UNIX manual page (roff format)
└── test/
    └── smoke.sh                 Cross-platform CLI validation suite
```

---

## 🤝 Contributing

1. Fork the repository and clone your fork.
2. Run `make check` to ensure your environment is clean.
3. Implement your feature or fix.
4. Follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `refactor:`, `perf:`).
5. Ensure `make check` passes with zero warnings.
6. Open a Pull Request.

---

## 📜 License

MIT License © [Hamim Lohani](https://github.com/hamimLohani)
