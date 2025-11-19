# System Suite v1.0.0

A comprehensive terminal-based system maintenance and monitoring toolkit for macOS, Linux, and Unix-like systems.

## Features

### 🖥️ System Monitoring
- **System Info Dashboard** - Complete system overview with CPU, memory, disk, and network stats
- **Process Monitor & Killer** - View running processes with htop or fallback to ps, kill processes
- **Battery Health** - Check battery status and health (macOS/Linux with upower)
- **Alert Check** - Monitor disk usage and system thresholds

### 🧹 System Maintenance
- **Disk Cleanup** - Clean temporary files, caches, logs, and development artifacts
- **Package Updates** - Update packages across multiple package managers
- **Cache Cleanup** - Remove orphaned packages and clean package caches

### 🌐 Network Tools
- **Internet Speed Test** - Multi-platform speed testing with native tools:
  - macOS: `networkQuality`
  - Linux: `speedtest-cli`, `fast-cli`
  - Universal: curl-based fallback
- **Latency Testing** - Ping multiple DNS servers for connection quality

### 📁 File Management
- **File Finder (fzf)** - Interactive file search with preview
- **File Editor (nvim)** - Create and edit files with Neovim
- **Log Analyzer** - View and filter system logs

### 🔧 System Services
- **Service Manager** - Start, stop, restart, and check system services
- **Backup Creator** - Create compressed backups of important directories

### ⏰ Utilities
- **Time & Date Display** - Current time, timezone, calendar, and uptime
- **View Logs** - Browse system suite operation logs

## Supported Systems

| OS | Package Manager | Speed Test | Services |
|---|---|---|---|
| macOS | Homebrew | networkQuality | launchctl |
| Linux | apt, dnf, yum, pacman, zypper | speedtest-cli, fast-cli | systemctl |
| WSL | apt, dnf, yum | speedtest-cli, fast-cli | systemctl |
| FreeBSD | pkg | speedtest-cli | - |
| OpenBSD | pkg | speedtest-cli | - |
| NetBSD | pkg | speedtest-cli | - |

## Installation

### Quick Start
```bash
# Clone or download the script
curl -O https://raw.githubusercontent.com/hamim-24/system_suite/system_suite.sh
chmod +x system_suite.sh
./system_suite.sh
```

### Dependencies

#### Required (Basic functionality)
- `bash` (4.0+)
- `curl` (for speed tests and updates)

#### Optional (Enhanced features)
```bash
# macOS
brew install htop fzf neovim speedtest-cli
npm install -g fast-cli

# Ubuntu/Debian
sudo apt update
sudo apt install htop fzf neovim speedtest-cli curl
npm install -g fast-cli

# CentOS/RHEL/Fedora
sudo dnf install htop fzf neovim speedtest-cli curl
npm install -g fast-cli

# Arch Linux
sudo pacman -S htop fzf neovim speedtest-cli curl
npm install -g fast-cli

# FreeBSD
sudo pkg install htop fzf neovim speedtest-cli curl
```

## Usage

### Interactive Mode (Default)
```bash
./system_suite.sh
```

### Non-Interactive Mode
```bash
# Run specific functions
./system_suite.sh --non-interactive info      # System info
./system_suite.sh --non-interactive cleanup   # Disk cleanup
./system_suite.sh --non-interactive update    # Package updates
./system_suite.sh --non-interactive backup    # Create backup
./system_suite.sh --non-interactive speed     # Speed test
./system_suite.sh --non-interactive monitor   # Process monitor
```

## Configuration

### Environment Variables
```bash
# Custom disk usage path
export SYSTEM_SUITE_DISK_PATH="/custom/path"

# Custom backup sources (space-separated)
export BACKUP_SOURCES="$HOME/Documents $HOME/Projects"
```

### File Locations
- **Config**: `~/.config/system_suite/`
- **Data**: `~/.local/share/system_suite/`
- **Logs**: `~/.local/share/system_suite/system_suite.log`
- **Backups**: `~/.local/share/system_suite/backups/`

## Speed Test Tools

### macOS
- **networkQuality** (built-in, macOS 12+) - Apple's native network quality tool
- **speedtest-cli** - Ookla's official CLI tool
- **fast-cli** - Netflix's speed test

### Linux/Unix
- **speedtest-cli** - Most reliable, works everywhere
- **fast-cli** - Netflix-based, requires Node.js
- **curl fallback** - Built-in alternative using test servers

### Installation Commands
```bash
# speedtest-cli
pip install speedtest-cli
# or via package manager (recommended)

# fast-cli
npm install -g fast-cli

# Alternative: Use built-in curl fallback (no installation needed)
```

## Package Manager Support

| Manager | Update | Install | Remove | Search | Clean |
|---------|--------|---------|--------|--------|-------|
| brew | ✅ | ✅ | ✅ | ✅ | ✅ |
| apt | ✅ | ✅ | ✅ | ✅ | ✅ |
| dnf | ✅ | ✅ | ✅ | ✅ | ✅ |
| yum | ✅ | ✅ | ✅ | ✅ | ✅ |
| pacman | ✅ | ✅ | ✅ | ✅ | ✅ |
| zypper | ✅ | ✅ | ✅ | ✅ | ✅ |
| pkg | ✅ | ✅ | ✅ | ✅ | ✅ |
| xbps | ✅ | ✅ | ✅ | ✅ | ✅ |
| apk | ✅ | ✅ | ✅ | ✅ | ✅ |

## File Finder Features

### Search Methods
1. **All files** - Interactive search with fzf
2. **By file type** - Text, code, config, images
3. **By pattern** - Wildcard matching
4. **Recent files** - Files modified in last 7 days

### File Actions
- Open with default application
- Show file information
- Copy path to clipboard
- Edit with Neovim

## Troubleshooting

### Permission Issues
```bash
# Fix Homebrew permissions (macOS)
sudo chown -R $(whoami) /opt/homebrew /usr/local/Homebrew

# Fix general permissions
sudo chown -R $(whoami) ~/.config ~/.local/share
```

### Missing Dependencies
The script will suggest installation commands for missing tools:
```bash
# Example output
No speed test tools available. Install speedtest-cli, fast-cli, or curl.

Installation suggestions:
  brew install speedtest-cli
  npm install -g fast-cli
```

### Log Files
Check logs for detailed error information:
```bash
tail -f ~/.local/share/system_suite/system_suite.log
```

## Advanced Usage

### Custom Backup Sources
Edit the script or set environment variable:
```bash
# In script (line ~1050)
backup_sources=("${HOME}/Documents" "${HOME}/Projects" "${HOME}/Pictures")

# Or via environment
export BACKUP_SOURCES="$HOME/Documents $HOME/Projects"
```

### Custom Cleanup Targets
Modify `get_cleanup_targets()` function to add custom directories.

### Keyboard Shortcuts
- **Ctrl+C** - Cancel current operation
- **ESC** - Exit fzf/interactive tools
- **Tab** - File path completion (where supported)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Test on multiple platforms
4. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Changelog

### v1.0.0
- Initial release
- Multi-platform support
- Native speed test tools
- Interactive file finder
- Comprehensive system monitoring
- Package manager integration