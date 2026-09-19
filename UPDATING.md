# Updating & Releasing System Suite

A step-by-step playbook for testing, tagging, and releasing a new version of System Suite, aligned with modern open-source automation.

---

## 1. Prepare Changes & Bump Version

Edit `system_suite.sh` and update `SCRIPT_VERSION` near the top:

```bash
SCRIPT_VERSION="1.3.1"
```

Also verify the version in `man/system-suite.1`:

```roff
.TH "SYSTEM-SUITE" "1" "Sep 2026" "system-suite 1.3.1" "System Suite Manual"
```

---

## 2. Run Local Quality Assurance

Run the comprehensive pre-release checks using `Makefile`:

```bash
# Run linting + smoke tests
make check

# Simulate clean CI environment
make test-ci

# Verify release packaging
make dist
make clean
```

All commands must pass cleanly before proceeding.

---

## 3. Commit and Push to GitHub

```bash
git add -A
git commit -m "chore(release): prepare v1.3.1"
git push origin main
```

Ensure GitHub Actions CI completes green on both `ubuntu-latest` and `macos-latest`.

---

## 4. Create and Push the Release Tag

Trigger the automated release workflow with `make tag`:

```bash
make tag VERSION=v1.3.1
```

This pushes the tag `v1.3.1` to GitHub and triggers the `.github/workflows/release.yml` pipeline, which:
1. Validates all tests and ShellCheck rules.
2. Compiles the Debian `.deb` package with man pages and completions.
3. Packages the universal release tarball (`system-suite-v1.3.1.tar.gz`).
4. Generates SHA-256 `checksums.txt`.
5. Publishes a GitHub Release with auto-generated semantic release notes.

---

## 5. Update the Homebrew Formula

Once GitHub creates the release tarball, obtain its SHA-256 hash:

```bash
curl -sL https://github.com/hamimLohani/system_suite/archive/refs/tags/v1.3.1.tar.gz \
  -o /tmp/system-suite-v1.3.1.tar.gz

shasum -a 256 /tmp/system-suite-v1.3.1.tar.gz
```

Update `/Users/Inz_mac/Developer/homebrew-tap/Formula/system-suite.rb`:

```ruby
class SystemSuite < Formula
  desc "Terminal-based system maintenance and monitoring toolkit"
  homepage "https://github.com/hamimLohani/system_suite"
  url "https://github.com/hamimLohani/system_suite/archive/refs/tags/v1.3.1.tar.gz"
  version "1.3.1"
  sha256 "<PASTE_NEW_SHA256_HASH_HERE>"
  license "MIT"
  head "https://github.com/hamimlohani/system_suite.git", branch: "main"

  depends_on "bash"

  def install
    bin.install "system_suite.sh" => "system-suite"
    man1.install Dir["man/*.1"] if Dir.exist?("man")
    bash_completion.install "completions/system-suite.bash" => "system-suite" if File.exist?("completions/system-suite.bash")
    zsh_completion.install "completions/system-suite.zsh" => "_system-suite" if File.exist?("completions/system-suite.zsh")
  end

  test do
    assert_match "System Suite", shell_output("#{bin/"system-suite"} --version")
    system bin/"system-suite", "--help"
  end
end
```

Push the tap changes:

```bash
cd /Users/Inz_mac/Developer/homebrew-tap
git add Formula/system-suite.rb
git commit -m "feat(system-suite): update to v1.3.1"
git push origin main
```

---

## 6. Verify Installation

```bash
brew update
brew upgrade system-suite
system-suite --version
man system-suite
```
