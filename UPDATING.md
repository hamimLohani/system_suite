# Updating System Suite

A step-by-step guide for releasing a new version.

---

## 1. Make Your Changes

Edit `system_suite.sh` and bump the version number near the top:

```bash
SCRIPT_VERSION="1.3.0"
```

---

## 2. Test Locally

```bash
cd /Users/Inz_mac/Developer/Shell/Project/system_suite

# Syntax check
bash -n system_suite.sh

# Run smoke tests
bash test/smoke.sh

# Simulate Ubuntu CI (bare environment)
env -i HOME="$HOME" PATH="/usr/bin:/bin:/usr/local/bin" bash test/smoke.sh
```

All three must pass before continuing.

---

## 3. Commit and Push to GitHub

```bash
git add -A
git commit -m "Release v1.3.0"
git push origin main
```

Wait for the CI checks on GitHub Actions to go green (ubuntu + macOS).

---

## 4. Create and Push the Version Tag

```bash
git tag v1.3.0
git push origin v1.3.0
```

This triggers the `build-deb.yml` workflow which builds the `.deb` package and uploads it as a GitHub release asset automatically.

---

## 5. Get the SHA256 of the GitHub Tarball

GitHub auto-generates a tarball when a tag is pushed. Wait ~30 seconds then run:

```bash
curl -sL https://github.com/hamimLohani/system_suite/archive/refs/tags/v1.3.0.tar.gz \
  -o /tmp/system-suite-v1.3.0.tar.gz

shasum -a 256 /tmp/system-suite-v1.3.0.tar.gz
```

Copy the hash from the output. It will look like:

```
b1f7cc1d9f189a88101fcd920372154bd0cc1fd6490da1a825a8a22ad1f95712  /tmp/...
```

> ⚠️ Always fetch this from GitHub — do **not** compute it from a local tarball. The hashes will differ.

---

## 6. Update the Homebrew Formula

Edit `/Users/Inz_mac/Developer/homebrew-tap/Formula/system-suite.rb`:

```ruby
class SystemSuite < Formula
  desc "Terminal-based system maintenance and monitoring toolkit"
  homepage "https://github.com/hamimLohani/system_suite"
  url "https://github.com/hamimLohani/system_suite/archive/refs/tags/v1.3.0.tar.gz"
  sha256 "paste_new_hash_here"
  license "MIT"
  version "1.3.0"

  depends_on "bash"

  def install
    bin.install "system_suite.sh" => "system-suite"
  end

  test do
    assert_match "System Suite v#{version}", shell_output("#{bin}/system-suite --version")
    system "#{bin}/system-suite", "--help"
  end
end
```

---

## 7. Commit and Push the Tap

```bash
cd /Users/Inz_mac/Developer/homebrew-tap

git add Formula/system-suite.rb
git commit -m "Update system-suite to v1.3.0"
git push origin main
```

---

## 8. Verify the Formula

```bash
brew update
brew upgrade hamimlohani/tap/system-suite
system-suite --version   # should print: System Suite v1.3.0
```

---

## Quick Checklist

| # | Step | Location |
|---|---|---|
| 1 | Bump `SCRIPT_VERSION` | `system_suite.sh` |
| 2 | Run smoke tests | `bash test/smoke.sh` |
| 3 | Commit and push code | `system_suite/` repo |
| 4 | Push tag | `git tag vX.X.X && git push origin vX.X.X` |
| 5 | Get SHA256 from GitHub tarball | `curl` + `shasum -a 256` |
| 6 | Update formula URL, sha256, version | `homebrew-tap/Formula/system-suite.rb` |
| 7 | Commit and push tap | `homebrew-tap/` repo |
| 8 | Verify with `brew upgrade` | Terminal |

---

## First-Time Install (for users)

```bash
brew tap hamimlohani/tap
brew trust hamimlohani/tap
brew install system-suite
```
