#!/usr/bin/env bash
set -euo pipefail

# Will attempt to install hashcat via package manager, and fall back to upstream binary.

INSTALL_PREFIX="/opt/hashcat"
SYMLINK="/usr/local/bin/hashcat"
TMPDIR="$(mktemp -d)"
GH_BASE="https://hashcat.net/hashcat/"
UPSTREAM_BASE="https://hashcat.net/files"

cleanup() {
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

echo "==> Detecting distro..."
if [ -f /etc/os-release ]; then
  . /etc/os-release
  DISTRO="${ID,,}"
  DISTRO_LIKE="${ID_LIKE:-}"
else
  echo "Cannot detect distro (/etc/os-release missing). Assuming generic Linux."
  DISTRO="unknown"
  DISTRO_LIKE=""
fi

install_via_apt() {
  echo "==> apt-based install (apt/dpkg)"
  apt update
  if apt-cache show hashcat >/dev/null 2>&1; then
    apt install -y hashcat || return 1
  else
    echo "hashcat package not found in APT repos."
    return 1
  fi
  return 0
}

install_via_dnf() {
  echo "==> dnf/yum-based install"
  if command -v dnf >/dev/null 2>&1; then
    dnf install -y hashcat || return 1
  else
    # older RHEL/CentOS might have yum
    yum install -y hashcat || return 1
  fi
  return 0
}

install_via_pacman() {
  echo "==> pacman (Arch) install"
  pacman -Sy --noconfirm hashcat || return 1
  return 0
}

install_from_upstream() {
  echo "==> Installing from upstream (hashcat.net)"
  mkdir -p "$INSTALL_PREFIX"
  cd "$TMPDIR"

  echo "Fetching latest stable filename from hashcat.net..."
  # attempt to fetch latest release filename (common pattern: hashcat-x.y.z.7z or .tar.gz)
  # We'll try to download hashcat-7.*.7z or .tar.gz; prefer tar.gz if available.
  # For reliability, try the latest release listed on the site (fallback to known pattern).
  # NOTE: this script downloads the tarball directly.
  # Common current format: hashcat-7.1.2.tar.gz  (may change over time)
  # Try a few likely filenames:
  CANDIDATES=(
    "hashcat-7.1.2.tar.gz"
    "hashcat-7.1.1.tar.gz"
    "hashcat-7.1.0.tar.gz"
    "hashcat-7.1.2.7z"
  )

  DL=""
  for f in "${CANDIDATES[@]}"; do
    url="$UPSTREAM_BASE/$f"
    if curl -fsSLI "$url" >/dev/null 2>&1; then
      DL="$url"
      break
    fi
  done

  if [ -z "$DL" ]; then
    echo "Couldn't find a known upstream filename automatically. Attempting to download latest via hashcat.net..."
    # Try to fetch index and parse; lightweight approach:
    if curl -fsSL "$GH_BASE" -o index.html; then
      # grep for filenames like hashcat-*.tar.gz or .7z and pick the first
      fname="$(grep -oE 'hashcat-[0-9]+\.[0-9]+\.[0-9]+\.(tar\.gz|7z)' index.html | head -n1 || true)"
      if [ -n "$fname" ]; then
        DL="$UPSTREAM_BASE/$fname"
      fi
    fi
  fi

  if [ -z "$DL" ]; then
    echo "Failed to determine upstream tarball. Aborting upstream install."
    return 1
  fi

  echo "Downloading $DL ..."
  curl -fsSL -o hashcat.tarball "$DL"

  echo "Extracting..."
  mkdir -p "$INSTALL_PREFIX"
  # handle .tar.gz and .7z
  if file hashcat.tarball | grep -q 'gzip'; then
    tar -xzf hashcat.tarball -C "$INSTALL_PREFIX" --strip-components=1
  else
    # require p7zip
    if ! command -v 7z >/dev/null 2>&1; then
      echo "7z required for .7z extraction. Installing p7zip..."
      if command -v apt >/dev/null 2>&1; then apt install -y p7zip-full; fi
      if command -v dnf >/dev/null 2>&1; then dnf install -y p7zip; fi
      if command -v pacman >/dev/null 2>&1; then pacman -S --noconfirm p7zip; fi
    fi
    7z x hashcat.tarball -o"$INSTALL_PREFIX"
    # Note: 7z extraction may create a subfolder; user should verify
  fi

  # create a symlink to the hashcat binary
  if [ -f "$INSTALL_PREFIX/hashcat" ]; then
    ln -fs "$INSTALL_PREFIX/hashcat" "$SYMLINK"
  elif [ -f "$INSTALL_PREFIX/hashcat.bin" ]; then
    ln -fs "$INSTALL_PREFIX/hashcat.bin" "$SYMLINK"
  elif [ -f "$INSTALL_PREFIX/hashcat64.bin" ]; then
    ln -fs "$INSTALL_PREFIX/hashcat64.bin" "$SYMLINK"
  else
    # try to find any executable in folder named hashcat*
    exe="$(find "$INSTALL_PREFIX" -maxdepth 2 -type f -executable -name 'hashcat*' | head -n1 || true)"
    if [ -n "$exe" ]; then
      ln -fs "$exe" "$SYMLINK"
    else
      echo "Could not find a hashcat executable after extracting. Inspect $INSTALL_PREFIX."
      return 1
    fi
  fi

  echo "Upstream hashcat installed to $INSTALL_PREFIX and symlinked to $SYMLINK."
  return 0
}

echo "Detected: $DISTRO (like: $DISTRO_LIKE)"

INSTALLED=1
case "$DISTRO" in
  kali|debian|ubuntu|linuxmint)
    if install_via_apt; then INSTALLED=0; fi
    ;;
  fedora|rhel|centos)
    if install_via_dnf; then INSTALLED=0; fi
    ;;
  arch|manjaro)
    if install_via_pacman; then INSTALLED=0; fi
    ;;
  *)
    # attempt to infer from ID_LIKE
    if echo "$DISTRO_LIKE" | grep -qi "debian"; then
      if install_via_apt; then INSTALLED=0; fi
    elif echo "$DISTRO_LIKE" | grep -qi "rhel"; then
      if install_via_dnf; then INSTALLED=0; fi
    elif echo "$DISTRO_LIKE" | grep -qi "arch"; then
      if install_via_pacman; then INSTALLED=0; fi
    else
      echo "Unknown distro: attempting upstream install."
    fi
    ;;
esac

if [ "$INSTALLED" -ne 0 ]; then
  echo "Package install didn't run or failed — falling back to upstream."
  if ! install_from_upstream; then
    echo "All install methods failed. Exiting."
    exit 2
  fi
fi

echo "==> Post-install checks"

if ! command -v hashcat >/dev/null 2>&1; then
  echo "hashcat binary not in PATH. If you installed upstream, confirm $SYMLINK exists or add $INSTALL_PREFIX to PATH."
  echo "ls -lah $INSTALL_PREFIX"
  exit 1
fi

echo "hashcat version:"
hashcat --version || true

echo
echo "List detected OpenCL/CUDA devices (hashcat -I):"
hashcat -I || true

echo
echo "If you want low-level OpenCL info, install clinfo and run:"
if ! command -v clinfo >/dev/null 2>&1; then
  echo "  sudo apt install -y clinfo   # or dnf/pacman equivalent"
else
  echo "  clinfo"
fi

echo
cat <<'EOF'
IMPORTANT:
 - Hashcat uses OpenCL (and optionally CUDA for NVIDIA). If you want GPU acceleration you MUST install the correct GPU drivers:
   * NVIDIA: install the proprietary NVIDIA driver from nvidia.com and the CUDA/OpenCL runtime as needed.
   * AMD: install AMD's drivers (Pro/OpenCL) from AMD's support site or use distribution packages.
 - On Kali, hashcat is packaged; GPU support still needs correct drivers. See Kali docs for NVIDIA installation.
 - If you get "No OpenCL platforms found" or no devices in `hashcat -I`, install GPU drivers / OpenCL runtime first.

References (official):
 - hashcat: https://hashcat.net/hashcat/ 
 - Kali docs: https://www.kali.org/tools/hashcat/ and NVIDIA drivers on Kali. 
EOF

echo "Done."
