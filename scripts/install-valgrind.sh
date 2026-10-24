#!/usr/bin/env bash
# Installs Valgrind, from the .deb files cached in $1 if they install, or
# else downloads them into $1 for the workflow to cache.
#
# apt fetches packages from one mirror and only gives up on a mirror that
# sends nothing: a trickling Azure mirror once held a 22 MB download for
# five minutes. So apt only names the packages and their SHA-2 sums,
# from its signed index, and curl fetches each from the first mirror that
# keeps up, verifying every file before dpkg installs it.
set -euo pipefail

debs=${1:?usage: install-valgrind.sh DIR}
mirrors=(
  http://azure.archive.ubuntu.com/ubuntu
  http://archive.ubuntu.com/ubuntu
  https://mirrors.edge.kernel.org/ubuntu
)

if compgen -G "$debs/*.deb" >/dev/null && sudo dpkg -i "$debs"/*.deb >/dev/null; then
  echo "Valgrind: installed from cache"
  exit 0
fi

rm -rf "$debs"
mkdir -p "$debs"
sudo apt-get -q -o Acquire::http::Timeout=20 -o Acquire::Retries=3 update >/dev/null
# Lines of: 'URI' file size SHA512:sum (or SHA256), for the packages not
# yet installed.
uris=$(sudo apt-get install -qq --print-uris --no-install-recommends valgrind)
[ -n "$uris" ] || { echo "Valgrind: nothing to download"; exit 0; }

# A line this script cannot fetch by itself (another repository layout, no
# SHA-2 sum) leaves the whole install to apt, slow mirrors and all, rather
# than failing the job; the line is printed so the script can learn it.
unexpected=0
while read -r uri file _ sum; do
  path=$(sed -E "s#^'.*/(pool/.*)'\$#\1#" <<<"$uri")
  if [[ $path != pool/* || ! ${sum%%:*} =~ ^SHA(512|256)$ ]]; then
    echo "Valgrind: unexpected package line: $uri $file $sum"
    unexpected=1
  fi
done <<<"$uris"
if (( unexpected )); then
  rm -rf "$debs"
  sudo apt-get install -y -q -o Acquire::http::Timeout=20 -o Acquire::Retries=3 \
    --no-install-recommends valgrind >/dev/null
  echo "Valgrind: installed by apt"
  exit 0
fi

while read -r uri file _ sum; do
  path=$(sed -E "s#^'.*/(pool/.*)'\$#\1#" <<<"$uri")
  case ${sum%%:*} in
    SHA512) check=sha512sum ;;
    *) check=sha256sum ;;
  esac
  for mirror in "${mirrors[@]}"; do
    # Give up on a mirror that drops below 100 KB/s for 15 seconds.
    if curl -fsSL --connect-timeout 10 --speed-limit 102400 --speed-time 15 --max-time 120 \
         -o "$debs/$file" "$mirror/$path" \
       && $check --quiet -c <<<"${sum#*:}  $debs/$file"; then
      echo "Valgrind: fetched $file from $mirror"
      continue 2
    fi
    rm -f "$debs/$file"
  done
  echo "Valgrind: no mirror served $file"
  exit 1
done <<<"$uris"

sudo dpkg -i "$debs"/*.deb >/dev/null
echo "Valgrind: installed"
