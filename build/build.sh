#!/usr/bin/env bash
#
# Builds the enclave image file (EIF) of one commit and writes its measurements.
#
#   build/build.sh --release NAME --out DIR [--source DIR] [--no-cache]
#
#   --release  the name of the release: the tag that started the build, or `dev`.
#   --out      receives enclave.eif and measurements.json.
#   --source   a git work tree (default: the one this script is in). What is built is its
#              commit HEAD, not the files of the tree.
#   --no-cache build every stage anew (a second build to compare with the first).
#
# Prints measurements.json to the standard output; everything else goes to the standard error.
#
# Adapted from pickle-com/credential-enclave (builder/enclave-build.sh, Apache-2.0).
#
# The steps:
#   1. the commit: its files (`git archive HEAD`), its hash and its time (SOURCE_DATE_EPOCH);
#   2. the `enclave` program, compiled by build/Dockerfile.enclave in a BuildKit daemon of a
#      fixed version, exported as an image whose file times are the commit time;
#   3. the EIF, assembled and measured by the nitro-cli of build/Dockerfile.eif;
#   4. measurements.json: the release, the commit, PCR0, PCR1 and PCR2, and the digests of
#      every input (images, files of the commit, the files nitro-cli puts into the EIF, the
#      program).
#
# Needs bash, git and Docker with buildx (Linux x86_64, or Docker Desktop with Linux
# containers). Two builds of one commit give the same PCR0, PCR1 and PCR2, on any machine.
# They do not give the same EIF file: its metadata section holds the build time and is not
# measured.

set -euo pipefail

# BuildKit, fixed by digest.
BUILDKIT_IMAGE="moby/buildkit:v0.33.1@sha256:cec9f139f45e93c5c69c60f8b07cfad9f43f4ef6b6a6cd917527fea5ff2e3dea"
# The one architecture of an enclave.
PLATFORM="linux/amd64"
# The socket of the Docker daemon, as the daemon sees it. nitro-cli reads the enclave image
# through it.
DOCKER_SOCKET="${DOCKER_SOCKET:-/var/run/docker.sock}"

# Git Bash on Windows rewrites arguments that look like paths; the script converts the paths
# of this machine itself (native) and leaves the paths inside containers alone.
export MSYS_NO_PATHCONV=1

say() {
    printf 'build: %s\n' "$*" >&2
}

fail() {
    printf 'build: %s\n' "$*" >&2
    exit 1
}

usage() {
    sed -n '3,13p' "$0" | sed 's/^# \{0,1\}//'
}

# A path of this machine as the Docker client takes it.
native() {
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -w "$1"
    else
        printf '%s' "$1"
    fi
}

sha256_stdin() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum | cut -d ' ' -f 1
    else
        shasum -a 256 | cut -d ' ' -f 1
    fi
}

is_hex() {
    printf '%s' "$1" | grep -Eq "^[0-9a-f]{$2}\$"
}

# The digest of the first `FROM image@sha256:...` line of a Dockerfile.
from_digest() {
    sed -n 's/^FROM [^ ]*@sha256:\([0-9a-f]\{64\}\).*/\1/p' "$1" | head -n 1
}

PROCEDURE=$(cd "$(dirname "$0")" && pwd)
SOURCE=""
RELEASE=""
OUT=""
NO_CACHE=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --source) SOURCE="${2:-}"; shift 2 ;;
        --release) RELEASE="${2:-}"; shift 2 ;;
        --out) OUT="${2:-}"; shift 2 ;;
        --no-cache) NO_CACHE=1; shift ;;
        -h | --help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done
[ -n "$RELEASE" ] && [ -n "$OUT" ] || { usage >&2; exit 2; }
[ -n "$SOURCE" ] || SOURCE="$PROCEDURE/.."

case "$RELEASE" in
    "" | *[!A-Za-z0-9._-]*) fail "the release name $RELEASE holds a character outside A-Z a-z 0-9 . _ -" ;;
esac

command -v git >/dev/null 2>&1 || fail "git is not installed"
command -v docker >/dev/null 2>&1 || fail "docker is not installed"
docker buildx version >/dev/null 2>&1 || fail "docker buildx is not available"

SOURCE=$(cd "$SOURCE" && pwd)
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)

# ---- 1. The commit.

# The build takes the files of the commit. A work tree that differs from it would give
# measurements of something the tree does not show.
git -C "$SOURCE" diff --quiet HEAD -- ||
    fail "the work tree has uncommitted changes: commit them first (the build takes HEAD)"
GIT_COMMIT=$(git -C "$SOURCE" rev-parse --verify HEAD)
SHORT_COMMIT=$(printf '%s' "$GIT_COMMIT" | cut -c 1-12)
SOURCE_DATE_EPOCH=$(git -C "$SOURCE" log -1 --format=%ct HEAD)
committed() {
    git -C "$SOURCE" cat-file blob "$GIT_COMMIT:$1"
}
say "release $RELEASE, commit $GIT_COMMIT, commit time $SOURCE_DATE_EPOCH"

NODE_IMAGE="credentials-enclave:$SHORT_COMMIT"
TOOLS_IMAGE="credentials-eif-tools:$(sha256_stdin <"$PROCEDURE/Dockerfile.eif" | cut -c 1-12)"
BUILDER="credentials-enclave-$(printf '%s' "$BUILDKIT_IMAGE" | sed 's/.*@sha256:\(.\{12\}\).*/\1/')"

# The work directory is under the output directory: a Docker daemon in a virtual machine sees
# the directories shared with it, and the directory of temporary files is not always one.
WORK="$OUT/.work"
CONTAINER=""
cleanup() {
    [ -z "$CONTAINER" ] || docker rm --force "$CONTAINER" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT
rm -rf "$WORK"
mkdir -p "$WORK/empty"

# ---- The BuildKit daemon, of the fixed version, in a container of its own.

if ! docker buildx inspect "$BUILDER" >/dev/null 2>&1; then
    say "creating the BuildKit builder $BUILDER"
    docker buildx create --name "$BUILDER" --driver docker-container \
        --driver-opt "image=$BUILDKIT_IMAGE" >/dev/null
fi
docker buildx inspect --bootstrap "$BUILDER" >/dev/null

# ---- 2. The enclave program and its image.

# The stage `image` is never taken from the layer cache: BuildKit finds a cached copy of it by
# the bytes of the program, so a commit whose program has the bytes of an earlier build would
# get the layer of that build, with that build's time (`rewrite-timestamp` lowers later times
# to the commit time and leaves earlier ones).
CACHE_OPTIONS=(--no-cache-filter image)
[ -z "$NO_CACHE" ] || CACHE_OPTIONS=(--no-cache)

say "building the enclave image $NODE_IMAGE"
git -C "$SOURCE" archive --format=tar "$GIT_COMMIT" | docker buildx build \
    --builder "$BUILDER" \
    --platform "$PLATFORM" \
    --provenance=false \
    --sbom=false \
    "${CACHE_OPTIONS[@]}" \
    --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
    --file build/Dockerfile.enclave \
    --target image \
    --output "type=docker,name=$NODE_IMAGE,rewrite-timestamp=true" \
    - >&2

CONTAINER=$(docker create --platform "$PLATFORM" "$NODE_IMAGE")
docker cp "$CONTAINER:/enclave" "$(native "$WORK/enclave")" >&2
docker rm "$CONTAINER" >/dev/null
CONTAINER=""
binary=$(sha256_stdin <"$WORK/enclave")
say "enclave program: sha256 $binary"

# ---- 3. The EIF and its measurements.

say "building the assembly tools $TOOLS_IMAGE"
docker buildx build \
    --builder "$BUILDER" \
    --platform "$PLATFORM" \
    --provenance=false \
    --sbom=false \
    --file "$(native "$PROCEDURE/Dockerfile.eif")" \
    --output "type=docker,name=$TOOLS_IMAGE" \
    "$(native "$WORK/empty")" >&2

say "assembling the enclave image file"
CONTAINER=$(docker create --platform "$PLATFORM" \
    --volume "$DOCKER_SOCKET:/var/run/docker.sock" \
    --env "NODE_IMAGE=$NODE_IMAGE" \
    "$TOOLS_IMAGE" sh -euc '
        mkdir -p /work /var/log/nitro_enclaves
        cd /work
        nitro-cli build-enclave --docker-uri "$NODE_IMAGE" --output-file enclave.eif >&2
        nitro-cli describe-eif --eif-path enclave.eif >describe-eif.json
        jq -e ".IsSigned == false" describe-eif.json >/dev/null
        for index in 0 1 2; do
            jq -er ".Measurements.PCR$index" describe-eif.json >"pcr$index"
        done
        cd /usr/share/nitro_enclaves/blobs
        sha256sum bzImage cmdline init linuxkit nsm.ko >/work/blobs.sha256
    ')
docker start --attach "$CONTAINER" >&2
docker cp "$CONTAINER:/work" "$(native "$WORK/assembly")" >&2
docker rm "$CONTAINER" >/dev/null
CONTAINER=""

pcr0=$(tr -d '\r\n' <"$WORK/assembly/pcr0")
pcr1=$(tr -d '\r\n' <"$WORK/assembly/pcr1")
pcr2=$(tr -d '\r\n' <"$WORK/assembly/pcr2")
for value in "$pcr0" "$pcr1" "$pcr2"; do
    is_hex "$value" 96 || fail "nitro-cli gave a measurement that is not 96 hex digits"
done

# ---- 4. The outputs.

buildkit_image=${BUILDKIT_IMAGE##*@sha256:}
rust_image=$(committed build/Dockerfile.enclave | sed -n 's/^FROM [^ ]*@sha256:\([0-9a-f]\{64\}\).*/\1/p' | head -n 1)
amazonlinux_image=$(from_digest "$PROCEDURE/Dockerfile.eif")
for value in "$buildkit_image" "$rust_image" "$amazonlinux_image" "$binary"; do
    is_hex "$value" 64 || fail "an input of the build has no SHA-256"
done

cp "$WORK/assembly/enclave.eif" "$OUT/enclave.eif"
{
    printf '{\n'
    printf '  "release": "%s",\n' "$RELEASE"
    printf '  "git_commit": "%s",\n' "$GIT_COMMIT"
    printf '  "pcr0": "%s",\n' "$pcr0"
    printf '  "pcr1": "%s",\n' "$pcr1"
    printf '  "pcr2": "%s",\n' "$pcr2"
    printf '  "inputs": {\n'
    printf '    "image/buildkit": "%s",\n' "$buildkit_image"
    printf '    "image/rust": "%s",\n' "$rust_image"
    printf '    "image/amazonlinux": "%s",\n' "$amazonlinux_image"
    for file in rust-toolchain.toml Cargo.toml Cargo.lock build/Dockerfile.enclave build/Dockerfile.eif build/build.sh; do
        printf '    "file/%s": "%s",\n' "$file" "$(committed "$file" | sha256_stdin)"
    done
    for blob in bzImage cmdline init linuxkit nsm.ko; do
        hash=$(awk -v name="$blob" '$2 == name { print $1 }' "$WORK/assembly/blobs.sha256")
        is_hex "$hash" 64 || fail "the blob $blob has no SHA-256"
        printf '    "blob/%s": "%s",\n' "$blob" "$hash"
    done
    printf '    "binary/enclave": "%s"\n' "$binary"
    printf '  }\n'
    printf '}\n'
} >"$OUT/measurements.json"

say "wrote $OUT/enclave.eif (sha256 $(sha256_stdin <"$OUT/enclave.eif"))"
say "wrote $OUT/measurements.json"
cat "$OUT/measurements.json"
