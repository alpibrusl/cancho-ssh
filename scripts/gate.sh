#!/bin/sh
# The gate (docs/design.md section 8): the checks a change must pass, cheapest first, stopping at the first that fails
# and saying which stage it was.
#
#   scripts/gate.sh [--cancho PATH] [--only STAGE] [--skip STAGE]...
#
#   --cancho PATH  the `cancho` to run the checks with (also $CANCHO; default: `cancho` on the path)
#   --only STAGE   run one stage
#   --skip STAGE   leave a stage out (more than once is allowed)
#
# Stages: fmt (`cancho fmt --check`), files (no source file over 2,000 lines), check (the package with the example,
# and with the bare probe), bare (the probe builds for aarch64-none-elf and its object calls nothing but its four
# drivers and the heap's bounds), store (the committed `.cancho-vcs` is what `cancho vcs publish --dir src` writes, so a
# dependent that pins a commit gets these sources), tests (`cancho test` over tests/*_test.cho, with the number of tests each must
# pass), interop (scripts/interop.py: OpenSSH's client and others against examples/sshd), hostile (scripts/hostile.py:
# clients that misbehave), run (scripts/bare_run.py: the bare object, run on AArch64 under qemu, logged in to).
# interop and hostile need python3 with `cryptography` and OpenSSH's client; run also needs a cross compiler and
# qemu. A stage whose tools are missing fails, except run, which says that it was skipped.
# Exit status: 0 if every stage ran and passed, 1 if one failed, 2 for a bad call.
set -u
here=$(cd "$(dirname "$0")/.." && pwd)
cd "$here" || exit 2
cancho=${CANCHO:-cancho}
only=
skip=" "
stages="fmt files check bare store tests interop hostile run"
while [ $# -gt 0 ]; do
  case $1 in
    --cancho) cancho=$2; shift 2 ;;
    --only) only=$2; shift 2 ;;
    --skip) skip="$skip$2 "; shift 2 ;;
    *) echo "usage: gate.sh [--cancho PATH] [--only STAGE] [--skip STAGE]...   stages: $stages" >&2; exit 2 ;;
  esac
done
for s in $only $skip; do
  case " $stages " in *" $s "*) ;; *) echo "gate: no stage called $s ($stages)" >&2; exit 2 ;; esac
done
command -v "$cancho" >/dev/null 2>&1 || { echo "gate: no compiler: $cancho (give --cancho PATH)" >&2; exit 2; }
CANCHO=$cancho
export CANCHO

wanted() { [ -z "$only" ] && case "$skip" in *" $1 "*) return 1 ;; esac; [ -z "$only" ] || [ "$only" = "$1" ]; }
fail() { echo "gate: FAILED at stage $1" >&2; exit 1; }
stage() { echo "gate: $1" >&2; }

package="src/auth.cho src/channel.cho src/cipher.cho src/kex.cho src/server.cho src/sha256.cho src/slot.cho src/wire.cho"
probe="tests/probes/bare.cho examples/sshd/shell.cho $package"
mkdir -p build

if wanted fmt; then
  stage "fmt: cancho fmt --check"
  "$cancho" fmt --check src examples tests || fail fmt
fi

if wanted files; then
  stage "files: no source file over 2,000 lines"
  for f in src/*.cho examples/*/*.cho tests/*.cho tests/probes/*.cho; do
    n=$(wc -l < "$f")
    [ "$n" -le 2000 ] || { echo "gate: $f has $n lines" >&2; fail files; }
  done
fi

if wanted check; then
  stage "check: the package with the example, and with the bare probe"
  "$cancho" check examples/sshd/*.cho $package --std || fail check
  "$cancho" check $probe --std || fail check
fi

if wanted bare; then
  stage "bare: the probe for aarch64-none-elf, and what its object calls"
  "$cancho" build $probe --std --target aarch64-none-elf --emit ll -o build/bare.ll || fail bare
  # What the module calls and does not define, read from the module itself so that no AArch64 `nm` is needed. The
  # LLVM intrinsics are not calls of anything.
  calls=$(grep -o 'call [^@]*@[A-Za-z0-9_.]*' build/bare.ll | sed 's/.*@//' | sort -u)
  undefined=
  for name in $calls; do
    case $name in llvm.*) continue ;; esac
    grep -q "^define .*@$name(" build/bare.ll || undefined="$undefined $name"
  done
  [ "$undefined" = " board_key board_random board_receive board_send" ] || { echo "gate: the bare module calls and does not define:$undefined" >&2; fail bare; }
  "$cancho" build $probe --std --target aarch64-none-elf --emit obj -o build/bare.o || fail bare
  [ "$(od -An -tx1 -N4 build/bare.o | tr -d ' \n')" = "7f454c46" ] || { echo "gate: build/bare.o is not an ELF object" >&2; fail bare; }
fi

if wanted store; then
  stage "store: .cancho-vcs is what publishing src writes"
  fresh=build/store
  rm -rf "$fresh"
  "$cancho" vcs publish --std --dir src --store "$fresh" >/dev/null || fail store
  diff -r "$fresh" .cancho-vcs >/dev/null || { echo "gate: .cancho-vcs is stale: cancho vcs publish --std --dir src --store .cancho-vcs" >&2; fail store; }
fi

if wanted tests; then
  stage "tests: cancho test"
  # Each line: the test file, and how many tests it must pass. A file that passes fewer has lost one.
  while read -r file count; do
    [ -n "$file" ] || continue
    out=$("$cancho" test "$file" tests/support.cho $package --std 2>&1) || { echo "$out" >&2; fail tests; }
    echo "$out" | grep -q "test result: ok. $count passed; 0 failed" || { echo "$out" | tail -3 >&2; echo "gate: $file must pass $count tests" >&2; fail tests; }
  done <<LIST
tests/sha256_test.cho 5
tests/wire_test.cho 6
tests/cipher_test.cho 4
tests/server_test.cho 19
LIST
fi

if wanted interop; then
  stage "interop: real clients against examples/sshd"
  python3 scripts/interop.py || fail interop
fi

if wanted hostile; then
  stage "hostile: clients that misbehave"
  python3 scripts/hostile.py || fail hostile
fi

if wanted run; then
  stage "run: the bare object on AArch64, under qemu"
  python3 scripts/bare_run.py || fail run
fi

echo "gate: passed" >&2
