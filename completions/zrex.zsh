#compdef zrex

_zrex() {
  local candidate
  local -a candidates
  while IFS= read -r candidate; do
    [[ -n $candidate ]] && candidates+=("$candidate")
  done < <("${words[1]}" __complete "${words[2,-1]}" 2>/dev/null)
  compadd -- "${candidates[@]}"
}

compdef _zrex zrex
