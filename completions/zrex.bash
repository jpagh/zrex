_zrex_complete()
{
    local candidate
    local current="${COMP_WORDS[COMP_CWORD]}"
    local -a prior
    COMPREPLY=()
    if (( COMP_CWORD > 1 )); then
        prior=("${COMP_WORDS[@]:1:COMP_CWORD-1}")
    fi
    while IFS= read -r candidate; do
        [ -n "$candidate" ] && COMPREPLY+=("$candidate")
    done < <("${COMP_WORDS[0]}" __complete "$current" "${prior[@]}" 2>/dev/null)
}

complete -F _zrex_complete zrex
