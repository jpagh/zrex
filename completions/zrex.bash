_zrex_complete()
{
    local candidate
    COMPREPLY=()
    while IFS= read -r candidate; do
        [ -n "$candidate" ] && COMPREPLY+=("$candidate")
    done < <("${COMP_WORDS[0]}" __complete "${COMP_WORDS[@]:1:COMP_CWORD}" 2>/dev/null)
}

complete -F _zrex_complete zrex
