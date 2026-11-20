_zrex_complete()
{
    local candidate word trimmed i last=0
    local current="${COMP_WORDS[COMP_CWORD]}"
    local rest="${COMP_LINE}"
    local -a words prior
    words=()
    prior=()
    COMPREPLY=()

    # Bash splits URLs at ':' (and can split them at other word breaks).
    # Join adjacent pieces of finished words using their spacing in COMP_LINE.
    for (( i = 0; i < COMP_CWORD; i++ )); do
        word="${COMP_WORDS[i]}"
        trimmed="${rest#"${rest%%[![:space:]]*}"}"
        if [[ $trimmed != "$word"* ]]; then
            # The line may contain shell syntax outside this command.
            words=("${COMP_WORDS[@]:0:COMP_CWORD}")
            break
        fi
        if (( i == 0 )) || [[ $rest != "$trimmed" ]]; then
            last=${#words[@]}
            words[last]="$word"
        else
            words[last]+="$word"
        fi
        rest="${trimmed#"$word"}"
    done
    for word in "${words[@]:1}"; do
        case $word in
            \"*\"|\'*\') word="${word:1:${#word}-2}" ;;
        esac
        prior+=("$word")
    done
    while IFS= read -r candidate; do
        [ -n "$candidate" ] && COMPREPLY+=("$candidate")
    done < <("${COMP_WORDS[0]}" __complete "$current" "${prior[@]}" 2>/dev/null)
}

complete -F _zrex_complete zrex
