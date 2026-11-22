_zrex_complete()
{
    local candidate word trimmed escaped i last=0
    local current="${COMP_WORDS[COMP_CWORD]}"
    local quote=""
    local sq="'"
    local rep="'\\''"
    local rest="${COMP_LINE}"
    local -a words prior
    words=()
    prior=()
    COMPREPLY=()

    case $current in
        \"*)
            quote='"'
            current="${current#\"}"
            ;;
        \'*)
            quote="'"
            current="${current#\'}"
            ;;
    esac

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
        [ -z "$candidate" ] && continue
        case $quote in
            "'")
                escaped="${candidate//$sq/$rep}"
                COMPREPLY+=("'${escaped}'")
                ;;
            '"')
                escaped="${candidate//\\/\\\\}"
                escaped="${escaped//\"/\\\"}"
                escaped="${escaped//\$/\\\$}"
                escaped="${escaped//\`/\\\`}"
                COMPREPLY+=("\"${escaped}\"")
                ;;
            *)
                printf -v escaped '%q' "$candidate"
                COMPREPLY+=("$escaped")
                ;;
        esac
    done < <("${COMP_WORDS[0]}" __complete "$current" "${prior[@]}" 2>/dev/null)
}

complete -F _zrex_complete zrex
