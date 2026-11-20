function __zrex_complete
    set -l tokens (commandline -opc)
    set -l current (commandline -ct)
    set -l candidates ($tokens[1] __complete $tokens[2..-1] "$current" 2>/dev/null)
    for candidate in $candidates
        printf '%s\n' $candidate
    end
end

complete -c zrex -f -a '(__zrex_complete)'
