# bash completion for system-suite

_system_suite_completion() {
    local cur prev words cword
    _init_completion || return

    local commands="info cleanup update backup monitor speed service battery logs find time edit completion man help version"
    local options="--yes -y --dry-run --help -h --version -v --non-interactive"

    if [[ ${cword} -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "${commands} ${options}" -- "${cur}") )
        return 0
    fi

    case "${words[1]}" in
        completion)
            COMPREPLY=( $(compgen -W "bash zsh" -- "${cur}") )
            return 0
            ;;
        cleanup|update|backup)
            COMPREPLY=( $(compgen -W "--yes -y --dry-run" -- "${cur}") )
            return 0
            ;;
        *)
            COMPREPLY=( $(compgen -W "${options}" -- "${cur}") )
            return 0
            ;;
    esac
}

complete -F _system_suite_completion system-suite system_suite.sh
