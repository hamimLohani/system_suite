#compdef system-suite system_suite.sh

_system_suite() {
    local -a commands options

    commands=(
        'info:Show system information dashboard'
        'cleanup:Show cleanup targets; clean safe targets with --yes'
        'update:List package updates; update packages with --yes'
        'backup:Show backup sources; create backup with --yes'
        'monitor:Show top processes without prompting'
        'speed:Run network speed and latency test'
        'service:List and inspect system services'
        'battery:Show battery health and diagnostics'
        'logs:Display System Suite operation logs'
        'find:Search files interactively or by criteria'
        'time:Show current date, time, calendar, and uptime'
        'edit:Create or edit files with nvim/nano'
        'completion:Generate shell completion script (bash/zsh)'
        'man:View manual page or export roff documentation'
        'help:Show help message'
        'version:Show version information'
    )

    options=(
        '(-y --yes)'{-y,--yes}'[Confirm destructive or modifying actions]'
        '--dry-run[Preview cleanup actions without deleting]'
        '(-h --help)'{-h,--help}'[Show help]'
        '(-v --version)'{-v,--version}'[Show version]'
        '--non-interactive[Run in non-interactive batch mode]'
    )

    _arguments \
        '1: :->subcommand' \
        '*: :->args' \
        && return 0

    case $state in
        subcommand)
            _describe -t commands 'command' commands
            _describe -t options 'option' options
            ;;
        args)
            case $words[2] in
                completion)
                    local -a shells
                    shells=('bash:Generate Bash completion' 'zsh:Generate Zsh completion')
                    _describe -t shells 'shell' shells
                    ;;
                cleanup|update|backup)
                    _values 'options' \
                        '-y[Confirm action]' \
                        '--yes[Confirm action]' \
                        '--dry-run[Preview only]'
                    ;;
            esac
            ;;
    esac
}

_system_suite "$@"
