#!/bin/bash

# Env vars
PYTHON=${PYTHON:-$(which python)}

# Vars
_eblih_path="./eblih.py"
_user="${USER}"

# Constants
GIT_HOST="git.epitech.eu"
MOULINETTE="ramassage-tek"

# Utility functions
_script=$0
show_usage() {
    echo "Usage: ${_script} <command> [args...]"
}

show_help() {
    show_usage
    echo
    echo "Commands:"
    echo "  create      -   Create a repository and import it."
    echo "  import      -   Import a repository."
}

fn_exists() {
    type -t $1 | grep -q 'function'
}

# local repo_full="${repo_name}"
# if [[ "${repo_full}" != */* ]]; then
#     repo_full="${_user}/${repo_full}"
# fi
# echo "Full repo: ${repo_full}"

# Commands
bliny_create() {
    local repo_name="$1"
    local repo_dest="$2"

    set -e

    if [ -z "${repo_name}" ]; then
        echo "Empty repository name."
        exit 1
    fi

    if [ -z "${repo_dest}" ]; then
        repo_dest="${repo_name}"
    fi

    echo "Creating repository on server..."
    ${PYTHON} ${_eblih_path} repository create ${repo_name} > /dev/null 2>&1
    ${PYTHON} ${_eblih_path} repository setacl ${repo_name} ${MOULINETTE} r > /dev/null 2>&1

    echo "Cloning repository..."
    git clone ${_user}@${GIT_HOST}:/${_user}/${repo_name} ${repo_dest} > /dev/null 2>&1

    echo "Configuring repository..."
    cd ${repo_dest}
    # git init > /dev/null 2>&1

    git config user.name ${_user} > /dev/null 2>&1
    git config user.email "${_user}@epitech.eu" > /dev/null 2>&1

    cat > .gitignore <<EOF
*.o
*~
EOF

    cat > auteur <<EOF
${_user}
EOF

    git add .gitignore auteur > /dev/null 2>&1
    git commit -m "Initial commit." > /dev/null 2>&1

    set +e
}

bliny_import() {
    local repo_name="$1"
    local repo_dest="$2"

    if [ -z "${repo_dest}" ]; then
        repo_dest="${repo_name}"
    fi

    local repo_full="${repo_name}"
    if [[ "${repo_full}" != */* ]]; then
        repo_full="${_user}/${repo_full}"
    fi

    echo "Cloning repository..."
    git clone ${_user}@${GIT_HOST}:/${repo_full} ${repo_dest} > /dev/null 2>&1
}

# Parse args
while getopts "he:u:" name; do
    case $name in
        h)
            show_help
            exit 0
            ;;
        e)
            _eblih_path="${OPTARG}"
            ;;
        u)
            _user="${OPTARG}"
            ;;
    esac
done
shift $(($OPTIND - 1))

_command=$1
_command_fnname="bliny_${_command}"
shift

_args=$*

if [ -z "${_command}" ]; then
    show_usage
    exit 1
fi

if fn_exists ${_command_fnname}; then
    ${_command_fnname} ${_args}
else
    echo "Unknown command: ${_command}"
    show_help
    exit 1
fi