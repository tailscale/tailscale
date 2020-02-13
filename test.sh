#!/usr/bin/env bash

function remove_test_files {
    rm -f ./*test{,.exe}
}

function fail {
    printf '%s\n' "$1" >&2
    # If we fail, clean up after ourselves
    remove_test_files
    exit 1
}

function main {
    test_dirs=()
    while IFS= read -r -d '' file
    do
        dir=$(dirname "$file")
        if [[ ! " ${test_dirs[*]} " =~ ${dir} ]]; then
            test_dirs+=("$dir")
        fi
    done <   <(find . -type f -iname '*_test.go' -print0)

    for goos in openbsd darwin windows
    do
        for dir in "${test_dirs[@]}"; do
            echo "Testing GOOS=$goos in dir $dir"
            GOOS="$goos" go test -c "./$dir" || fail "Test failed using $goos and $dir"
        done
    done

    # If all goes well, we should still clean up the test files
    echo "Test complete"
    remove_test_files
}

main "$@"

