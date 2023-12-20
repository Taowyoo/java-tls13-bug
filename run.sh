#!/bin/env bash

# run server
pushd rust-server-example
cargo run &
server_pid="$!"
echo "Rust TLS server is running at localhost:4443, pid: $server_pid"
popd

# setup server process cleaner
function cleanup()
{
    kill "$server_pid"
}
trap cleanup EXIT

pushd java-client-example
mvn test
popd
