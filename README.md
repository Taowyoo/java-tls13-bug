# Java tls 1.3 bug demo

## Dependencies

- JDK: >= 1.8
- Rust: stable
- maven

Command to install dependencies
```shell
sudo apt update -y
sudo apt install -y openjdk-11-jdk maven cargo
```

## Steps to reproduce

1. In a terminal, run `RUST_LOG=trace cargo run` under [rust-server-example](./rust-server-example/).
2. In another terminal, run `mvn test` under [java-client-example](./java-client-example/).
3. You could see the java test `testConnectWithDefaultProvider` failed. In comparison, test `testConnectWithOpenSSLProvider`succeed, it uses `org.conscrypt.OpenSSLProvider` as security provider.