# TLS-Benchmarks

### Not Reusing

| Backend         | Machine | Client Threads | Server Threads | Mean Latency (μs) | Mean Bandwidth (req/s) |
| --------------- | ------- | -------------- | -------------- | ----------------- | ---------------------- |
| Pico MiniCrypto | CICD    | 1              | 1              | 11,336.9          | 88.1                   |
| Pico OpenSSL    | CICD    | 1              | 1              | 4,439.6           | 225.1                  |
| Python OpenSSL  | CICD    | 1              | 1              | 8,563.9           | 116.7                  |
| Raw OpenSSL     | CICD    | 1              | 1              | 4768.2            | 209.1                  |
| Raw LibreSSL    | CICD    | 1              | 1              | 3287.9            | 304.2                  |
| Raw BoringSSL   | CICD    | 1              | 1              | 5843.3            | 171.0                  |

### Reusing

| Backend        | Machine | Client Threads | Server Threads | Mean Latency (μs) | Mean Bandwidth (req/s) |
| -------------- | ------- | -------------- | -------------- | ----------------- | ---------------------- |
| Python OpenSSL | CICD    | 1              | 1              | 43.9              | 23231.7                |
| Raw OpenSSL    | CICD    | 1              | 1              | 33.9              | 29832.4                |
| Raw LibreSSL   | CICD    | 1              | 1              | 32.9              | 30294.2                |
| Raw BoringSSL  | CICD    | 1              | 1              | 41.9              | 24132.2                |
