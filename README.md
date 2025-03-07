# CRI Proxy

CRI Proxy is a gRPC proxy server for Kubernetes Container Runtime Interface (CRI) that supports multiple runtime classes. It allows you to route CRI requests to different runtime endpoints based on the runtime class specified in the request.

## Features

- Supports multiple runtime classes
- Reuses gRPC connections for efficiency
- Supports Unix, vsock, and TCP endpoints
- TLS support for secure communication

## Project Structure

```
.
├── go.mod
├── go.sum
├── main.go
└── main_test.go
```

## Getting Started

### Prerequisites

- Go 1.20 or later
- Kubernetes CRI API
- gRPC

### Installation

1. Clone the repository:

   ```sh
   git clone https://github.com/ericvh/cri-proxy.git
   cd cri-proxy
   ```

2. Build the project:

   ```sh
   go build -o cri-proxy main.go
   ```

### Configuration

Create a `config.yaml` file with the following structure:

```yaml
runtimes:
  default: "unix:///var/run/default.sock"
  runtimeClass1: "tcp://127.0.0.1:1234"
  runtimeClass2: "vsock://2:1234"
tls:
  cert: "/path/to/cert.pem"
  key: "/path/to/key.pem"
  ca: "/path/to/ca.pem"
```

### Running the Proxy

Start the CRI Proxy server:

```sh
./cri-proxy
```

The server will listen on `/var/run/cri-proxy.sock` by default.

## Usage

The CRI Proxy server will route CRI requests to the appropriate runtime endpoint based on the runtime class specified in the request.

## Running Tests

To run the tests, use the following command:

```sh
go test -v
```

This will execute the tests defined in `main_test.go` and provide detailed output.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
