package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/yaml.v2"
	cri "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// Config struct for runtime mappings and TLS settings
type Config struct {
	Runtimes map[string]string `yaml:"runtimes"`
	TLS      struct {
		Cert string `yaml:"cert"`
		Key  string `yaml:"key"`
		CA   string `yaml:"ca"`
	} `yaml:"tls"`
}

// CRIProxy implements both RuntimeService and ImageService
type CRIProxy struct {
	cri.UnimplementedRuntimeServiceServer
	cri.UnimplementedImageServiceServer
	config    Config
	connMutex sync.Mutex
	connPool  map[string]*grpc.ClientConn
}

// Load configuration from YAML
func loadConfig(path string) (Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	return cfg, err
}

// Get gRPC connection, reusing existing ones if available
func (p *CRIProxy) getGRPCConn(runtimeClass string) (*grpc.ClientConn, error) {
	p.connMutex.Lock()
	defer p.connMutex.Unlock()

	// Use cached connection if available
	if conn, exists := p.connPool[runtimeClass]; exists {
		return conn, nil
	}

	// Get endpoint for runtime class
	endpoint, exists := p.config.Runtimes[runtimeClass]
	if !exists {
		endpoint = p.config.Runtimes["default"]
	}

	if endpoint == "" {
		return nil, fmt.Errorf("no endpoint found for runtime class %s", runtimeClass)
	}

	var opts []grpc.DialOption

	switch {
	case endpoint[:5] == "unix:":
		opts = append(opts, grpc.WithInsecure(), grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout("unix", addr[5:], timeout)
		}))
	case endpoint[:6] == "vsock:":
		vsockAddr := fmt.Sprintf("vsock://%s", endpoint[6:])
		opts = append(opts, grpc.WithInsecure(), grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout("vsock", vsockAddr, timeout)
		}))
	case endpoint[:6] == "tcp://":
		myConfig := struct {
			Cert string
			Key  string
			CA   string
		}{
			Cert: p.config.TLS.Cert,
			Key:  p.config.TLS.Key,
			CA:   p.config.TLS.CA,
		}
		tlsConfig, err := loadTLSConfig(myConfig)
		if err != nil {
			return nil, err
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	default:
		return nil, fmt.Errorf("unsupported endpoint type for runtime class %s: %s", runtimeClass, endpoint)
	}

	// Create and cache connection
	conn, err := grpc.Dial(endpoint, opts...)
	if err != nil {
		return nil, err
	}
	p.connPool[runtimeClass] = conn

	return conn, nil
}

// Load TLS credentials
func loadTLSConfig(tlsConfig struct{ Cert, Key, CA string }) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(tlsConfig.Cert, tlsConfig.Key)
	if err != nil {
		return nil, err
	}
	caCert, err := ioutil.ReadFile(tlsConfig.CA)
	if err != nil {
		return nil, err
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	return &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: caPool}, nil
}

// Proxy function for RuntimeService
func (p *CRIProxy) proxyRuntime(ctx context.Context, req interface{}, runtimeClass string) (interface{}, error) {
	conn, err := p.getGRPCConn(runtimeClass)
	if err != nil {
		return nil, err
	}

	client := cri.NewRuntimeServiceClient(conn)
	switch request := req.(type) {
	case *cri.RunPodSandboxRequest:
		return client.RunPodSandbox(ctx, request)
	case *cri.StopPodSandboxRequest:
		return client.StopPodSandbox(ctx, request)
	case *cri.RemovePodSandboxRequest:
		return client.RemovePodSandbox(ctx, request)
	case *cri.CreateContainerRequest:
		return client.CreateContainer(ctx, request)
	case *cri.StartContainerRequest:
		return client.StartContainer(ctx, request)
	case *cri.StopContainerRequest:
		return client.StopContainer(ctx, request)
	case *cri.RemoveContainerRequest:
		return client.RemoveContainer(ctx, request)
	case *cri.ListContainersRequest:
		return client.ListContainers(ctx, request)
	case *cri.ContainerStatusRequest:
		return client.ContainerStatus(ctx, request)
	default:
		return nil, fmt.Errorf("unsupported runtime request")
	}
}

// Proxy function for ImageService
func (p *CRIProxy) proxyImage(ctx context.Context, req interface{}, runtimeClass string) (interface{}, error) {
	conn, err := p.getGRPCConn(runtimeClass)
	if err != nil {
		return nil, err
	}

	client := cri.NewImageServiceClient(conn)
	switch request := req.(type) {
	case *cri.PullImageRequest:
		return client.PullImage(ctx, request)
	case *cri.ListImagesRequest:
		return client.ListImages(ctx, request)
	case *cri.ImageStatusRequest:
		return client.ImageStatus(ctx, request)
	case *cri.RemoveImageRequest:
		return client.RemoveImage(ctx, request)
	default:
		return nil, fmt.Errorf("unsupported image request")
	}
}

// Implement RuntimeService
func (p *CRIProxy) RunPodSandbox(ctx context.Context, req *cri.RunPodSandboxRequest) (*cri.RunPodSandboxResponse, error) {
	res, err := p.proxyRuntime(ctx, req, req.RuntimeHandler)
	return res.(*cri.RunPodSandboxResponse), err
}

// Removed redundant proxyRuntime method

func (p *CRIProxy) CreateContainer(ctx context.Context, req *cri.CreateContainerRequest) (*cri.CreateContainerResponse, error) {
	res, err := p.proxyRuntime(ctx, req, req.Config.Metadata.Name)
	return res.(*cri.CreateContainerResponse), err
}

// Implement ImageService
func (p *CRIProxy) PullImage(ctx context.Context, req *cri.PullImageRequest) (*cri.PullImageResponse, error) {
	res, err := p.proxyImage(ctx, req, req.Image.Image)
	return res.(*cri.PullImageResponse), err
}

func (p *CRIProxy) RemoveImage(ctx context.Context, req *cri.RemoveImageRequest) (*cri.RemoveImageResponse, error) {
	res, err := p.proxyImage(ctx, req, req.Image.Image)
	return res.(*cri.RemoveImageResponse), err
}

// Close all gRPC connections on shutdown
func (p *CRIProxy) CloseConnections() {
	p.connMutex.Lock()
	defer p.connMutex.Unlock()
	for _, conn := range p.connPool {
		conn.Close()
	}
}

// Main function
func main() {
	configPath := "config.yaml"
	config, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	proxy := &CRIProxy{
		config:   config,
		connPool: make(map[string]*grpc.ClientConn),
	}

	grpcServer := grpc.NewServer()
	cri.RegisterRuntimeServiceServer(grpcServer, proxy)
	cri.RegisterImageServiceServer(grpcServer, proxy)

	listener, err := net.Listen("unix", "/var/run/cri-proxy.sock")
	if err != nil {
		log.Fatalf("Failed to listen on socket: %v", err)
	}

	log.Println("CRI Proxy started on /var/run/cri-proxy.sock")
	defer proxy.CloseConnections() // Ensure cleanup

	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("Failed to start gRPC server: %v", err)
	}
}
