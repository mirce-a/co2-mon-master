package masterserver

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/mirce-a/co2-mon-master/services/mon-backend/master-server/handlers"
	"github.com/mirce-a/co2-mon-master/services/mon-backend/master-server/models"
)

const (
	BootstrapToken = "123456" // Hardcoded for now, perhaps find a better way to solve this in the future
	CA_Cert_File   = "ca.crt"
	CA_Key_File    = "ca.key"
)

type MasterServerClient struct {
	Client *http.Client
}

type MasterServer struct {
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey

	Client *http.Client
	Server *http.Server
	Mux    *http.ServeMux

	ConnectedDevices *[]models.Device
}

func NewMasterServer() *MasterServer {
	s := MasterServer{}
	s.loadCA()
	s.RegisterRoutes()
	s.InitiateClient()

	return &s
}

func (s *MasterServer) InitiateClient() {
	// 1. Load Master's certificate and key
	cert, err := tls.LoadX509KeyPair("master.crt", "master.key")
	if err != nil {
		log.Fatalf("Failed to load Master certs: %v", err)
	}

	// 2. Load CA cert so the Master can verify the Slave
	caCert, _ := os.ReadFile("ca.crt")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// 3. Create the mTLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		// Since we are using mDNS (.local), IP verification might fail
		// unless the cert has the correct SAN. For local testing:
		InsecureSkipVerify: true,
	}

	// 4. Create the client with the TLS config
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 5 * time.Second,
	}

	s.Client = client
}

func (s *MasterServer) RegisterRoutes() {
	s.Mux = http.NewServeMux()

	slaveHandler := &handlers.SlaveHandler{}

	s.Mux.HandleFunc("/onboard", s.handleOnboard)

	s.Mux.Handle("/api/slaves/search", slaveHandler)
	s.Mux.Handle("/api/slaves/search/", slaveHandler)

	s.Mux.Handle("/api/slaves/readco2", slaveHandler)
	s.Mux.Handle("/api/slaves/readco2/", slaveHandler)

	s.Mux.Handle("/api/slaves/connect", slaveHandler)
	s.Mux.Handle("/api/slaves/connect", slaveHandler)
}

func (s *MasterServer) ListenAndServe() {
	s.Server = &http.Server{
		Addr:    ":8080",
		Handler: s.Mux,
	}
	http.ListenAndServe(":8080", s.Mux)
}

func (s *MasterServer) loadCA() {
	// 1. Load the CA Certificate (ca.crt)
	caCertPEM, err := os.ReadFile(CA_Cert_File)
	if err != nil {
		log.Fatalf("Critical: Could not read CA cert file: %v", err)
	}

	block, _ := pem.Decode(caCertPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Fatal("Critical: Failed to decode PEM block containing CA certificate")
	}

	s.caCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("Critical: Failed to parse CA certificate: %v", err)
	}

	// 2. Load the CA Private Key (ca.key)
	caKeyPEM, err := os.ReadFile(CA_Key_File)
	if err != nil {
		log.Fatalf("Critical: Could not read CA key file: %v", err)
	}

	keyBlock, _ := pem.Decode(caKeyPEM)
	if keyBlock == nil || (keyBlock.Type != "RSA PRIVATE KEY" && keyBlock.Type != "PRIVATE KEY") {
		log.Fatal("Critical: Failed to decode PEM block containing CA private key")
	}

	// Try parsing as PKCS#1 (traditional RSA) or PKCS#8 (standard)
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		// If PKCS#1 fails, try PKCS#8
		genericKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			log.Fatalf("Critical: Failed to parse CA private key: %v", err)
		}
		s.caKey = genericKey.(*rsa.PrivateKey)
	} else {
		s.caKey = key
	}

	log.Println("CA successfully loaded. Ready to sign slave certificates.")
}

// func getCO2Data(slaveIP string) {

// 	// 5. Make the request to the Slave's secure port
// 	url := fmt.Sprintf("https://%s:8443/co2", slaveIP)
// 	resp, err := s.Client.Get(url)
// 	if err != nil {
// 		log.Printf("Error connecting to slave: %v", err)
// 		return
// 	}
// 	defer resp.Body.Close()

// 	body, _ := io.ReadAll(resp.Body)
// 	fmt.Printf("Data from Slave: %s\n", string(body))
// }

func (s *MasterServer) handleOnboard(w http.ResponseWriter, r *http.Request) {
	// Security Check: Validate Bootstrap Token
	if r.Header.Get("Authorization") != BootstrapToken {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Read the CSR sent by the Slave
	csrBytes, _ := io.ReadAll(r.Body)
	fmt.Printf("CSR BYTES: %+v\n", csrBytes)
	if len(csrBytes) == 0 {
		http.Error(w, "Must provide CSR", http.StatusBadRequest)
		return
	}
	block, _ := pem.Decode(csrBytes)
	clientCSR, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		http.Error(w, "Invalid CSR", http.StatusBadRequest)
		return
	}

	// Create a new signed Certificate for the Slave
	sn, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: sn,
		Subject:      clientCSR.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0), // Valid for 1 year
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certBytes, _ := x509.CreateCertificate(rand.Reader, &template, s.caCert, clientCSR.PublicKey, s.caKey)

	// Send the signed cert back to Slave
	pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
}
