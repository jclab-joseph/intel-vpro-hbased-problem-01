package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"github.com/jc-lab/intel-amt-host-api/pkg/pthi"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	var serverHash string
	var caFile string
	var certFile string
	var keyFile string

	flag.StringVar(&serverHash, "server-hash", "aac4a135dab25e93710aad805f82faaf7b98fac1b6c6ed3ff7c3a7a2a357f765", "provisioning server certificate sha256 hash")
	flag.StringVar(&caFile, "ca", "ca.crt", "ca certificate file")
	flag.StringVar(&certFile, "cert", "provisioning.crt", "provisioning certificate file")
	flag.StringVar(&keyFile, "key", "provisioning.key", "provisioning key file")

	flag.Parse()

	caRaw, err := os.ReadFile(caFile)
	if err != nil {
		log.Fatalln("ca certificate load failed: ", err)
	}
	block, _ := pem.Decode(caRaw)

	provisioningCertKeyPair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalln("load provisioning keypair failed: ", err)
	}
	provisioningCertKeyPair.Certificate = append(provisioningCertKeyPair.Certificate, block.Bytes)

	pthiInterface := pthi.NewCommand()
	if err := pthiInterface.Open(false); err != nil {
		log.Fatalln("pthi open failed: ", err)
	}
	defer pthiInterface.Close()

	// ==================== PRINT AMT VERSION ====================
	versionResult, err := pthiInterface.GetCodeVersions()
	if err != nil {
		log.Println("GetCodeVersions failed: ", err)
	} else {
		for i := 0; i < int(versionResult.CodeVersion.VersionsCount); i++ {
			key := string(versionResult.CodeVersion.Versions[i].Description.String[:versionResult.CodeVersion.Versions[i].Description.Length])
			value := strings.Replace(string(versionResult.CodeVersion.Versions[i].Version.String[:]), "\u0000", "", -1)
			switch key {
			case "AMT":
				log.Println("AMT Version: ", value)
			}
		}
	}

	// ==================== PRINT DNS SUFFIX ====================
	dnsSuffix, err := pthiInterface.GetDNSSuffix()
	if err != nil {
		log.Println("GetDNSSuffix failed: ", err)
	} else {
		log.Println("DNS SUFFIX: ", dnsSuffix)
	}

	// ==================== START HBASED CONFIGURATION ====================
	serverHashBin, err := hex.DecodeString(serverHash)
	if err != nil {
		log.Fatalln("serverHash parse failed: ", err)
	}

	// if already configuration mode
	status, err := pthiInterface.StopConfiguration()
	if status == pthi.AMT_STATUS_SUCCESS {
		log.Println("StopConfiguration. sleep 60s...")
		time.Sleep(time.Second * 60)
	}

	startResp, err := pthiInterface.StartConfigurationHBased(pthi.CERT_HASH_ALGORITHM_SHA256, serverHashBin, false, nil)
	if err != nil {
		log.Fatalln("StartConfigurationHBased failed: ", err)
	}
	if startResp.Header.Status != pthi.AMT_STATUS_SUCCESS {
		log.Fatalln("StartConfigurationHBased failed status=", startResp.Header.Status.String())
	}
	defer pthiInterface.StopConfiguration()

	log.Println("StartConfigurationHBased: AMT Cert Hash: ", hex.EncodeToString(startResp.AMTCertHash[:]))

	// ==================== MTLS ESTABLISHING ====================
	time.Sleep(time.Second)

	var conn net.Conn
	for retry := 0; retry < 30; retry++ {
		conn, err = net.Dial("tcp", "127.0.0.1:16993")
		if err == nil {
			break
		} else {
			log.Println("connect failed: ", err)
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		return
	}
	log.Println("tcp connected. start mtls...")
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "127.0.0.1",
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{provisioningCertKeyPair},
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			leaf := rawCerts[0]
			h := sha256.New()
			h.Write(leaf)
			amtHash := h.Sum(nil)

			log.Println("RECEIVED AMT HASH : ", hex.EncodeToString(amtHash))

			if bytes.Compare(amtHash, startResp.AMTCertHash[:len(amtHash)]) == 0 {
				log.Println("RECEIVED AMT HASH **MATCHED** :)")
			} else {
				log.Println("RECEIVED AMT HASH **NOT MATCHED** :(")
			}
			return nil
		},
	})

	if err = tlsConn.Handshake(); err != nil {
		log.Println("tls handshake failed: ", err)
		return
	}

	_, err = tlsConn.Write([]byte("GET / HTTP/1.1\n\n"))
	if err != nil {
		log.Println("TLS FAILURE: ", err)
	} else {
		log.Println("TLS SUCCESS")
	}
}
