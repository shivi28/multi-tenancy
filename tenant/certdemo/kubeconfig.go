package certdemo

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"k8s.io/client-go/util/cert"
	"strings"
)

const (
	kubeconfigTemplate = `
kind: Config
apiVersion: v1
users:
- name: {{ .username }}
  user:
    client-certificate-data: {{ .cert }}
    client-key-data: {{ .key }}
clusters:
- name: {{ .cluster }}
  cluster:
    certificate-authority-data: {{ .ca }}
    server: {{ .master }}
contexts:
- context:
    cluster: {{ .cluster }}
    user: {{ .username }}
  name: default
current-context: default
preferences: {}
`
)

type CrtKeyPair struct {
	Crt *x509.Certificate
	Key *rsa.PrivateKey
}

func GenerateKubeconfig(user, clusterName, apiserverDomain string, groups []string, rootCA *CrtKeyPair) (string, error) {
	caPair, err := NewClientCrtAndKey(user, rootCA, groups)
	if err != nil {
		return "", err
	}
	return generateKubeconfigUseCertAndKey(clusterName,
		[]string{apiserverDomain}, rootCA.Crt, caPair, user)
}

func NewClientCrtAndKey(user string, ca *CrtKeyPair, groups []string) (*CrtKeyPair, error) {
	cig := cert.Config{
		CommonName:   user,
		Organization: groups,
		Usages:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	config := &CertConfig{
		Config:             cig,
		PublicKeyAlgorithm: 0,
	}

	crt, key, err := NewCertAndKey(ca.Crt, ca.Key, config)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("fail to assert rsa private key")
	}

	return &CrtKeyPair{crt, rsaKey}, nil
}


// encodeCertPEM encodes x509 certificate to pem
func encodeCertPEM(cert *x509.Certificate) []byte {
	block := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return pem.EncodeToMemory(&block)
}

// encodePrivateKeyPEM encodes rsa key to pem
func encodePrivateKeyPEM(private *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Bytes: x509.MarshalPKCS1PrivateKey(private),
		Type:  "RSA PRIVATE KEY",
	})
}

// generateKubeconfigUseCertAndKey generates kubeconfig based on the given crt/key pair
func generateKubeconfigUseCertAndKey(clusterName string, ips []string, apiserverCA *x509.Certificate, caPair *CrtKeyPair, username string) (string, error) {
	urls := make([]string, 0, len(ips))
	for _, ip := range ips {
		urls = append(urls, fmt.Sprintf("%+v", ip))
	}
	ctx := map[string]string{
		"ca":       base64.StdEncoding.EncodeToString(encodeCertPEM(apiserverCA)),
		"key":      base64.StdEncoding.EncodeToString(encodePrivateKeyPEM(caPair.Key)),
		"cert":     base64.StdEncoding.EncodeToString(encodeCertPEM(caPair.Crt)),
		"username": username,
		"master":   strings.Join(urls, ","),
		"cluster":  clusterName,
	}

	return getTemplateContent(kubeconfigTemplate, ctx)
}

// getTemplateContent fills out the kubeconfig templates based on the context
func getTemplateContent(kubeConfigTmpl string, context interface{}) (string, error) {
	t, tmplPrsErr := template.New("test").Parse(kubeConfigTmpl)
	if tmplPrsErr != nil {
		return "", tmplPrsErr
	}
	writer := bytes.NewBuffer([]byte{})
	if err := t.Execute(writer, context); nil != err {
		return "", err
	}

	return writer.String(), nil
}
