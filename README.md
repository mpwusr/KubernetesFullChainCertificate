## 1.  What You Need
# You should collect the full PEM-encoded chain, e.g.:

```
openshift-full-chain.crt:
-----BEGIN CERTIFICATE-----
... root CA ...
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
... intermediate CA ...
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
... server cert (optional, usually not needed here) ...
-----END CERTIFICATE-----
This should mirror what's sent in TLS handshake — sometimes you’ll need to stitch this manually using OpenShift CA + issuer certs.
```
## How to Use It
# A.  Verify Full Chain Works (CLI Test)
```
curl --cacert openshift-full-chain.crt https://api.<cluster>:6443/version
```
# Should return a JSON response like:

```
{
  "major": "1",
  "minor": "27+",
  ...
}
```
# B.  Java: Trust Full Chain
# You can use a .crt file containing the entire chain. Here’s how to build a TrustManager:

```
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.security.KeyStore;
import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class SSLSocketFactoryUtil {
    public static javax.net.ssl.SSLSocketFactory fromFullChain(String chainPath) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (FileInputStream fis = new FileInputStream(chainPath)) {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            int i = 0;
            for (X509Certificate cert : (Iterable<X509Certificate>) () -> cf.generateCertificates(fis).iterator()) {
                ks.setCertificateEntry("cert" + i++, cert);
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);
            return sslContext.getSocketFactory();
        }
    }
}
```
In your client code:

```
OkHttpClient client = new OkHttpClient.Builder()
    .sslSocketFactory(SSLSocketFactoryUtil.fromFullChain("openshift-full-chain.crt"),
                      (X509TrustManager) tmf.getTrustManagers()[0])
    .build();
```
# C. Go: Load Full Chain into TLS Config
```
import (
    "crypto/tls"
    "crypto/x509"
    "io/ioutil"
    "net/http"
)

func createClientWithChain(chainPath string) *http.Client {
    certPool := x509.NewCertPool()
    chain, err := ioutil.ReadFile(chainPath)
    if err != nil {
        panic(err)
    }
    certPool.AppendCertsFromPEM(chain)

    tr := &http.Transport{
        TLSClientConfig: &tls.Config{RootCAs: certPool},
    }
    return &http.Client{Transport: tr}
}
```
# Then use:
```
client := createClientWithChain("openshift-full-chain.crt")
resp, err := client.Get("https://api.<cluster>:6443/version")
```
# D. Python Example (requests with full chain)
```
import requests

response = requests.get("https://api.<cluster>:6443/version", verify="openshift-full-chain.crt")
print(response.json())
```
## 1. Extract Full Chain from OpenShift API Server
```
openssl s_client -showcerts -connect api.your.openshift.domain:6443 </dev/null 2>/dev/null | \
awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/{ print $0 }' > openshift-full-chain.crt
```
# Explanation:
* s_client: Connects to the API server via TLS.
* -showcerts: Outputs all certs (leaf + intermediates).
* awk: Extracts only the PEM-formatted certificates.
* </dev/null: Ensures the connection closes cleanly.

# 2. Verify the PEM File Contains All Certs
```
openssl crl2pkcs7 -nocrl -certfile openshift-full-chain.crt | openssl pkcs7 -print_certs -noout
```
# You should see each certificate with a subject and issuer, like:
```
subject=/CN=api.your.openshift.domain
issuer=/C=US/O=Let's Encrypt/CN=R3

subject=/C=US/O=Let's Encrypt/CN=R3
issuer=/O=Internet Security Research Group/CN=ISRG Root X1
```
## If you don’t see the root, it’s likely your API server doesn’t send the full chain — see next section.

🛠# 3. If the Root CA Is Missing
You can manually append it from your local trust store or download it from the issuer (e.g., Let’s Encrypt, DigiCert, etc.):

Example for Let’s Encrypt:

```
curl https://letsencrypt.org/certs/isrgrootx1.pem >> openshift-full-chain.crt
```
# 4. Test the Full Chain with curl
```
curl --cacert openshift-full-chain.crt https://api.your.openshift.domain:6443/version
```
# Expected output:

```
{
  "major": "1",
  "minor": "27+",
  ...
}
```
## Optional: Clean Individual Certs
# To extract each cert individually:

```
csplit -f cert- openshift-full-chain.crt '/-----BEGIN CERTIFICATE-----/' '{*}'
```
# This creates:
```
cert-00

cert-01

```1

# Each as a single cert PEM file.

## Summary
* Extract full chain	openssl s_client -showcerts -connect <host>:<port>
* Save to file	Use awk or tee
* Verify full chain	openssl pkcs7 -print_certs -noout
* Append missing root cert	curl <root-issuer>.pem >> chain.crt
* Use in Java/Go/Python	Pass chain.crt as trusted CA bundle

