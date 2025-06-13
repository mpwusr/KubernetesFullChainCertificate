## 1. 📄 What You Need
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
# A. 🧪 Verify Full Chain Works (CLI Test)
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
# B. 🔧 Java: Trust Full Chain
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
