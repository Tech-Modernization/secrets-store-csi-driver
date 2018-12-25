/*
Copyright 2014 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package testingcert

// You can use cfssl tool to generate certificates, please refer
// https://github.com/coreos/etcd/tree/master/hack/tls-setup for more details.
//
// ca-config.json:
//   expiry was changed from 1 year to 100 years (876000h)
// ca-csr.json:
//   ca expiry was set to 100 years (876000h) ("ca":{"expiry":"876000h"})
//   key was changed from ecdsa,384 to rsa,2048
// req-csr.json:
//   key was changed from ecdsa,384 to rsa,2048
//   hosts were changed to "localhost","127.0.0.1"
const CAFileContent = `
-----BEGIN CERTIFICATE-----
MIIEUDCCAzigAwIBAgIUKfV5+qwlw3JneAPdJS7JCO8xIlYwDQYJKoZIhvcNAQEL
BQAwgawxCzAJBgNVBAYTAlVTMSowKAYDVQQKEyFIb25lc3QgQWNobWVkJ3MgVXNl
ZCBDZXJ0aWZpY2F0ZXMxKTAnBgNVBAsTIEhhc3RpbHktR2VuZXJhdGVkIFZhbHVl
cyBEaXZpc29uMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRMwEQYDVQQIEwpDYWxp
Zm9ybmlhMRkwFwYDVQQDExBBdXRvZ2VuZXJhdGVkIENBMCAXDTE2MDMxMjIzMTQw
MFoYDzIxMTYwMjE3MjMxNDAwWjCBrDELMAkGA1UEBhMCVVMxKjAoBgNVBAoTIUhv
bmVzdCBBY2htZWQncyBVc2VkIENlcnRpZmljYXRlczEpMCcGA1UECxMgSGFzdGls
eS1HZW5lcmF0ZWQgVmFsdWVzIERpdmlzb24xFjAUBgNVBAcTDVNhbiBGcmFuY2lz
Y28xEzARBgNVBAgTCkNhbGlmb3JuaWExGTAXBgNVBAMTEEF1dG9nZW5lcmF0ZWQg
Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDP+acpr1USrObZFu+6
v+Bk6rYw+sWynP373cNUUiHfnZ3D7f9yJsDscV0Mo4R8DddqkxawrA5fK2Fm2Z9G
vvY5par4/JbwRIEkXmeM4e52Mqv0Yuoz62O+0jQvRawnCCJMcKuo+ijHMjmm0AF1
JdhTpTgvUwEP9WtY9JVTkfMCnDqZiqOU5D+d4YWUtkKqgQNvbZRs6wGubhMCZe8X
m+3bK8YAsWWtoFgr7plxXk4D8MLh+PqJ3oJjfxfW5A9dHbnSEmdZ3vrYwrKgyfNf
bvHE5qQmiSZUbUaCw3mKfaEMCNesPT46nBHxhAWc5aiL1tOXzvV5Uze7A7huPoI9
a3etAgMBAAGjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEC
MB0GA1UdDgQWBBQYc0xXQ6VNjFvIOqWfXorxx9rKRzAfBgNVHSMEGDAWgBQYc0xX
Q6VNjFvIOqWfXorxx9rKRzANBgkqhkiG9w0BAQsFAAOCAQEAaKyHDWYVjEyEKTXJ
qS9r46ehL5FZlWD2ZytBP8aHE307l9AfQ+DFWldCNaqMXLZozsresVaSzSOI6UUD
lCIQLDpPyxbpR320u8mC08+lhhwR/YRkrEqKHk56Wl4OaqoyWmguqYU9p0DiQeTU
sZsxOwG7cyEEvvs+XmZ/vBLBOr59xyjwn4seQqzwZj3VYeiKLw40iQt1yT442rcP
CfdlE9wTEONvWT+kBGMt0JlalXH3jFvlfcGQdDfRmDeTJtA+uIbvJhwJuGCNHHAc
xqC+4mAGBPN/dMPXpjayHD5dOXIKLfrNpqse6jImYlY9zduvwIHRDK/zvqTyPlNZ
uR84Nw==
-----END CERTIFICATE-----
`
const CertFileContent = `
-----BEGIN CERTIFICATE-----
MIIELzCCAxegAwIBAgIUcjkJA3cmHeoBQggaKZmfKebFL9cwDQYJKoZIhvcNAQEL
BQAwgawxCzAJBgNVBAYTAlVTMSowKAYDVQQKEyFIb25lc3QgQWNobWVkJ3MgVXNl
ZCBDZXJ0aWZpY2F0ZXMxKTAnBgNVBAsTIEhhc3RpbHktR2VuZXJhdGVkIFZhbHVl
cyBEaXZpc29uMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRMwEQYDVQQIEwpDYWxp
Zm9ybmlhMRkwFwYDVQQDExBBdXRvZ2VuZXJhdGVkIENBMCAXDTE2MDMxMjIzMTQw
MFoYDzIxMTYwMjE3MjMxNDAwWjBVMRYwFAYDVQQKEw1hdXRvZ2VuZXJhdGVkMRUw
EwYDVQQLEwxldGNkIGNsdXN0ZXIxFTATBgNVBAcTDHRoZSBpbnRlcm5ldDENMAsG
A1UEAxMEZXRjZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOiW5A65
hWGbnwceoZHM0+OexU4cPF/FpP+7BOK5i7ymSWAqfKfNuio2TB1lAErC1oX7bgTX
ieP10uz3FYWQNrlDn0I4KSA888rFPtx8GwoxH/52fGlE80BUV9PNeOVP+mYza0ih
oFj2+PhXVL/JZbx9P/2RLSNbEnq+OPk8AN82SkNtpFzanwtpb3f+kt73878KNoQu
xYZaCF1sK45Kn7mjKSDu/b3xUbTrNwnyVAGOdLzI7CCWOu+ECoZYAH4ZNHHakbyY
eWQ7U9leocEOPlqxsQAKodaCYjuAaOFIcz8/W81q+3qNw/6GbZ4znjRKQ3OtIPZ4
JH1iNofCudWDp+0CAwEAAaOBnDCBmTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYw
FAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFMJE
43qLCWhyZAE/wxNneSJw7aUVMB8GA1UdIwQYMBaAFBhzTFdDpU2MW8g6pZ9eivHH
2spHMBoGA1UdEQQTMBGCCWxvY2FsaG9zdIcEfwAAATANBgkqhkiG9w0BAQsFAAOC
AQEAuELC8tbmpyKlA4HLSDHOUquypNyiE6ftBIifJtp8bvBd+jiv4Pr8oVGxHoqq
48X7lamvDirLV5gmK0CxO+EXkIUHhULzPyYPynqsR7KZlk1PWghqsF65nwqcjS3b
tykLttD1AUDIozYvujVYBKXGxb6jcGM1rBF1XtslciFZ5qQnj6dTUujo9/xBA2ql
kOKiVXBNU8KFzq4c20RzHFLfWkbc30Q4XG4dTDVBeGupnFQRkZ0y2dSSU82QcLA/
HgAyQSO7+csN13r84zbmDuRpUgo6eTXzJ+77G19KDkEL7XEtlw2jB2L6/o+3RGtw
JLOpEsgi7hsvOYCuTA3Krw52Mw==
-----END CERTIFICATE-----
`
const KeyFileContent = `
REDACTED_SECRET
`
