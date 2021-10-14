/*
 *
 *    Copyright (c) 2021 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
#include "DeviceAttestationCredsExample.h"

#include <crypto/CHIPCryptoPAL.h>

#include <lib/core/CHIPError.h>
#include <lib/support/Span.h>

namespace chip {
namespace Credentials {
namespace Examples {

namespace {

// TODO: This should be moved to a method of P256Keypair
CHIP_ERROR LoadKeypairFromRaw(ByteSpan private_key, ByteSpan public_key, Crypto::P256Keypair & keypair)
{
    Crypto::P256SerializedKeypair serialized_keypair;
    ReturnErrorOnFailure(serialized_keypair.SetLength(private_key.size() + public_key.size()));
    memcpy(serialized_keypair.Bytes(), public_key.data(), public_key.size());
    memcpy(serialized_keypair.Bytes() + public_key.size(), private_key.data(), private_key.size());
    return keypair.Deserialize(serialized_keypair);
}

class ExampleDACProvider : public DeviceAttestationCredentialsProvider
{
public:
    CHIP_ERROR GetCertificationDeclaration(MutableByteSpan & out_cd_buffer) override;
    CHIP_ERROR GetFirmwareInformation(MutableByteSpan & out_firmware_info_buffer) override;
    CHIP_ERROR GetDeviceAttestationCert(MutableByteSpan & out_dac_buffer) override;
    CHIP_ERROR GetProductAttestationIntermediateCert(MutableByteSpan & out_pai_buffer) override;
    CHIP_ERROR SignWithDeviceAttestationKey(const ByteSpan & digest_to_sign, MutableByteSpan & out_signature_buffer) override;
};

CHIP_ERROR ExampleDACProvider::GetDeviceAttestationCert(MutableByteSpan & out_dac_buffer)
{
    /*
    credentials/test/attestation/Chip-Test-DAC-FFF1-8000-000A-Cert.pem
    -----BEGIN CERTIFICATE-----
    MIIB6jCCAY+gAwIBAgIIBRpp5eeAND4wCgYIKoZIzj0EAwIwRjEYMBYGA1UEAwwP
    TWF0dGVyIFRlc3QgUEFJMRQwEgYKKwYBBAGConwCAQwERkZGMTEUMBIGCisGAQQB
    gqJ8AgIMBDgwMDAwIBcNMjEwNjI4MTQyMzQzWhgPOTk5OTEyMzEyMzU5NTlaMEsx
    HTAbBgNVBAMMFE1hdHRlciBUZXN0IERBQyAwMDBBMRQwEgYKKwYBBAGConwCAQwE
    RkZGMTEUMBIGCisGAQQBgqJ8AgIMBDgwMDAwWTATBgcqhkjOPQIBBggqhkjOPQMB
    BwNCAAR6hFivu5vNFeGa3NJm9mycL2B8dHR6NfgPN+EYEz+A8XYBEyePkfFaoPf4
    eTIJT+aftyhoqB4ml5s2izO1VDEDo2AwXjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB
    /wQEAwIHgDAdBgNVHQ4EFgQU1a2yuIOOyAc8R3LcfoeX/rsjs64wHwYDVR0jBBgw
    FoAUhPUd/57M2ik1lEhSDoXxKS2j7dcwCgYIKoZIzj0EAwIDSQAwRgIhAPL+Fnlk
    P0xbynYuijQV7VEwBvzQUtpQbWLYvVFeN70IAiEAvi20eqszdReOEkmgeSCgrG6q
    OS8H8W2E/ctS268o19k=
    -----END CERTIFICATE-----
    */
    constexpr uint8_t kDacCertificate[] = {
        0x30, 0x82, 0x01, 0xEA, 0x30, 0x82, 0x01, 0x8F, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x08, 0x05, 0x1A, 0x69, 0xE5, 0xE7,
        0x80, 0x34, 0x3E, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30, 0x46, 0x31, 0x18, 0x30,
        0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0F, 0x4D, 0x61, 0x74, 0x74, 0x65, 0x72, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20,
        0x50, 0x41, 0x49, 0x31, 0x14, 0x30, 0x12, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x02, 0x01, 0x0C,
        0x04, 0x46, 0x46, 0x46, 0x31, 0x31, 0x14, 0x30, 0x12, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x02,
        0x02, 0x0C, 0x04, 0x38, 0x30, 0x30, 0x30, 0x30, 0x20, 0x17, 0x0D, 0x32, 0x31, 0x30, 0x36, 0x32, 0x38, 0x31, 0x34, 0x32,
        0x33, 0x34, 0x33, 0x5A, 0x18, 0x0F, 0x39, 0x39, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39,
        0x5A, 0x30, 0x4B, 0x31, 0x1D, 0x30, 0x1B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x14, 0x4D, 0x61, 0x74, 0x74, 0x65, 0x72,
        0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x44, 0x41, 0x43, 0x20, 0x30, 0x30, 0x30, 0x41, 0x31, 0x14, 0x30, 0x12, 0x06, 0x0A,
        0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x02, 0x01, 0x0C, 0x04, 0x46, 0x46, 0x46, 0x31, 0x31, 0x14, 0x30, 0x12,
        0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x02, 0x02, 0x0C, 0x04, 0x38, 0x30, 0x30, 0x30, 0x30, 0x59,
        0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01,
        0x07, 0x03, 0x42, 0x00, 0x04, 0x7A, 0x84, 0x58, 0xAF, 0xBB, 0x9B, 0xCD, 0x15, 0xE1, 0x9A, 0xDC, 0xD2, 0x66, 0xF6, 0x6C,
        0x9C, 0x2F, 0x60, 0x7C, 0x74, 0x74, 0x7A, 0x35, 0xF8, 0x0F, 0x37, 0xE1, 0x18, 0x13, 0x3F, 0x80, 0xF1, 0x76, 0x01, 0x13,
        0x27, 0x8F, 0x91, 0xF1, 0x5A, 0xA0, 0xF7, 0xF8, 0x79, 0x32, 0x09, 0x4F, 0xE6, 0x9F, 0xB7, 0x28, 0x68, 0xA8, 0x1E, 0x26,
        0x97, 0x9B, 0x36, 0x8B, 0x33, 0xB5, 0x54, 0x31, 0x03, 0xA3, 0x60, 0x30, 0x5E, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x1D, 0x13,
        0x01, 0x01, 0xFF, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF, 0x04, 0x04, 0x03,
        0x02, 0x07, 0x80, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0xD5, 0xAD, 0xB2, 0xB8, 0x83, 0x8E,
        0xC8, 0x07, 0x3C, 0x47, 0x72, 0xDC, 0x7E, 0x87, 0x97, 0xFE, 0xBB, 0x23, 0xB3, 0xAE, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D,
        0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x84, 0xF5, 0x1D, 0xFF, 0x9E, 0xCC, 0xDA, 0x29, 0x35, 0x94, 0x48, 0x52, 0x0E,
        0x85, 0xF1, 0x29, 0x2D, 0xA3, 0xED, 0xD7, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x03,
        0x49, 0x00, 0x30, 0x46, 0x02, 0x21, 0x00, 0xF2, 0xFE, 0x16, 0x79, 0x64, 0x3F, 0x4C, 0x5B, 0xCA, 0x76, 0x2E, 0x8A, 0x34,
        0x15, 0xED, 0x51, 0x30, 0x06, 0xFC, 0xD0, 0x52, 0xDA, 0x50, 0x6D, 0x62, 0xD8, 0xBD, 0x51, 0x5E, 0x37, 0xBD, 0x08, 0x02,
        0x21, 0x00, 0xBE, 0x2D, 0xB4, 0x7A, 0xAB, 0x33, 0x75, 0x17, 0x8E, 0x12, 0x49, 0xA0, 0x79, 0x20, 0xA0, 0xAC, 0x6E, 0xAA,
        0x39, 0x2F, 0x07, 0xF1, 0x6D, 0x84, 0xFD, 0xCB, 0x52, 0xDB, 0xAF, 0x28, 0xD7, 0xD9
    };

    return CopySpanToMutableSpan(ByteSpan{ kDacCertificate }, out_dac_buffer);
}

CHIP_ERROR ExampleDACProvider::GetProductAttestationIntermediateCert(MutableByteSpan & out_pai_buffer)
{
    /*
    credentials/test/attestation/Chip-Test-PAI-FFF1-8000-Cert.pem
    -----BEGIN CERTIFICATE-----
    MIIBvzCCAWagAwIBAgIIfpkqTYmEBRUwCgYIKoZIzj0EAwIwHzEdMBsGA1UEAwwU
    TWF0dGVyIFRlc3QgUEFBIEZGRjEwIBcNMjEwNjI4MTQyMzQzWhgPOTk5OTEyMzEy
    MzU5NTlaMEYxGDAWBgNVBAMMD01hdHRlciBUZXN0IFBBSTEUMBIGCisGAQQBgqJ8
    AgEMBEZGRjExFDASBgorBgEEAYKifAICDAQ4MDAwMFkwEwYHKoZIzj0CAQYIKoZI
    zj0DAQcDQgAEynPORkG/CDtKM42gQxoKMjB/ZtFgV0tmEi8lBs9q03Djf2XWNHrn
    l6GXJlBQl200rHtjezvaC1vYQ+2OXV6b8qNjMGEwDwYDVR0TAQH/BAUwAwEB/zAO
    BgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFIT1Hf+ezNopNZRIUg6F8Skto+3XMB8G
    A1UdIwQYMBaAFO8Y4OzUZgQ03w28kR7UUhaZZoOfMAoGCCqGSM49BAMCA0cAMEQC
    IFlGfLWq/BpStUOJbdI73kXQgGxTpzec5xLkqAqtZ6taAiA/mv80v+8mVtOb+tF2
    WCRrNllsMubAajV+yukQb3k0dQ==
    -----END CERTIFICATE-----
    */
    constexpr uint8_t kPaiCertificate[] = {
        0x30, 0x82, 0x01, 0xBF, 0x30, 0x82, 0x01, 0x66, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x08, 0x7E, 0x99, 0x2A, 0x4D, 0x89,
        0x84, 0x05, 0x15, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30, 0x1F, 0x31, 0x1D, 0x30,
        0x1B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x14, 0x4D, 0x61, 0x74, 0x74, 0x65, 0x72, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20,
        0x50, 0x41, 0x41, 0x20, 0x46, 0x46, 0x46, 0x31, 0x30, 0x20, 0x17, 0x0D, 0x32, 0x31, 0x30, 0x36, 0x32, 0x38, 0x31, 0x34,
        0x32, 0x33, 0x34, 0x33, 0x5A, 0x18, 0x0F, 0x39, 0x39, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35,
        0x39, 0x5A, 0x30, 0x46, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0F, 0x4D, 0x61, 0x74, 0x74, 0x65,
        0x72, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x50, 0x41, 0x49, 0x31, 0x14, 0x30, 0x12, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04,
        0x01, 0x82, 0xA2, 0x7C, 0x02, 0x01, 0x0C, 0x04, 0x46, 0x46, 0x46, 0x31, 0x31, 0x14, 0x30, 0x12, 0x06, 0x0A, 0x2B, 0x06,
        0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x02, 0x02, 0x0C, 0x04, 0x38, 0x30, 0x30, 0x30, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07,
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        0x04, 0xCA, 0x73, 0xCE, 0x46, 0x41, 0xBF, 0x08, 0x3B, 0x4A, 0x33, 0x8D, 0xA0, 0x43, 0x1A, 0x0A, 0x32, 0x30, 0x7F, 0x66,
        0xD1, 0x60, 0x57, 0x4B, 0x66, 0x12, 0x2F, 0x25, 0x06, 0xCF, 0x6A, 0xD3, 0x70, 0xE3, 0x7F, 0x65, 0xD6, 0x34, 0x7A, 0xE7,
        0x97, 0xA1, 0x97, 0x26, 0x50, 0x50, 0x97, 0x6D, 0x34, 0xAC, 0x7B, 0x63, 0x7B, 0x3B, 0xDA, 0x0B, 0x5B, 0xD8, 0x43, 0xED,
        0x8E, 0x5D, 0x5E, 0x9B, 0xF2, 0xA3, 0x63, 0x30, 0x61, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04,
        0x05, 0x30, 0x03, 0x01, 0x01, 0xFF, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF, 0x04, 0x04, 0x03, 0x02,
        0x01, 0x06, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x84, 0xF5, 0x1D, 0xFF, 0x9E, 0xCC, 0xDA,
        0x29, 0x35, 0x94, 0x48, 0x52, 0x0E, 0x85, 0xF1, 0x29, 0x2D, 0xA3, 0xED, 0xD7, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23,
        0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xEF, 0x18, 0xE0, 0xEC, 0xD4, 0x66, 0x04, 0x34, 0xDF, 0x0D, 0xBC, 0x91, 0x1E, 0xD4,
        0x52, 0x16, 0x99, 0x66, 0x83, 0x9F, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x03, 0x47,
        0x00, 0x30, 0x44, 0x02, 0x20, 0x59, 0x46, 0x7C, 0xB5, 0xAA, 0xFC, 0x1A, 0x52, 0xB5, 0x43, 0x89, 0x6D, 0xD2, 0x3B, 0xDE,
        0x45, 0xD0, 0x80, 0x6C, 0x53, 0xA7, 0x37, 0x9C, 0xE7, 0x12, 0xE4, 0xA8, 0x0A, 0xAD, 0x67, 0xAB, 0x5A, 0x02, 0x20, 0x3F,
        0x9A, 0xFF, 0x34, 0xBF, 0xEF, 0x26, 0x56, 0xD3, 0x9B, 0xFA, 0xD1, 0x76, 0x58, 0x24, 0x6B, 0x36, 0x59, 0x6C, 0x32, 0xE6,
        0xC0, 0x6A, 0x35, 0x7E, 0xCA, 0xE9, 0x10, 0x6F, 0x79, 0x34, 0x75
    };

    return CopySpanToMutableSpan(ByteSpan{ kPaiCertificate }, out_pai_buffer);
}

CHIP_ERROR ExampleDACProvider::GetCertificationDeclaration(MutableByteSpan & out_cd_buffer)
{
    constexpr uint8_t kCertificationDeclaration[] = {
        0x30, 0x81, 0xd1, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02, 0xa0, 0x81, 0xc3, 0x30, 0x81, 0xc0,
        0x02, 0x01, 0x03, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x30, 0x2c,
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0xa0, 0x1f, 0x04, 0x1d, 0x15, 0x25, 0x01, 0x88, 0x99,
        0x25, 0x02, 0xfe, 0xff, 0x25, 0x03, 0xd2, 0x04, 0x25, 0x04, 0x2e, 0x16, 0x24, 0x05, 0xaa, 0x25, 0x06, 0xde, 0xc0, 0x25,
        0x07, 0x94, 0x26, 0x18, 0x31, 0x7e, 0x30, 0x7c, 0x02, 0x01, 0x03, 0x80, 0x14, 0xfd, 0x03, 0xc3, 0x49, 0xfc, 0x32, 0x9e,
        0x6c, 0xef, 0xf0, 0x1b, 0xa7, 0x7f, 0x6b, 0x8a, 0x31, 0xfb, 0xc0, 0xe7, 0xd4, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48,
        0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x04, 0x48,
        0x30, 0x46, 0x02, 0x21, 0x00, 0xe0, 0x5e, 0x1f, 0xac, 0x8f, 0x5e, 0xe3, 0xbd, 0x1c, 0xd7, 0x06, 0x24, 0x71, 0x0a, 0xe4,
        0x3f, 0xee, 0xa7, 0xbe, 0x80, 0xd7, 0x22, 0xb9, 0xfb, 0x0a, 0xf5, 0x52, 0x57, 0xa9, 0xa9, 0xab, 0x82, 0x02, 0x21, 0x00,
        0xb3, 0x4a, 0x73, 0x11, 0x70, 0x05, 0x28, 0x54, 0x84, 0x62, 0x35, 0x4f, 0xfc, 0xad, 0x21, 0xe4, 0x09, 0x79, 0xbc, 0xea,
        0x22, 0x8e, 0xd7, 0xbf, 0xa9, 0xf7, 0x7f, 0x10, 0xe8, 0x7e, 0xdf, 0x84
    };

    return CopySpanToMutableSpan(ByteSpan{ kCertificationDeclaration }, out_cd_buffer);
}

CHIP_ERROR ExampleDACProvider::GetFirmwareInformation(MutableByteSpan & out_firmware_info_buffer)
{
    // TODO: We need a real example FirmwareInformation to be populated.
    out_firmware_info_buffer.reduce_size(0);

    return CHIP_NO_ERROR;
}

CHIP_ERROR ExampleDACProvider::SignWithDeviceAttestationKey(const ByteSpan & digest_to_sign, MutableByteSpan & out_signature_buffer)
{

    /*
     credentials/test/attestation/Chip-Test-DAC-FFF1-8000-000A-Key.pem
     -----BEGIN EC PRIVATE KEY-----
     MHcCAQEEIAXGw6hNxgXMPMgFgAmwGzKc9gzxWXDGqQ6tquLeSWSeoAoGCCqGSM49
     AwEHoUQDQgAEeoRYr7ubzRXhmtzSZvZsnC9gfHR0ejX4DzfhGBM/gPF2ARMnj5Hx
     WqD3+HkyCU/mn7coaKgeJpebNosztVQxAw==
     -----END EC PRIVATE KEY-----
    */

    constexpr uint8_t dac_private_key[] = { 0x05, 0xc6, 0xc3, 0xa8, 0x4d, 0xc6, 0x05, 0xcc, 0x3c, 0xc8, 0x05,
                                            0x80, 0x09, 0xb0, 0x1b, 0x32, 0x9c, 0xf6, 0x0c, 0xf1, 0x59, 0x70,
                                            0xc6, 0xa9, 0x0e, 0xad, 0xaa, 0xe2, 0xde, 0x49, 0x64, 0x9e };

    // In a non-exemplary implementation, the public key is not needed here. It is used here merely because
    // Crypto::P256Keypair is only (currently) constructable from raw keys if both private/public keys are present.
    constexpr uint8_t dac_public_key[] = { 0x04, 0x7a, 0x84, 0x58, 0xaf, 0xbb, 0x9b, 0xcd, 0x15, 0xe1, 0x9a, 0xdc, 0xd2,
                                           0x66, 0xf6, 0x6c, 0x9c, 0x2f, 0x60, 0x7c, 0x74, 0x74, 0x7a, 0x35, 0xf8, 0x0f,
                                           0x37, 0xe1, 0x18, 0x13, 0x3f, 0x80, 0xf1, 0x76, 0x01, 0x13, 0x27, 0x8f, 0x91,
                                           0xf1, 0x5a, 0xa0, 0xf7, 0xf8, 0x79, 0x32, 0x09, 0x4f, 0xe6, 0x9f, 0xb7, 0x28,
                                           0x68, 0xa8, 0x1e, 0x26, 0x97, 0x9b, 0x36, 0x8b, 0x33, 0xb5, 0x54, 0x31, 0x03 };

    Crypto::P256ECDSASignature signature;
    Crypto::P256Keypair keypair;

    VerifyOrReturnError(IsSpanUsable(out_signature_buffer), CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(IsSpanUsable(digest_to_sign), CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(out_signature_buffer.size() >= signature.Capacity(), CHIP_ERROR_BUFFER_TOO_SMALL);

    ReturnErrorOnFailure(LoadKeypairFromRaw(ByteSpan{ dac_private_key }, ByteSpan{ dac_public_key }, keypair));
    ReturnErrorOnFailure(keypair.ECDSA_sign_hash(digest_to_sign.data(), digest_to_sign.size(), signature));

    return CopySpanToMutableSpan(ByteSpan{ signature.ConstBytes(), signature.Length() }, out_signature_buffer);
}

} // namespace

DeviceAttestationCredentialsProvider * GetExampleDACProvider()
{
    static ExampleDACProvider example_dac_provider;

    return &example_dac_provider;
}

} // namespace Examples
} // namespace Credentials
} // namespace chip
