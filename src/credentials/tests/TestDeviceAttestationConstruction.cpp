/*
 *
 *    Copyright (c) 2021 Project CHIP Authors
 *    All rights reserved.
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

// #include <credentials/CHIPCert.h>

#include <lib/core/CHIPError.h>
#include <lib/support/Span.h>
#include <lib/support/UnitTestRegistration.h>
#include <support/CodeUtils.h>

#include <nlunit-test.h>

#include "support/ScopedBuffer.h"
#include "credentials/DeviceAttestation.h"

using namespace chip;
using namespace chip::Credentials;


static void TestAttestationElements(nlTestSuite * inSuite, void * inContext)
{
    CHIP_ERROR err = CHIP_NO_ERROR;
    chip::Platform::ScopedMemoryBuffer<uint8_t> attestationElements;
    size_t attestationElementsLen;

    uint8_t certificationDeclaration[] = { 0xd2, 0x84, 0x4b, 0xa2, 0x01, 0x26, 0x04, 0x46, 0x63, 0x73, 0x61, 0x63, 0x64, 0x30,
                                           0xa0, 0x58, 0x1d, 0x15, 0x25, 0x01, 0x88, 0x99, 0x25, 0x02, 0xfe, 0xff, 0x25, 0x03,
                                           0xd2, 0x04, 0x25, 0x04, 0x2e, 0x16, 0x24, 0x05, 0xaa, 0x25, 0x06, 0xde, 0xc0, 0x25,
                                           0x07, 0x94, 0x26, 0x18, 0x58, 0x40, 0x96, 0x57, 0x2d, 0xd6, 0x3c, 0x03, 0x64, 0x0b,
                                           0x28, 0x67, 0x02, 0xbd, 0x6b, 0xba, 0x48, 0xac, 0x7c, 0x83, 0x54, 0x9b, 0x68, 0x73,
                                           0x29, 0x47, 0x48, 0xb9, 0x51, 0xd5, 0xab, 0x66, 0x62, 0x2e, 0x9d, 0x26, 0x10, 0x41,
                                           0xf8, 0x0e, 0x97, 0x49, 0xfe, 0xff, 0x78, 0x10, 0x02, 0x49, 0x67, 0xae, 0xdf, 0x41,
                                           0x38, 0x36, 0x5b, 0x0a, 0x22, 0x57, 0x14, 0x9c, 0x9a, 0x12, 0x3e, 0x0d, 0x30, 0xaa };
    uint8_t attestationNonce[] = { 0xe0, 0x42, 0x1b, 0x91, 0xc6, 0xfd, 0xcd, 0xb4, 0x0e, 0x2a, 0x4d, 0x2c, 0xf3, 0x1d, 0xb2, 0xb4,
                                   0xe1, 0x8b, 0x41, 0x1b, 0x1d, 0x3a, 0xd4, 0xd1, 0x2a, 0x9d, 0x90, 0xaa, 0x8e, 0x52, 0xfa, 0xe2 };
    uint32_t timestamp         = 677103357;

    uint8_t vendorReserved1[]  = { 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x5f, 0x76, 0x65, 0x6e, 0x64, 0x6f,
                                  0x72, 0x5f, 0x72, 0x65, 0x73, 0x65, 0x72, 0x76, 0x65, 0x64, 0x31 };
    uint8_t vendorReserved3[]  = { 0x76, 0x65, 0x6e, 0x64, 0x6f, 0x72, 0x5f, 0x72, 0x65, 0x73, 0x65, 0x72,
                                  0x76, 0x65, 0x64, 0x33, 0x5f, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65 };
    uint8_t attestationElementsTestVector[] = {
#if 0 
        0x15, 0x30, 0x01, 0x70, 0xd2, 0x84, 0x4b, 0xa2, 0x01, 0x26, 0x04, 0x46, 0x63, 0x73, 0x61, 0x63, 0x64, 0x30, 0xa0, 0x58,
        0x1d, 0x15, 0x25, 0x01, 0x88, 0x99, 0x25, 0x02, 0xfe, 0xff, 0x25, 0x03, 0xd2, 0x04, 0x25, 0x04, 0x2e, 0x16, 0x24, 0x05,
        0xaa, 0x25, 0x06, 0xde, 0xc0, 0x25, 0x07, 0x94, 0x26, 0x18, 0x58, 0x40, 0x96, 0x57, 0x2d, 0xd6, 0x3c, 0x03, 0x64, 0x0b,
        0x28, 0x67, 0x02, 0xbd, 0x6b, 0xba, 0x48, 0xac, 0x7c, 0x83, 0x54, 0x9b, 0x68, 0x73, 0x29, 0x47, 0x48, 0xb9, 0x51, 0xd5,
        0xab, 0x66, 0x62, 0x2e, 0x9d, 0x26, 0x10, 0x41, 0xf8, 0x0e, 0x97, 0x49, 0xfe, 0xff, 0x78, 0x10, 0x02, 0x49, 0x67, 0xae,
        0xdf, 0x41, 0x38, 0x36, 0x5b, 0x0a, 0x22, 0x57, 0x14, 0x9c, 0x9a, 0x12, 0x3e, 0x0d, 0x30, 0xaa, 0x30, 0x02, 0x20, 0xe0,
        0x42, 0x1b, 0x91, 0xc6, 0xfd, 0xcd, 0xb4, 0x0e, 0x2a, 0x4d, 0x2c, 0xf3, 0x1d, 0xb2, 0xb4, 0xe1, 0x8b, 0x41, 0x1b, 0x1d,
        0x3a, 0xd4, 0xd1, 0x2a, 0x9d, 0x90, 0xaa, 0x8e, 0x52, 0xfa, 0xe2, 0x26, 0x03, 0xfd, 0xc6, 0x5b, 0x28, 0x30, 0x05, 0x17,
        0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x5f, 0x76, 0x65, 0x6e, 0x64, 0x6f, 0x72, 0x5f, 0x72, 0x65, 0x73, 0x65, 0x72, 0x76,
        0x65, 0x64, 0x31, 0x30, 0x07, 0x18, 0x76, 0x65, 0x6e, 0x64, 0x6f, 0x72, 0x5f, 0x72, 0x65, 0x73, 0x65, 0x72, 0x76, 0x65,
        0x64, 0x33, 0x5f, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x18
#else
		0x15, 0x30, 0x01, 0x70, 0xd2, 0x84, 0x4b, 0xa2, 0x01, 0x26, 0x04, 0x46, 0x63, 0x73, 0x61, 0x63,
		0x64, 0x30, 0xa0, 0x58, 0x1d, 0x15, 0x25, 0x01, 0x88, 0x99, 0x25, 0x02, 0xfe, 0xff, 0x25, 0x03,
		0xd2, 0x04, 0x25, 0x04, 0x2e, 0x16, 0x24, 0x05, 0xaa, 0x25, 0x06, 0xde, 0xc0, 0x25, 0x07, 0x94,
		0x26, 0x18, 0x58, 0x40, 0x96, 0x57, 0x2d, 0xd6, 0x3c, 0x03, 0x64, 0x0b, 0x28, 0x67, 0x02, 0xbd,
		0x6b, 0xba, 0x48, 0xac, 0x7c, 0x83, 0x54, 0x9b, 0x68, 0x73, 0x29, 0x47, 0x48, 0xb9, 0x51, 0xd5,
		0xab, 0x66, 0x62, 0x2e, 0x9d, 0x26, 0x10, 0x41, 0xf8, 0x0e, 0x97, 0x49, 0xfe, 0xff, 0x78, 0x10,
		0x02, 0x49, 0x67, 0xae, 0xdf, 0x41, 0x38, 0x36, 0x5b, 0x0a, 0x22, 0x57, 0x14, 0x9c, 0x9a, 0x12,
		0x3e, 0x0d, 0x30, 0xaa, 0x30, 0x02, 0x20, 0xe0, 0x42, 0x1b, 0x91, 0xc6, 0xfd, 0xcd, 0xb4, 0x0e,
		0x2a, 0x4d, 0x2c, 0xf3, 0x1d, 0xb2, 0xb4, 0xe1, 0x8b, 0x41, 0x1b, 0x1d, 0x3a, 0xd4, 0xd1, 0x2a,
		0x9d, 0x90, 0xaa, 0x8e, 0x52, 0xfa, 0xe2, 0x26, 0x03, 0xfd, 0xc6, 0x5b, 0x28, 0xd0, 0xf1, 0xff,
		0x3e, 0x00, 0x01, 0x00, 0x17, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x5f, 0x76, 0x65, 0x6e, 0x64,
		0x6f, 0x72, 0x5f, 0x72, 0x65, 0x73, 0x65, 0x72, 0x76, 0x65, 0x64, 0x31, 0xd0, 0xf1, 0xff, 0x3e,
		0x00, 0x03, 0x00, 0x18, 0x76, 0x65, 0x6e, 0x64, 0x6f, 0x72, 0x5f, 0x72, 0x65, 0x73, 0x65, 0x72,
		0x76, 0x65, 0x64, 0x33, 0x5f, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x18
#endif
    };

    attestationElementsLen = sizeof(certificationDeclaration) + sizeof(attestationNonce) + sizeof(timestamp) +
        sizeof(vendorReserved1) + sizeof(vendorReserved3) + sizeof(uint64_t) * 5 ;
    attestationElements.Alloc(attestationElementsLen);
    NL_TEST_ASSERT(inSuite, attestationElements);

    {
        uint16_t vendorId = 0xbeef;
        uint16_t profileNum = 0xdead;
        std::vector<ByteSpan>  vendorReserved;

        MutableByteSpan attestationElementsSpan(attestationElements.Get(), attestationElementsLen);
        err = ConstructAttestationElements(ByteSpan(certificationDeclaration), ByteSpan(attestationNonce),
                    timestamp, ByteSpan(),  vendorReserved,  vendorId, profileNum, attestationElementsSpan);
        NL_TEST_ASSERT(inSuite, err == CHIP_NO_ERROR);
        attestationElementsLen = attestationElementsSpan.size();
    }

    NL_TEST_ASSERT(inSuite, sizeof(attestationElementsTestVector) == attestationElementsLen);
    NL_TEST_ASSERT(inSuite,
                   memcmp(attestationElements.Get(), attestationElementsTestVector, sizeof(attestationElementsTestVector)) == 0);

    ByteSpan certificationDeclarationSpan;
    ByteSpan attestationNonceSpan;
    uint32_t timestampDeconstructed;
    ByteSpan firmwareInfoSpan;
    std::vector<ByteSpan> vendorReserved;
    uint16_t vendorId;
    uint16_t vendorProfile;

    err = DeconstructAttestationElements(ByteSpan(attestationElementsTestVector), certificationDeclarationSpan,
                                         attestationNonceSpan, timestampDeconstructed, firmwareInfoSpan, 
                                         vendorReserved, vendorId, vendorProfile);
    NL_TEST_ASSERT(inSuite, err == CHIP_NO_ERROR);

    NL_TEST_ASSERT(inSuite, sizeof(certificationDeclaration) == certificationDeclarationSpan.size());
    NL_TEST_ASSERT(inSuite,
                   memcmp(certificationDeclarationSpan.data(), certificationDeclaration, sizeof(certificationDeclaration)) == 0);

    NL_TEST_ASSERT(inSuite, sizeof(attestationNonce) == attestationNonceSpan.size());
    NL_TEST_ASSERT(inSuite, memcmp(attestationNonceSpan.data(), attestationNonce, sizeof(attestationNonce)) == 0);

    NL_TEST_ASSERT(inSuite, timestamp == timestampDeconstructed);

    NL_TEST_ASSERT(inSuite, firmwareInfoSpan.empty());
}



/**
 *   Test Suite. It lists all the test functions.
 */
// clang-format off
static const nlTest sTests[] = {
    NL_TEST_DEF("Test Device Attestation", TestAttestationElements),
//    NL_TEST_DEF("Test Example Device Attestation Signature", TestDACProvidersExample_Signature),
    NL_TEST_SENTINEL()
};
// clang-format on

/**
 *  Set up the test suite.
 */
int TestDeviceAttestation_Setup(void * inContext)
{
    CHIP_ERROR error = chip::Platform::MemoryInit();
    if (error != CHIP_NO_ERROR)
        return FAILURE;
    return SUCCESS;
}

/**
 *  Tear down the test suite.
 */
int TestDeviceAttestation_Teardown(void * inContext)
{
    chip::Platform::MemoryShutdown();
    return SUCCESS;
}

int TestDeviceAttestation()
{
    // clang-format off
    nlTestSuite theSuite =
    {
        "Device Attestation",
        &sTests[0],
        TestDeviceAttestation_Setup,
        TestDeviceAttestation_Teardown
    };
    // clang-format on
    nlTestRunner(&theSuite, nullptr);
    return (nlTestRunnerStats(&theSuite));
}

CHIP_REGISTER_TEST_SUITE(TestDeviceAttestation);
