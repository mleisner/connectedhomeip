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
#include "DeviceAttestationConstructor.h"

#include <lib/core/CHIPTLV.h>
#include <lib/support/CodeUtils.h>
#include <lib/support/logging/CHIPLogging.h>

#include <iostream>

namespace chip {
namespace Credentials {

// context tag positions
enum
{
    kCertificationDeclarationTagId = 1,
    kAttestationNonceTagId         = 2,
    kTimestampTagId                = 3,
    kFirmwareInfoTagId             = 4,
};

CHIP_ERROR DeconstructAttestationElements(const ByteSpan & attestationElements, ByteSpan & certificationDeclaration,
                                          ByteSpan & attestationNonce, uint32_t & timestamp, ByteSpan & firmwareInfo,
                                          ByteSpan * vendorReservedArray, size_t vendorReservedArraySize, uint16_t & vendorId,
                                          uint16_t & profileNum)
{
    bool certificationDeclarationExists = false;
    bool attestationNonceExists         = false;
    bool timestampExists                = false;
    bool firmwareInfoExists             = false;
    size_t vendorReservedIdx            = 0;
    TLV::TLVReader tlvReader;
    TLV::TLVType containerType = TLV::kTLVType_Structure;

    tlvReader.Init(attestationElements.data(), static_cast<uint32_t>(attestationElements.size()));
    ReturnErrorOnFailure(tlvReader.Next(containerType, TLV::AnonymousTag));
    ReturnErrorOnFailure(tlvReader.EnterContainer(containerType));

    CHIP_ERROR error = CHIP_NO_ERROR;
    while ((error = tlvReader.Next()) == CHIP_NO_ERROR)
    {
        uint64_t tag = tlvReader.GetTag();

        if (TLV::IsContextTag(tag))
        {
            switch (TLV::TagNumFromTag(tag))
            {
            case kCertificationDeclarationTagId:
                VerifyOrReturnError(certificationDeclarationExists == false, CHIP_ERROR_IM_MALFORMED_COMMAND_DATA_ELEMENT);
                ReturnErrorOnFailure(tlvReader.Get(certificationDeclaration));
                certificationDeclarationExists = true;
                break;
            case kAttestationNonceTagId:
                VerifyOrReturnError(attestationNonceExists == false, CHIP_ERROR_IM_MALFORMED_COMMAND_DATA_ELEMENT);
                ReturnErrorOnFailure(tlvReader.Get(attestationNonce));
                attestationNonceExists = true;
                break;
            case kTimestampTagId:
                VerifyOrReturnError(timestampExists == false, CHIP_ERROR_IM_MALFORMED_COMMAND_DATA_ELEMENT);
                ReturnErrorOnFailure(tlvReader.Get(timestamp));
                timestampExists = true;
                break;
            case kFirmwareInfoTagId:
                VerifyOrReturnError(firmwareInfoExists == false, CHIP_ERROR_IM_MALFORMED_COMMAND_DATA_ELEMENT);
                ReturnErrorOnFailure(tlvReader.Get(firmwareInfo));
                firmwareInfoExists = true;
                break;
            default:
                return CHIP_ERROR_IM_MALFORMED_COMMAND_DATA_ELEMENT;
            }
        }
        else if (TLV::IsProfileTag(tag))
        {
            // vendor fields
            bool seenProfile = false;
            uint16_t currentVendorId;
            uint16_t currentProfileNum;

            currentVendorId   = TLV::VendorIdFromTag(tag);
            currentProfileNum = TLV::ProfileNumFromTag(tag);
            if (!seenProfile)
            {
                seenProfile = true;
                vendorId    = currentVendorId;
                profileNum  = currentProfileNum;
            }
            else
            {
                // check that vendorId and profileNum match in every Vendor Reserved entry
                VerifyOrReturnError(currentVendorId == vendorId && currentProfileNum == profileNum,
                                    CHIP_ERROR_IM_MALFORMED_COMMAND_DATA_ELEMENT);
            }

            ByteSpan vendorReservedEntry;
            ReturnErrorOnFailure(tlvReader.Get(vendorReservedEntry));
            VerifyOrReturnError(vendorReservedIdx < vendorReservedArraySize, CHIP_ERROR_NO_MEMORY);
            vendorReservedArray[vendorReservedIdx++] = vendorReservedEntry;
        }
        else
        {
            return CHIP_ERROR_IM_MALFORMED_COMMAND_DATA_ELEMENT;
        }
    }

    VerifyOrReturnError(error == CHIP_END_OF_TLV, error);
    VerifyOrReturnError(certificationDeclarationExists && attestationNonceExists && timestampExists,
                        CHIP_ERROR_MISSING_TLV_ELEMENT);

    return CHIP_NO_ERROR;
}

CHIP_ERROR ConstructAttestationElements(const ByteSpan & certificationDeclaration, const ByteSpan & attestationNonce,
                                        uint32_t timestamp, const ByteSpan & firmwareInfo, ByteSpan * vendorReservedArray,
                                        size_t vendorReservedArraySize, uint16_t vendorId, uint16_t profileNum,
                                        MutableByteSpan & attestationElements)
{
    TLV::TLVWriter tlvWriter;
    TLV::TLVType outerContainerType = TLV::kTLVType_NotSpecified;

    VerifyOrReturnError(!certificationDeclaration.empty() && !attestationNonce.empty(), CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(attestationNonce.size() == 32, CHIP_ERROR_INVALID_MESSAGE_LENGTH);
    if (vendorReservedArraySize != 0)
    {
        VerifyOrReturnError(vendorReservedArray != nullptr, CHIP_ERROR_INVALID_ARGUMENT);
    }

    tlvWriter.Init(attestationElements.data(), static_cast<uint32_t>(attestationElements.size()));
    outerContainerType = TLV::kTLVType_NotSpecified;
    ReturnErrorOnFailure(tlvWriter.StartContainer(TLV::AnonymousTag, TLV::kTLVType_Structure, outerContainerType));
    ReturnErrorOnFailure(tlvWriter.Put(TLV::ContextTag(1), certificationDeclaration));
    ReturnErrorOnFailure(tlvWriter.Put(TLV::ContextTag(2), attestationNonce));
    ReturnErrorOnFailure(tlvWriter.Put(TLV::ContextTag(3), timestamp));
    if (!firmwareInfo.empty())
    {
        ReturnErrorOnFailure(tlvWriter.Put(TLV::ContextTag(4), firmwareInfo));
    }

    uint8_t vendorTagNum = 1;
    for (size_t vendorReservedIdx = 0; vendorReservedIdx < vendorReservedArraySize; ++vendorReservedIdx)
    {
        if (!vendorReservedArray[vendorReservedIdx].empty())
        {
            ReturnErrorOnFailure(
                tlvWriter.Put(TLV::ProfileTag(vendorId, profileNum, vendorTagNum), vendorReservedArray[vendorReservedIdx]));
        }
        vendorTagNum++;
    }

    ReturnErrorOnFailure(tlvWriter.EndContainer(outerContainerType));
    ReturnErrorOnFailure(tlvWriter.Finalize());
    attestationElements = attestationElements.SubSpan(0, tlvWriter.GetLengthWritten());

    return CHIP_NO_ERROR;
}

} // namespace Credentials

} // namespace chip
