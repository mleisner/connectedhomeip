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
#pragma once

#include <lib/core/CHIPError.h>
#include <lib/support/Span.h>
#include <vector>


namespace chip {
namespace Credentials {

class DeviceAttestation
{
public:
    /**
     *  @brief Take the attestation elements vector and return each component seperately.
     *
     *  @param[in]  attestionElements Buffer containg source of attestion 
     *  @param[out] certificationDeclaration
     *  @param[out] attestationNonce
     *  @param[out] timestamp
     *  @param[out] firmwareInfo
     *  @param[out] vendorReserved elements
     *  @param[out] vendorId (from vendor reserved elements)
     *  @param[out] profileNum (from vendor reserved elements)
     */
    static CHIP_ERROR DeconstructAttestationElements(const ByteSpan & attestationElements, ByteSpan & certificationDeclaration,
                                          ByteSpan & attestationNonce, uint32_t & timestamp, ByteSpan & firmwareInfo,
                      std::vector<ByteSpan> &vendorReserved, uint16_t & vendorId, uint16_t & profileNum );
                     // uint16_t & vendorId, uint16_t & profileNum );
                      

    /**
     *  @brief Take discrete components  .
     *
     *  @param[in]  attestionElements Buffer containg source of attestion 
     *  @param[out] certificationDeclaration
     *  @param[out] attestationNonce
     *  @param[out] timestamp
     *  @param[out] firmwareInfo
     *  @param[out] vendorReserved elements
     *  @param[out] vendorId (from vendor reserved elements)
     *  @param[out] profileNum (from vendor reserved elements)
     */

    static CHIP_ERROR ConstructAttestationElements(const ByteSpan & certificationDeclaration, const ByteSpan & attestationNonce,
                                        uint32_t timestamp, const ByteSpan & firmwareInfo, 
                    std::vector<ByteSpan> &vendorReserved, uint16_t vendorId, uint16_t profileNum,
     //       uint16_t vendorId, uint16_t profileNum,
                    MutableByteSpan & attestationElements);
};

} // namespace Credentials
} // namespace chip

