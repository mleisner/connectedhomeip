#include "DeviceAttestation.h"
#include <core/CHIPTLV.h>
#include <support/CodeUtils.h>

namespace chip {
namespace Credentials {

// TODO: vendor data needs fully qualitified IDs -- (vendor ID, profile number, tag #)


// context tag positions
enum {  CERTIFICATE_DECLARATION = 1, 
    ATTESTATION_NONCE     = 2,
    TIMESTAMP             = 3,
    FIRMWARE_INFO         = 4,
    LAST_TAG              = FIRMWARE_INFO
};

CHIP_ERROR DeviceAttestation::DeconstructAttestationElements(const ByteSpan & attestationElements, 
                                            ByteSpan & certificationDeclaration,
                                            ByteSpan & attestationNonce, uint32_t & timestamp, ByteSpan & firmwareInfo,
//                                            std::vector<ByteSpan> & vendorReserved,
                                          uint16_t & vendorId, uint16_t & profileNum)
{
#if 0
    ByteSpan * element_array[] = { &certificationDeclaration, &attestationNonce,
                               nullptr,     /* timestamp */
                   &firmwareInfo,
                 };
#endif

    uint32_t validArgumentCount = 0;
    uint32_t currentDecodeTagId = 0;
    bool argExists[4] = { false };  // only check the first 4 elements
    CHIP_ERROR TLVError         = CHIP_NO_ERROR;
    TLV::TLVReader tlvReader;
    TLV::TLVType containerType = TLV::kTLVType_Structure;

    tlvReader.Init(attestationElements.data(), static_cast<uint32_t>(attestationElements.size()));
    ReturnErrorOnFailure(tlvReader.Next(containerType, TLV::AnonymousTag));
    ReturnErrorOnFailure(tlvReader.EnterContainer(containerType));

    while ((TLVError = tlvReader.Next()) == CHIP_NO_ERROR)
    {
        // Since call to aDataTlv.Next() is CHIP_NO_ERROR, the read head always points to an element.
        uint64_t tag;

        tag = tlvReader.GetTag();

        if (TLV::IsContextTag(tag))
        {
            currentDecodeTagId = TLV::TagNumFromTag(tag);
            if(0 == currentDecodeTagId)
                continue;   // ignore tag 0?   or error?
            if(currentDecodeTagId >  LAST_TAG)
               continue;   // ignore tags too high?  or error
            if(true == argExists[currentDecodeTagId - 1])
               return CHIP_ERROR_IM_MALFORMED_COMMAND_DATA_ELEMENT;
            argExists[currentDecodeTagId - 1] = true;
            validArgumentCount++;

            const uint8_t *data = nullptr;
	        // TODO: helper routine for cases 1, 3, 4 -- CHIP_ERROR getByteSpan(field &, tlvReader)
	        switch(currentDecodeTagId) {
	           case CERTIFICATE_DECLARATION:
//	              if(nullptr ==  certificationDeclaration) 
//	                  break;
	              VerifyOrReturnError(tlvReader.GetDataPtr(data) != CHIP_NO_ERROR,  CHIP_ERROR_IM_MALFORMED_COMMAND_DATA_ELEMENT);
	              certificationDeclaration = ByteSpan(data, tlvReader.GetLength());
	              break;
	           case ATTESTATION_NONCE:
//	                if(nullptr == attestationNonce)
//	                    break;
	                VerifyOrReturnError(tlvReader.GetDataPtr(data) != CHIP_NO_ERROR,  CHIP_ERROR_IM_MALFORMED_COMMAND_DATA_ELEMENT);
	                attestationNonce = ByteSpan(data, tlvReader.GetLength());
	                break;
	            case TIMESTAMP:
//	                if(nullptr == timestamp)
//	                    break;
	                VerifyOrReturnError(tlvReader.Get(timestamp) != CHIP_NO_ERROR,  CHIP_ERROR_IM_MALFORMED_COMMAND_DATA_ELEMENT);
	                break;
	            case FIRMWARE_INFO:
//	                if(nullptr == firmwareInfo)
//	                    break;
	                VerifyOrReturnError(tlvReader.GetDataPtr(data) != CHIP_NO_ERROR,  CHIP_ERROR_IM_MALFORMED_COMMAND_DATA_ELEMENT);
	                firmwareInfo = ByteSpan(data, tlvReader.GetLength());
	                break;
	            default:
	                // should never get here?   Error?
	               return CHIP_ERROR_IM_MALFORMED_COMMAND_DATA_ELEMENT;
	        }
         } else if(TLV::IsProfileTag(tag)) {
            // vendor information
         } else {
            // error
            return CHIP_ERROR_IM_MALFORMED_COMMAND_DATA_ELEMENT;
         } 
    }

    return CHIP_NO_ERROR;
}


CHIP_ERROR DeviceAttestation::ConstructAttestationElements(const ByteSpan & certificationDeclaration, const ByteSpan & attestationNonce,
                                        uint32_t timestamp, const ByteSpan & firmwareInfo, 
//                                        std::vector<ByteSpan> &vendorReserved, 
                                        uint16_t vendorId, uint16_t profileNum,
                                        MutableByteSpan & attestationElements )
{
    TLV::TLVWriter tlvWriter;
    TLV::TLVType outerContainerType = TLV::kTLVType_NotSpecified;

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

    // TODO: this has to be changed
#if 0
    uint8_t tagNum = 5;
    for(auto &vendorItem : vendorReserved) {
        if(!vendorItem.empty()) 
        {
            ReturnErrorOnFailure(tlvWriter.Put(TLV::ContextTag(tagNum), vendorItem));
        }
        tagNum++;
    }
#endif

    ReturnErrorOnFailure(tlvWriter.EndContainer(outerContainerType));
    ReturnErrorOnFailure(tlvWriter.Finalize());
    attestationElements = attestationElements.SubSpan(0, tlvWriter.GetLengthWritten());
    
    return CHIP_NO_ERROR;
}


}  // namespace Credentials

}  // namespace chip
