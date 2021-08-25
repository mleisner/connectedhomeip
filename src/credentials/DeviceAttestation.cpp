#include "DeviceAttestation.h"
#include <core/CHIPTLV.h>
#include <support/CodeUtils.h>

namespace chip {
namespace Credentials {

// TODO: vendor data needs fully qualitified IDs -- (vendor ID, profile number, tag #)
// ml -- not sure how to do this

CHIP_ERROR DeconstructAttestationElements(const ByteSpan & attestationElements, ByteSpan & certificationDeclaration,
                                          ByteSpan & attestationNonce, uint32_t & timestamp, ByteSpan & firmwareInfo,
                                          std::vector<ByteSpan> & vendorReserved,
					  uint16_t & vendorId, uint16_t & profileNum)
{
#if 0
    ByteSpan * element_array[] = { &certificationDeclaration, &attestationNonce,
	                           nullptr,  	/* timestamp */
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

   /*
    * prototype code
    *    uint64_t tag;
    *    tag = tlvRead.getTag();
    *    if(TLV::IsContextTag(tlvRead.getTag()) {
    *         // must be 1-4
    *         if(TLV::tlvRead.ElementType() == timeType)
    *              get time
    *         // first four arguments
    *    } else if(TLV::IsProfileTag(tag)) {
    *         // vendor parameters 
    *    }
    */
    while ((TLVError = tlvReader.Next()) == CHIP_NO_ERROR)
    {

        // Since call to aDataTlv.Next() is CHIP_NO_ERROR, the read head always points to an element.
        // Skip this element if it is not a ContextTag, not consider it as an error if other values are valid.
        if (!TLV::IsContextTag(tlvReader.GetTag()))
        {
	    // TODO -- qualified tags for vendor
            continue;
        }
        currentDecodeTagId = TLV::TagNumFromTag(tlvReader.GetTag());
	if (currentDecodeTagId == 0) 
	{
	    continue; 	// tag > 0? 	
        }

	if(currentDecodeTagId < 5) {
            if (true == argExists[currentDecodeTagId - 1])
            {
                // Duplicate TLV tag
                TLVError = CHIP_ERROR_IM_MALFORMED_COMMAND_DATA_ELEMENT;
                break;
            }
            else
            {
                argExists[currentDecodeTagId - 1] = true;
                validArgumentCount++;
            }
        }


	if(TLVError != CHIP_NO_ERROR)	
	    break;

        switch (currentDecodeTagId)
        {
        case 1:
        case 2:
        case 4: 
            {
               const uint8_t * data = nullptr;
               TLVError       = tlvReader.GetDataPtr(data);
#if 0
               if (element_array[currentDecodeTagId - 1] != nullptr)
               {
                   *element_array[currentDecodeTagId - 1] = ByteSpan(data, tlvReader.GetLength());
               }
#endif
            }
            break;
        case 3: 
            TLVError = tlvReader.Get(timestamp);
	    break;
        default:
	    // what to do about the rest of the items 
            break;
        }
        if (CHIP_NO_ERROR != TLVError)
        {
            break;
        }
    }

    if (CHIP_END_OF_TLV != TLVError)
    {
        // CHIP_END_OF_TLV means we have iterated all items in the structure, which is not a real error.
	return TLVError;
    }

#if 0
    // does this make sense now?
    if (validArgumentCount > 8)
    {
        return CHIP_ERROR_INVALID_TLV_ELEMENT;
    }
#endif
    return CHIP_NO_ERROR;
}


CHIP_ERROR ConstructAttestationElements(const ByteSpan & certificationDeclaration, const ByteSpan & attestationNonce,
                                        uint32_t timestamp, const ByteSpan & firmwareInfo, 
                                        std::vector<ByteSpan> &vendorReserved, 
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
    uint8_t tagNum = 5;
    for(auto &vendorItem : vendorReserved) {
        if(!vendorItem.empty()) 
        {
            ReturnErrorOnFailure(tlvWriter.Put(TLV::ContextTag(tagNum), vendorItem));
	}
	tagNum++;
    }

    ReturnErrorOnFailure(tlvWriter.EndContainer(outerContainerType));
    ReturnErrorOnFailure(tlvWriter.Finalize());
    attestationElements = attestationElements.SubSpan(0, tlvWriter.GetLengthWritten());
	
    return CHIP_NO_ERROR;
}


}  // namespace Credentials

}  // namespace chip
