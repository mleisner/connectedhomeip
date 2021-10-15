/*
 *   Copyright (c) 2021 Project CHIP Authors
 *   All rights reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 */

#pragma once

#include <commands/common/Commands.h>
#include <controller/ExampleOperationalCredentialsIssuer.h>
#include <credentials/DeviceAttestationCredsProvider.h>
#include <credentials/DeviceAttestationVerifier.h>
#include <credentials/examples/DeviceAttestationCredsExample.h>
#include <credentials/examples/DeviceAttestationVerifierExample.h>

class ExampleCredentialIssuerCommands : public Commands
{
private:
    CHIP_ERROR InitializeCredentialsIssuer(chip::PersistentStorageDelegate & storage) override
    {
        return mOpCredsIssuer.Initialize(storage);
    }
    CHIP_ERROR SetupDeviceAttestation() override
    {
        chip::Credentials::SetDeviceAttestationCredentialsProvider(chip::Credentials::Examples::GetExampleDACProvider());
        chip::Credentials::SetDeviceAttestationVerifier(chip::Credentials::Examples::GetExampleDACVerifier());
        return CHIP_NO_ERROR;
    }
    chip::Controller::OperationalCredentialsDelegate * GetCredentialIssuer() override { return &mOpCredsIssuer; }
    CHIP_ERROR GenerateControllerNOCChain(NodeId nodeId, FabricId fabricId, chip::Crypto::P256Keypair & keypair,
                                          chip::MutableByteSpan & rcac, chip::MutableByteSpan & icac,
                                          chip::MutableByteSpan & noc) override
    {
        return mOpCredsIssuer.GenerateNOCChainAfterValidation(nodeId, fabricId, keypair.Pubkey(), rcac, icac, noc);
    }

    chip::Controller::ExampleOperationalCredentialsIssuer mOpCredsIssuer;
};
