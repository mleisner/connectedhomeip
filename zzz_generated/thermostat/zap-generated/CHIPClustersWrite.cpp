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

// THIS FILE IS GENERATED BY ZAP

#include "CHIPClusters.h"

#include <app-common/zap-generated/cluster-objects.h>
#include <app-common/zap-generated/ids/Attributes.h>

namespace chip {

using namespace app::Clusters;
using namespace System;
using namespace Encoding::LittleEndian;

namespace Controller {

// Identify Cluster Attributes

template CHIP_ERROR ClusterBase::WriteAttribute<chip::app::Clusters::Identify::Attributes::IdentifyTime::TypeInfo>(
    const chip::app::Clusters::Identify::Attributes::IdentifyTime::TypeInfo::Type & requestData, void * context,
    WriteResponseSuccessCallback successCb, WriteResponseFailureCallback failureCb);

template <typename AttributeInfo>
CHIP_ERROR ClusterBase::WriteAttribute(const typename AttributeInfo::Type & requestData, void * context,
                                       WriteResponseSuccessCallback successCb, WriteResponseFailureCallback failureCb)
{
    VerifyOrReturnError(mDevice != nullptr, CHIP_ERROR_INCORRECT_STATE);
    ReturnErrorOnFailure(mDevice->LoadSecureSessionParametersIfNeeded());

    auto onSuccessCb = [context, successCb](const app::ConcreteAttributePath & commandPath) {
        if (successCb != nullptr)
        {
            successCb(context);
        }
    };

    auto onFailureCb = [context, failureCb](const app::ConcreteAttributePath * commandPath, app::StatusIB status,
                                            CHIP_ERROR aError) {
        if (failureCb != nullptr)
        {
            failureCb(context, app::ToEmberAfStatus(status.mStatus));
        }
    };

    return chip::Controller::WriteAttribute<AttributeInfo>(mDevice->GetExchangeManager(), mDevice->GetSecureSession().Value(),
                                                           mEndpoint, requestData, onSuccessCb, onFailureCb);
}

} // namespace Controller
} // namespace chip
