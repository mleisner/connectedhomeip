/*
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

#include <app/tests/AppTestContext.h>

#include <app/InteractionModelEngine.h>
#include <lib/support/CodeUtils.h>
#include <lib/support/ErrorStr.h>

namespace chip {
namespace Test {

CHIP_ERROR AppContext::Init()
{
    ReturnErrorOnFailure(chip::Platform::MemoryInit());
    ReturnErrorOnFailure(mIOContext.Init());
    ReturnErrorOnFailure(mTransportManager.Init("LOOPBACK"));
    ReturnErrorOnFailure(MessagingContext::Init(&mTransportManager, &mIOContext));
    ReturnErrorOnFailure(chip::app::InteractionModelEngine::GetInstance()->Init(&GetExchangeManager(), nullptr));

    return CHIP_NO_ERROR;
}

CHIP_ERROR AppContext::Shutdown()
{
    ReturnErrorOnFailure(MessagingContext::Shutdown());
    ReturnErrorOnFailure(mIOContext.Shutdown());
    chip::Platform::MemoryShutdown();

    return CHIP_NO_ERROR;
}

} // namespace Test
} // namespace chip
