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

#pragma once

#include <app/util/basic-types.h>

namespace chip {
namespace app {
namespace Clusters {

namespace Globals {
namespace Commands {
namespace Ids {
static constexpr CommandId ReadAttributes                     = 0x00000000;
static constexpr CommandId ReadAttributesResponse             = 0x00000001;
static constexpr CommandId WriteAttributes                    = 0x00000002;
static constexpr CommandId WriteAttributesUndivided           = 0x00000003;
static constexpr CommandId WriteAttributesResponse            = 0x00000004;
static constexpr CommandId WriteAttributesNoResponse          = 0x00000005;
static constexpr CommandId ConfigureReporting                 = 0x00000006;
static constexpr CommandId ConfigureReportingResponse         = 0x00000007;
static constexpr CommandId ReadReportingConfiguration         = 0x00000008;
static constexpr CommandId ReadReportingConfigurationResponse = 0x00000009;
static constexpr CommandId ReportAttributes                   = 0x0000000A;
static constexpr CommandId DefaultResponse                    = 0x0000000B;
static constexpr CommandId DiscoverAttributes                 = 0x0000000C;
static constexpr CommandId DiscoverAttributesResponse         = 0x0000000D;
static constexpr CommandId ReadAttributesStructured           = 0x0000000E;
static constexpr CommandId WriteAttributesStructured          = 0x0000000F;
static constexpr CommandId WriteAttributesStructuredResponse  = 0x00000010;
static constexpr CommandId DiscoverCommandsReceived           = 0x00000011;
static constexpr CommandId DiscoverCommandsReceivedResponse   = 0x00000012;
static constexpr CommandId DiscoverCommandsGenerated          = 0x00000013;
static constexpr CommandId DiscoverCommandsGeneratedResponse  = 0x00000014;
static constexpr CommandId DiscoverAttributesExtended         = 0x00000015;
static constexpr CommandId DiscoverAttributesExtendedResponse = 0x00000016;
} // namespace Ids
} // namespace Commands
} // namespace Globals

namespace Identify {
namespace Commands {
namespace Ids {
static constexpr CommandId Identify              = 0x00000000;
static constexpr CommandId IdentifyQueryResponse = 0x00000000;
static constexpr CommandId IdentifyQuery         = 0x00000001;
static constexpr CommandId EZModeInvoke          = 0x00000002;
static constexpr CommandId UpdateCommissionState = 0x00000003;
static constexpr CommandId TriggerEffect         = 0x00000040;
} // namespace Ids
} // namespace Commands
} // namespace Identify

namespace Groups {
namespace Commands {
namespace Ids {
static constexpr CommandId AddGroup                   = 0x00000000;
static constexpr CommandId AddGroupResponse           = 0x00000000;
static constexpr CommandId ViewGroup                  = 0x00000001;
static constexpr CommandId ViewGroupResponse          = 0x00000001;
static constexpr CommandId GetGroupMembership         = 0x00000002;
static constexpr CommandId GetGroupMembershipResponse = 0x00000002;
static constexpr CommandId RemoveGroup                = 0x00000003;
static constexpr CommandId RemoveGroupResponse        = 0x00000003;
static constexpr CommandId RemoveAllGroups            = 0x00000004;
static constexpr CommandId AddGroupIfIdentifying      = 0x00000005;
} // namespace Ids
} // namespace Commands
} // namespace Groups

namespace Scenes {
namespace Commands {
namespace Ids {
static constexpr CommandId AddScene                   = 0x00000000;
static constexpr CommandId AddSceneResponse           = 0x00000000;
static constexpr CommandId ViewScene                  = 0x00000001;
static constexpr CommandId ViewSceneResponse          = 0x00000001;
static constexpr CommandId RemoveScene                = 0x00000002;
static constexpr CommandId RemoveSceneResponse        = 0x00000002;
static constexpr CommandId RemoveAllScenes            = 0x00000003;
static constexpr CommandId RemoveAllScenesResponse    = 0x00000003;
static constexpr CommandId StoreScene                 = 0x00000004;
static constexpr CommandId StoreSceneResponse         = 0x00000004;
static constexpr CommandId RecallScene                = 0x00000005;
static constexpr CommandId GetSceneMembership         = 0x00000006;
static constexpr CommandId GetSceneMembershipResponse = 0x00000006;
static constexpr CommandId EnhancedAddScene           = 0x00000040;
static constexpr CommandId EnhancedAddSceneResponse   = 0x00000040;
static constexpr CommandId EnhancedViewScene          = 0x00000041;
static constexpr CommandId EnhancedViewSceneResponse  = 0x00000041;
static constexpr CommandId CopyScene                  = 0x00000042;
static constexpr CommandId CopySceneResponse          = 0x00000042;
} // namespace Ids
} // namespace Commands
} // namespace Scenes

namespace OnOff {
namespace Commands {
namespace Ids {
static constexpr CommandId Off                                    = 0x00000000;
static constexpr CommandId SampleMfgSpecificOffWithTransition     = 0x10020000;
static constexpr CommandId On                                     = 0x00000001;
static constexpr CommandId SampleMfgSpecificOnWithTransition      = 0x10020001;
static constexpr CommandId SampleMfgSpecificOnWithTransition2     = 0x10490001;
static constexpr CommandId Toggle                                 = 0x00000002;
static constexpr CommandId SampleMfgSpecificToggleWithTransition  = 0x10020002;
static constexpr CommandId SampleMfgSpecificToggleWithTransition2 = 0x10490002;
static constexpr CommandId OffWithEffect                          = 0x00000040;
static constexpr CommandId OnWithRecallGlobalScene                = 0x00000041;
static constexpr CommandId OnWithTimedOff                         = 0x00000042;
} // namespace Ids
} // namespace Commands
} // namespace OnOff

namespace LevelControl {
namespace Commands {
namespace Ids {
static constexpr CommandId MoveToLevel          = 0x00000000;
static constexpr CommandId Move                 = 0x00000001;
static constexpr CommandId Step                 = 0x00000002;
static constexpr CommandId Stop                 = 0x00000003;
static constexpr CommandId MoveToLevelWithOnOff = 0x00000004;
static constexpr CommandId MoveWithOnOff        = 0x00000005;
static constexpr CommandId StepWithOnOff        = 0x00000006;
static constexpr CommandId StopWithOnOff        = 0x00000007;
} // namespace Ids
} // namespace Commands
} // namespace LevelControl

namespace Alarms {
namespace Commands {
namespace Ids {
static constexpr CommandId ResetAlarm       = 0x00000000;
static constexpr CommandId Alarm            = 0x00000000;
static constexpr CommandId ResetAllAlarms   = 0x00000001;
static constexpr CommandId GetAlarmResponse = 0x00000001;
static constexpr CommandId GetAlarm         = 0x00000002;
static constexpr CommandId ResetAlarmLog    = 0x00000003;
} // namespace Ids
} // namespace Commands
} // namespace Alarms

namespace PowerProfile {
namespace Commands {
namespace Ids {
static constexpr CommandId PowerProfileRequest                         = 0x00000000;
static constexpr CommandId PowerProfileNotification                    = 0x00000000;
static constexpr CommandId PowerProfileStateRequest                    = 0x00000001;
static constexpr CommandId PowerProfileResponse                        = 0x00000001;
static constexpr CommandId GetPowerProfilePriceResponse                = 0x00000002;
static constexpr CommandId PowerProfileStateResponse                   = 0x00000002;
static constexpr CommandId GetOverallSchedulePriceResponse             = 0x00000003;
static constexpr CommandId GetPowerProfilePrice                        = 0x00000003;
static constexpr CommandId EnergyPhasesScheduleNotification            = 0x00000004;
static constexpr CommandId PowerProfilesStateNotification              = 0x00000004;
static constexpr CommandId EnergyPhasesScheduleResponse                = 0x00000005;
static constexpr CommandId GetOverallSchedulePrice                     = 0x00000005;
static constexpr CommandId PowerProfileScheduleConstraintsRequest      = 0x00000006;
static constexpr CommandId EnergyPhasesScheduleRequest                 = 0x00000006;
static constexpr CommandId EnergyPhasesScheduleStateRequest            = 0x00000007;
static constexpr CommandId EnergyPhasesScheduleStateResponse           = 0x00000007;
static constexpr CommandId GetPowerProfilePriceExtendedResponse        = 0x00000008;
static constexpr CommandId EnergyPhasesScheduleStateNotification       = 0x00000008;
static constexpr CommandId PowerProfileScheduleConstraintsNotification = 0x00000009;
static constexpr CommandId PowerProfileScheduleConstraintsResponse     = 0x0000000A;
static constexpr CommandId GetPowerProfilePriceExtended                = 0x0000000B;
} // namespace Ids
} // namespace Commands
} // namespace PowerProfile

namespace ApplianceControl {
namespace Commands {
namespace Ids {
static constexpr CommandId ExecutionOfACommand     = 0x00000000;
static constexpr CommandId SignalStateResponse     = 0x00000000;
static constexpr CommandId SignalState             = 0x00000001;
static constexpr CommandId SignalStateNotification = 0x00000001;
static constexpr CommandId WriteFunctions          = 0x00000002;
static constexpr CommandId OverloadPauseResume     = 0x00000003;
static constexpr CommandId OverloadPause           = 0x00000004;
static constexpr CommandId OverloadWarning         = 0x00000005;
} // namespace Ids
} // namespace Commands
} // namespace ApplianceControl

namespace PollControl {
namespace Commands {
namespace Ids {
static constexpr CommandId CheckIn              = 0x00000000;
static constexpr CommandId CheckInResponse      = 0x00000000;
static constexpr CommandId FastPollStop         = 0x00000001;
static constexpr CommandId SetLongPollInterval  = 0x00000002;
static constexpr CommandId SetShortPollInterval = 0x00000003;
} // namespace Ids
} // namespace Commands
} // namespace PollControl

namespace Basic {
namespace Commands {
namespace Ids {
static constexpr CommandId StartUp         = 0x00000000;
static constexpr CommandId MfgSpecificPing = 0x10020000;
static constexpr CommandId ShutDown        = 0x00000001;
static constexpr CommandId Leave           = 0x00000002;
} // namespace Ids
} // namespace Commands
} // namespace Basic

namespace OtaSoftwareUpdateProvider {
namespace Commands {
namespace Ids {
static constexpr CommandId QueryImage                 = 0x00000000;
static constexpr CommandId ApplyUpdateRequest         = 0x00000001;
static constexpr CommandId NotifyUpdateApplied        = 0x00000002;
static constexpr CommandId QueryImageResponse         = 0x00000003;
static constexpr CommandId ApplyUpdateRequestResponse = 0x00000004;
} // namespace Ids
} // namespace Commands
} // namespace OtaSoftwareUpdateProvider

namespace OtaSoftwareUpdateRequestor {
namespace Commands {
namespace Ids {
static constexpr CommandId AnnounceOtaProvider = 0x00000000;
} // namespace Ids
} // namespace Commands
} // namespace OtaSoftwareUpdateRequestor

namespace GeneralCommissioning {
namespace Commands {
namespace Ids {
static constexpr CommandId ArmFailSafe                   = 0x00000000;
static constexpr CommandId ArmFailSafeResponse           = 0x00000001;
static constexpr CommandId SetRegulatoryConfig           = 0x00000002;
static constexpr CommandId SetRegulatoryConfigResponse   = 0x00000003;
static constexpr CommandId CommissioningComplete         = 0x00000004;
static constexpr CommandId CommissioningCompleteResponse = 0x00000005;
} // namespace Ids
} // namespace Commands
} // namespace GeneralCommissioning

namespace NetworkCommissioning {
namespace Commands {
namespace Ids {
static constexpr CommandId ScanNetworks                      = 0x00000000;
static constexpr CommandId ScanNetworksResponse              = 0x00000001;
static constexpr CommandId AddWiFiNetwork                    = 0x00000002;
static constexpr CommandId AddWiFiNetworkResponse            = 0x00000003;
static constexpr CommandId UpdateWiFiNetwork                 = 0x00000004;
static constexpr CommandId UpdateWiFiNetworkResponse         = 0x00000005;
static constexpr CommandId AddThreadNetwork                  = 0x00000006;
static constexpr CommandId AddThreadNetworkResponse          = 0x00000007;
static constexpr CommandId UpdateThreadNetwork               = 0x00000008;
static constexpr CommandId UpdateThreadNetworkResponse       = 0x00000009;
static constexpr CommandId RemoveNetwork                     = 0x0000000A;
static constexpr CommandId RemoveNetworkResponse             = 0x0000000B;
static constexpr CommandId EnableNetwork                     = 0x0000000C;
static constexpr CommandId EnableNetworkResponse             = 0x0000000D;
static constexpr CommandId DisableNetwork                    = 0x0000000E;
static constexpr CommandId DisableNetworkResponse            = 0x0000000F;
static constexpr CommandId GetLastNetworkCommissioningResult = 0x00000010;
} // namespace Ids
} // namespace Commands
} // namespace NetworkCommissioning

namespace DiagnosticLogs {
namespace Commands {
namespace Ids {
static constexpr CommandId RetrieveLogsRequest  = 0x00000000;
static constexpr CommandId RetrieveLogsResponse = 0x00000001;
} // namespace Ids
} // namespace Commands
} // namespace DiagnosticLogs

namespace SoftwareDiagnostics {
namespace Commands {
namespace Ids {
static constexpr CommandId ResetWatermarks = 0x00000000;
} // namespace Ids
} // namespace Commands
} // namespace SoftwareDiagnostics

namespace ThreadNetworkDiagnostics {
namespace Commands {
namespace Ids {
static constexpr CommandId ResetCounts = 0x00000000;
} // namespace Ids
} // namespace Commands
} // namespace ThreadNetworkDiagnostics

namespace WiFiNetworkDiagnostics {
namespace Commands {
namespace Ids {
static constexpr CommandId ResetCounts = 0x00000000;
} // namespace Ids
} // namespace Commands
} // namespace WiFiNetworkDiagnostics

namespace EthernetNetworkDiagnostics {
namespace Commands {
namespace Ids {
static constexpr CommandId ResetCounts = 0x00000000;
} // namespace Ids
} // namespace Commands
} // namespace EthernetNetworkDiagnostics

namespace BridgedDeviceBasic {
namespace Commands {
namespace Ids {
static constexpr CommandId StartUp          = 0x00000000;
static constexpr CommandId ShutDown         = 0x00000001;
static constexpr CommandId Leave            = 0x00000002;
static constexpr CommandId ReachableChanged = 0x00000003;
} // namespace Ids
} // namespace Commands
} // namespace BridgedDeviceBasic

namespace AdministratorCommissioning {
namespace Commands {
namespace Ids {
static constexpr CommandId OpenCommissioningWindow      = 0x00000000;
static constexpr CommandId OpenBasicCommissioningWindow = 0x00000001;
static constexpr CommandId RevokeCommissioning          = 0x00000002;
} // namespace Ids
} // namespace Commands
} // namespace AdministratorCommissioning

namespace OperationalCredentials {
namespace Commands {
namespace Ids {
static constexpr CommandId AttestationRequest           = 0x00000000;
static constexpr CommandId AttestationResponse          = 0x00000001;
static constexpr CommandId CertificateChainRequest      = 0x00000002;
static constexpr CommandId CertificateChainResponse     = 0x00000003;
static constexpr CommandId OpCSRRequest                 = 0x00000004;
static constexpr CommandId OpCSRResponse                = 0x00000005;
static constexpr CommandId AddNOC                       = 0x00000006;
static constexpr CommandId UpdateNOC                    = 0x00000007;
static constexpr CommandId NOCResponse                  = 0x00000008;
static constexpr CommandId UpdateFabricLabel            = 0x00000009;
static constexpr CommandId RemoveFabric                 = 0x0000000A;
static constexpr CommandId AddTrustedRootCertificate    = 0x0000000B;
static constexpr CommandId RemoveTrustedRootCertificate = 0x0000000C;
} // namespace Ids
} // namespace Commands
} // namespace OperationalCredentials

namespace DoorLock {
namespace Commands {
namespace Ids {
static constexpr CommandId LockDoor                     = 0x00000000;
static constexpr CommandId LockDoorResponse             = 0x00000000;
static constexpr CommandId UnlockDoor                   = 0x00000001;
static constexpr CommandId UnlockDoorResponse           = 0x00000001;
static constexpr CommandId Toggle                       = 0x00000002;
static constexpr CommandId ToggleResponse               = 0x00000002;
static constexpr CommandId UnlockWithTimeout            = 0x00000003;
static constexpr CommandId UnlockWithTimeoutResponse    = 0x00000003;
static constexpr CommandId GetLogRecord                 = 0x00000004;
static constexpr CommandId GetLogRecordResponse         = 0x00000004;
static constexpr CommandId SetPin                       = 0x00000005;
static constexpr CommandId SetPinResponse               = 0x00000005;
static constexpr CommandId GetPin                       = 0x00000006;
static constexpr CommandId GetPinResponse               = 0x00000006;
static constexpr CommandId ClearPin                     = 0x00000007;
static constexpr CommandId ClearPinResponse             = 0x00000007;
static constexpr CommandId ClearAllPins                 = 0x00000008;
static constexpr CommandId ClearAllPinsResponse         = 0x00000008;
static constexpr CommandId SetUserStatus                = 0x00000009;
static constexpr CommandId SetUserStatusResponse        = 0x00000009;
static constexpr CommandId GetUserStatus                = 0x0000000A;
static constexpr CommandId GetUserStatusResponse        = 0x0000000A;
static constexpr CommandId SetWeekdaySchedule           = 0x0000000B;
static constexpr CommandId SetWeekdayScheduleResponse   = 0x0000000B;
static constexpr CommandId GetWeekdaySchedule           = 0x0000000C;
static constexpr CommandId GetWeekdayScheduleResponse   = 0x0000000C;
static constexpr CommandId ClearWeekdaySchedule         = 0x0000000D;
static constexpr CommandId ClearWeekdayScheduleResponse = 0x0000000D;
static constexpr CommandId SetYeardaySchedule           = 0x0000000E;
static constexpr CommandId SetYeardayScheduleResponse   = 0x0000000E;
static constexpr CommandId GetYeardaySchedule           = 0x0000000F;
static constexpr CommandId GetYeardayScheduleResponse   = 0x0000000F;
static constexpr CommandId ClearYeardaySchedule         = 0x00000010;
static constexpr CommandId ClearYeardayScheduleResponse = 0x00000010;
static constexpr CommandId SetHolidaySchedule           = 0x00000011;
static constexpr CommandId SetHolidayScheduleResponse   = 0x00000011;
static constexpr CommandId GetHolidaySchedule           = 0x00000012;
static constexpr CommandId GetHolidayScheduleResponse   = 0x00000012;
static constexpr CommandId ClearHolidaySchedule         = 0x00000013;
static constexpr CommandId ClearHolidayScheduleResponse = 0x00000013;
static constexpr CommandId SetUserType                  = 0x00000014;
static constexpr CommandId SetUserTypeResponse          = 0x00000014;
static constexpr CommandId GetUserType                  = 0x00000015;
static constexpr CommandId GetUserTypeResponse          = 0x00000015;
static constexpr CommandId SetRfid                      = 0x00000016;
static constexpr CommandId SetRfidResponse              = 0x00000016;
static constexpr CommandId GetRfid                      = 0x00000017;
static constexpr CommandId GetRfidResponse              = 0x00000017;
static constexpr CommandId ClearRfid                    = 0x00000018;
static constexpr CommandId ClearRfidResponse            = 0x00000018;
static constexpr CommandId ClearAllRfids                = 0x00000019;
static constexpr CommandId ClearAllRfidsResponse        = 0x00000019;
static constexpr CommandId OperationEventNotification   = 0x00000020;
static constexpr CommandId ProgrammingEventNotification = 0x00000021;
} // namespace Ids
} // namespace Commands
} // namespace DoorLock

namespace WindowCovering {
namespace Commands {
namespace Ids {
static constexpr CommandId UpOrOpen           = 0x00000000;
static constexpr CommandId DownOrClose        = 0x00000001;
static constexpr CommandId StopMotion         = 0x00000002;
static constexpr CommandId GoToLiftValue      = 0x00000004;
static constexpr CommandId GoToLiftPercentage = 0x00000005;
static constexpr CommandId GoToTiltValue      = 0x00000007;
static constexpr CommandId GoToTiltPercentage = 0x00000008;
} // namespace Ids
} // namespace Commands
} // namespace WindowCovering

namespace BarrierControl {
namespace Commands {
namespace Ids {
static constexpr CommandId BarrierControlGoToPercent = 0x00000000;
static constexpr CommandId BarrierControlStop        = 0x00000001;
} // namespace Ids
} // namespace Commands
} // namespace BarrierControl

namespace Thermostat {
namespace Commands {
namespace Ids {
static constexpr CommandId SetpointRaiseLower    = 0x00000000;
static constexpr CommandId CurrentWeeklySchedule = 0x00000000;
static constexpr CommandId SetWeeklySchedule     = 0x00000001;
static constexpr CommandId RelayStatusLog        = 0x00000001;
static constexpr CommandId GetWeeklySchedule     = 0x00000002;
static constexpr CommandId ClearWeeklySchedule   = 0x00000003;
static constexpr CommandId GetRelayStatusLog     = 0x00000004;
} // namespace Ids
} // namespace Commands
} // namespace Thermostat

namespace ColorControl {
namespace Commands {
namespace Ids {
static constexpr CommandId MoveToHue                      = 0x00000000;
static constexpr CommandId MoveHue                        = 0x00000001;
static constexpr CommandId StepHue                        = 0x00000002;
static constexpr CommandId MoveToSaturation               = 0x00000003;
static constexpr CommandId MoveSaturation                 = 0x00000004;
static constexpr CommandId StepSaturation                 = 0x00000005;
static constexpr CommandId MoveToHueAndSaturation         = 0x00000006;
static constexpr CommandId MoveToColor                    = 0x00000007;
static constexpr CommandId MoveColor                      = 0x00000008;
static constexpr CommandId StepColor                      = 0x00000009;
static constexpr CommandId MoveToColorTemperature         = 0x0000000A;
static constexpr CommandId EnhancedMoveToHue              = 0x00000040;
static constexpr CommandId EnhancedMoveHue                = 0x00000041;
static constexpr CommandId EnhancedStepHue                = 0x00000042;
static constexpr CommandId EnhancedMoveToHueAndSaturation = 0x00000043;
static constexpr CommandId ColorLoopSet                   = 0x00000044;
static constexpr CommandId StopMoveStep                   = 0x00000047;
static constexpr CommandId MoveColorTemperature           = 0x0000004B;
static constexpr CommandId StepColorTemperature           = 0x0000004C;
} // namespace Ids
} // namespace Commands
} // namespace ColorControl

namespace IasZone {
namespace Commands {
namespace Ids {
static constexpr CommandId ZoneEnrollResponse                  = 0x00000000;
static constexpr CommandId ZoneStatusChangeNotification        = 0x00000000;
static constexpr CommandId InitiateNormalOperationMode         = 0x00000001;
static constexpr CommandId ZoneEnrollRequest                   = 0x00000001;
static constexpr CommandId InitiateTestMode                    = 0x00000002;
static constexpr CommandId InitiateNormalOperationModeResponse = 0x00000002;
static constexpr CommandId InitiateTestModeResponse            = 0x00000003;
} // namespace Ids
} // namespace Commands
} // namespace IasZone

namespace IasAce {
namespace Commands {
namespace Ids {
static constexpr CommandId Arm                        = 0x00000000;
static constexpr CommandId ArmResponse                = 0x00000000;
static constexpr CommandId Bypass                     = 0x00000001;
static constexpr CommandId GetZoneIdMapResponse       = 0x00000001;
static constexpr CommandId Emergency                  = 0x00000002;
static constexpr CommandId GetZoneInformationResponse = 0x00000002;
static constexpr CommandId Fire                       = 0x00000003;
static constexpr CommandId ZoneStatusChanged          = 0x00000003;
static constexpr CommandId Panic                      = 0x00000004;
static constexpr CommandId PanelStatusChanged         = 0x00000004;
static constexpr CommandId GetZoneIdMap               = 0x00000005;
static constexpr CommandId GetPanelStatusResponse     = 0x00000005;
static constexpr CommandId GetZoneInformation         = 0x00000006;
static constexpr CommandId SetBypassedZoneList        = 0x00000006;
static constexpr CommandId GetPanelStatus             = 0x00000007;
static constexpr CommandId BypassResponse             = 0x00000007;
static constexpr CommandId GetBypassedZoneList        = 0x00000008;
static constexpr CommandId GetZoneStatusResponse      = 0x00000008;
static constexpr CommandId GetZoneStatus              = 0x00000009;
} // namespace Ids
} // namespace Commands
} // namespace IasAce

namespace IasWd {
namespace Commands {
namespace Ids {
static constexpr CommandId StartWarning = 0x00000000;
static constexpr CommandId Squawk       = 0x00000001;
} // namespace Ids
} // namespace Commands
} // namespace IasWd

namespace TvChannel {
namespace Commands {
namespace Ids {
static constexpr CommandId ChangeChannel         = 0x00000000;
static constexpr CommandId ChangeChannelResponse = 0x00000000;
static constexpr CommandId ChangeChannelByNumber = 0x00000001;
static constexpr CommandId SkipChannel           = 0x00000002;
} // namespace Ids
} // namespace Commands
} // namespace TvChannel

namespace TargetNavigator {
namespace Commands {
namespace Ids {
static constexpr CommandId NavigateTarget         = 0x00000000;
static constexpr CommandId NavigateTargetResponse = 0x00000000;
} // namespace Ids
} // namespace Commands
} // namespace TargetNavigator

namespace MediaPlayback {
namespace Commands {
namespace Ids {
static constexpr CommandId MediaPlay                 = 0x00000000;
static constexpr CommandId MediaPlayResponse         = 0x00000000;
static constexpr CommandId MediaPause                = 0x00000001;
static constexpr CommandId MediaPauseResponse        = 0x00000001;
static constexpr CommandId MediaStop                 = 0x00000002;
static constexpr CommandId MediaStopResponse         = 0x00000002;
static constexpr CommandId MediaStartOver            = 0x00000003;
static constexpr CommandId MediaStartOverResponse    = 0x00000003;
static constexpr CommandId MediaPrevious             = 0x00000004;
static constexpr CommandId MediaPreviousResponse     = 0x00000004;
static constexpr CommandId MediaNext                 = 0x00000005;
static constexpr CommandId MediaNextResponse         = 0x00000005;
static constexpr CommandId MediaRewind               = 0x00000006;
static constexpr CommandId MediaRewindResponse       = 0x00000006;
static constexpr CommandId MediaFastForward          = 0x00000007;
static constexpr CommandId MediaFastForwardResponse  = 0x00000007;
static constexpr CommandId MediaSkipForward          = 0x00000008;
static constexpr CommandId MediaSkipForwardResponse  = 0x00000008;
static constexpr CommandId MediaSkipBackward         = 0x00000009;
static constexpr CommandId MediaSkipBackwardResponse = 0x00000009;
static constexpr CommandId MediaSeek                 = 0x0000000A;
static constexpr CommandId MediaSeekResponse         = 0x0000000B;
} // namespace Ids
} // namespace Commands
} // namespace MediaPlayback

namespace MediaInput {
namespace Commands {
namespace Ids {
static constexpr CommandId SelectInput     = 0x00000000;
static constexpr CommandId ShowInputStatus = 0x00000001;
static constexpr CommandId HideInputStatus = 0x00000002;
static constexpr CommandId RenameInput     = 0x00000003;
} // namespace Ids
} // namespace Commands
} // namespace MediaInput

namespace LowPower {
namespace Commands {
namespace Ids {
static constexpr CommandId Sleep = 0x00000000;
} // namespace Ids
} // namespace Commands
} // namespace LowPower

namespace KeypadInput {
namespace Commands {
namespace Ids {
static constexpr CommandId SendKey         = 0x00000000;
static constexpr CommandId SendKeyResponse = 0x00000000;
} // namespace Ids
} // namespace Commands
} // namespace KeypadInput

namespace ContentLauncher {
namespace Commands {
namespace Ids {
static constexpr CommandId LaunchContent         = 0x00000000;
static constexpr CommandId LaunchContentResponse = 0x00000000;
static constexpr CommandId LaunchURL             = 0x00000001;
static constexpr CommandId LaunchURLResponse     = 0x00000001;
} // namespace Ids
} // namespace Commands
} // namespace ContentLauncher

namespace AudioOutput {
namespace Commands {
namespace Ids {
static constexpr CommandId SelectOutput = 0x00000000;
static constexpr CommandId RenameOutput = 0x00000001;
} // namespace Ids
} // namespace Commands
} // namespace AudioOutput

namespace ApplicationLauncher {
namespace Commands {
namespace Ids {
static constexpr CommandId LaunchApp         = 0x00000000;
static constexpr CommandId LaunchAppResponse = 0x00000000;
} // namespace Ids
} // namespace Commands
} // namespace ApplicationLauncher

namespace ApplicationBasic {
namespace Commands {
namespace Ids {
static constexpr CommandId ChangeStatus = 0x00000000;
} // namespace Ids
} // namespace Commands
} // namespace ApplicationBasic

namespace AccountLogin {
namespace Commands {
namespace Ids {
static constexpr CommandId GetSetupPIN         = 0x00000000;
static constexpr CommandId GetSetupPINResponse = 0x00000000;
static constexpr CommandId Login               = 0x00000001;
} // namespace Ids
} // namespace Commands
} // namespace AccountLogin

namespace TestCluster {
namespace Commands {
namespace Ids {
static constexpr CommandId Test                     = 0x00000000;
static constexpr CommandId TestSpecificResponse     = 0x00000000;
static constexpr CommandId TestNotHandled           = 0x00000001;
static constexpr CommandId TestAddArgumentsResponse = 0x00000001;
static constexpr CommandId TestSpecific             = 0x00000002;
static constexpr CommandId TestUnknownCommand       = 0x00000003;
static constexpr CommandId TestAddArguments         = 0x00000004;
} // namespace Ids
} // namespace Commands
} // namespace TestCluster

namespace Messaging {
namespace Commands {
namespace Ids {
static constexpr CommandId DisplayMessage          = 0x00000000;
static constexpr CommandId GetLastMessage          = 0x00000000;
static constexpr CommandId CancelMessage           = 0x00000001;
static constexpr CommandId MessageConfirmation     = 0x00000001;
static constexpr CommandId DisplayProtectedMessage = 0x00000002;
static constexpr CommandId GetMessageCancellation  = 0x00000002;
static constexpr CommandId CancelAllMessages       = 0x00000003;
} // namespace Ids
} // namespace Commands
} // namespace Messaging

namespace ApplianceEventsAndAlert {
namespace Commands {
namespace Ids {
static constexpr CommandId GetAlerts          = 0x00000000;
static constexpr CommandId GetAlertsResponse  = 0x00000000;
static constexpr CommandId AlertsNotification = 0x00000001;
static constexpr CommandId EventsNotification = 0x00000002;
} // namespace Ids
} // namespace Commands
} // namespace ApplianceEventsAndAlert

namespace ApplianceStatistics {
namespace Commands {
namespace Ids {
static constexpr CommandId LogNotification     = 0x00000000;
static constexpr CommandId LogRequest          = 0x00000000;
static constexpr CommandId LogResponse         = 0x00000001;
static constexpr CommandId LogQueueRequest     = 0x00000001;
static constexpr CommandId LogQueueResponse    = 0x00000002;
static constexpr CommandId StatisticsAvailable = 0x00000003;
} // namespace Ids
} // namespace Commands
} // namespace ApplianceStatistics

namespace ElectricalMeasurement {
namespace Commands {
namespace Ids {
static constexpr CommandId GetProfileInfoResponseCommand        = 0x00000000;
static constexpr CommandId GetProfileInfoCommand                = 0x00000000;
static constexpr CommandId GetMeasurementProfileResponseCommand = 0x00000001;
static constexpr CommandId GetMeasurementProfileCommand         = 0x00000001;
} // namespace Ids
} // namespace Commands
} // namespace ElectricalMeasurement

namespace Binding {
namespace Commands {
namespace Ids {
static constexpr CommandId Bind   = 0x00000000;
static constexpr CommandId Unbind = 0x00000001;
} // namespace Ids
} // namespace Commands
} // namespace Binding

namespace SampleMfgSpecificCluster {
namespace Commands {
namespace Ids {
static constexpr CommandId CommandOne = 0x10020000;
} // namespace Ids
} // namespace Commands
} // namespace SampleMfgSpecificCluster

namespace SampleMfgSpecificCluster2 {
namespace Commands {
namespace Ids {
static constexpr CommandId CommandTwo = 0x10490000;
} // namespace Ids
} // namespace Commands
} // namespace SampleMfgSpecificCluster2

} // namespace Clusters
} // namespace app
} // namespace chip
