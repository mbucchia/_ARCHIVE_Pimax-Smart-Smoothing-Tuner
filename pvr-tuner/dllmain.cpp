// MIT License
//
// Copyright(c) 2022 Matthieu Bucchianeri
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this softwareand associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and /or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright noticeand this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "pch.h"

// I reuse the tracelogging GUID from PimaxXR for simplicity.
// {cbf3adcd-42b1-4c38-830b-91980af201f6}
TRACELOGGING_DEFINE_PROVIDER(g_traceProvider,
                             "PimaxOpenXR",
                             (0xcbf3adcd, 0x42b1, 0x4c38, 0x83, 0x0b, 0x91, 0x98, 0x0a, 0xf2, 0x01, 0xf6));

TraceLoggingActivity<g_traceProvider> g_traceActivity;

#define TraceLocalActivity(activity) TraceLoggingActivity<g_traceProvider> activity;

#define TLArg(var, ...) TraceLoggingValue(var, ##__VA_ARGS__)
#define TLPArg(var, ...) TraceLoggingPointer(var, ##__VA_ARGS__)

namespace {
    const std::string RegPrefix = "SOFTWARE\\Pimax-Tuner";
}

namespace util {

    // https://docs.microsoft.com/en-us/archive/msdn-magazine/2017/may/c-use-modern-c-to-access-the-windows-registry
    static std::optional<int> RegGetDword(HKEY hKey, const std::string_view& subKey, const std::string_view& value) {
        DWORD data{};
        DWORD dataSize = sizeof(data);
        LONG retCode = ::RegGetValue(hKey,
                                     std::wstring(subKey.begin(), subKey.end()).c_str(),
                                     std::wstring(value.begin(), value.end()).c_str(),
                                     RRF_RT_REG_DWORD,
                                     nullptr,
                                     &data,
                                     &dataSize);
        if (retCode != ERROR_SUCCESS) {
            return {};
        }
        return data;
    }

    std::optional<int> getSetting(const std::string_view& value) {
        return RegGetDword(HKEY_LOCAL_MACHINE, RegPrefix, value);
    }

    static inline std::string ToString(pvrResult result) {
        switch (result) {
        case pvr_success:
            return "Success";
        case pvr_failed:
            return "Failed";
        case pvr_dll_failed:
            return "DLL Failed";
        case pvr_dll_wrong:
            return "DLL Wrong";
        case pvr_interface_not_found:
            return "Interface not found";
        case pvr_invalid_param:
            return "Invalid Parameter";
        case pvr_rpc_failed:
            return "RPC Failed";
        case pvr_share_mem_failed:
            return "Share Memory Failed";
        case pvr_unsupport_render_name:
            return "Unsupported Render Name";
        case pvr_no_display:
            return "No Display";
        case pvr_no_render_device:
            return "No Render Device";
        case pvr_app_not_visible:
            return "App Not Visible";
        case pvr_srv_not_ready:
            return "Service Not Ready";
        case pvr_dll_srv_mismatch:
            return "DLL Mismatch";
        case pvr_app_adapter_mismatch:
            return "App Adapter Mismatch";
        case pvr_not_support:
            return " Not Supported";

        default:
            return fmt::format("pvrResult_{}", result);
        }
    }

    namespace {

        std::ofstream g_logStream;

        // Utility logging function.
        void InternalLog(const char* fmt, va_list va) {
            const std::time_t now = std::time(nullptr);

            char buf[1024];
            size_t offset = std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S %z: ", std::localtime(&now));
            vsnprintf_s(buf + offset, sizeof(buf) - offset, _TRUNCATE, fmt, va);
            OutputDebugStringA(buf);
            if (g_logStream.is_open()) {
                g_logStream << buf;
                g_logStream.flush();
            }
        }

    } // namespace

    void Log(const char* fmt, ...) {
        va_list va;
        va_start(va, fmt);
        InternalLog(fmt, va);
        va_end(va);
    }

} // namespace util

namespace {
    using namespace util;

    std::mutex g_globalLock;
    wil::unique_hmodule g_realPvrLibrary;

    pvrInterface g_realPvrInterface{};
    bool g_realPvrInterfaceValid = false;

    wil::unique_registry_watcher g_registryWatcher;

    float g_actualRefreshRate = 90.f;
    float g_latestClientRenderMs = -1.f;
    float g_latestAdjustedClientRenderMs = -1.f;

    std::deque<float> g_ClientRenderMsFilter;

    std::filesystem::path g_localAppData;
    std::ofstream g_logStats;

    struct {
        bool writeToCsv{false};
        uint32_t filterLength{15};
        std::optional<float> absoluteRenderMsFloor;
        std::optional<float> absoluteRenderMsCeiling;
        std::optional<float> keepoutRenderMsLower;
        std::optional<float> keepoutRenderMsUpper;
        std::optional<float> pullUpRenderMsLower;
        std::optional<float> pullUpRenderMsUpper;
        std::optional<float> pullDownRenderMsLower;
        std::optional<float> pullDownRenderMsUpper;
        std::optional<float> biasRenderMs;
    } g_settings;

    void refreshSettings() {
        std::unique_lock lock(g_globalLock);

        g_settings.writeToCsv = getSetting("frame_time_log_to_csv").value_or(0);

        const auto referenceRefreshRate = getSetting("frame_time_reference_refresh_rate").value_or(90);

        // Multiplier to transpose settings from the reference refresh rate into the actual refresh rate.
        const auto multiplier = referenceRefreshRate / g_actualRefreshRate;
        TraceLoggingWrite(g_traceProvider, "Settings", TLArg(multiplier));

        const auto getOptionalSettingMs = [multiplier](const std::string_view& setting) -> std::optional<float> {
            const auto valueUs = getSetting(setting);
            if (valueUs) {
                const auto value = (valueUs.value() / 1e3f) * multiplier;
                TraceLoggingWrite(g_traceProvider, "Settings", TLArg(setting.data(), "setting"), TLArg(value, "value"));
                return value;
            } else {
                TraceLoggingWrite(
                    g_traceProvider, "Settings", TLArg(setting.data(), "setting"), TLArg("Not set", "value"));
                return std::nullopt;
            }
        };

        g_settings.absoluteRenderMsFloor = getOptionalSettingMs("frame_time_absolute_floor_us");
        g_settings.absoluteRenderMsCeiling = getOptionalSettingMs("frame_time_absolute_ceil_us");
        g_settings.keepoutRenderMsLower = getOptionalSettingMs("frame_time_keepout_lower_us");
        g_settings.keepoutRenderMsUpper = getOptionalSettingMs("frame_time_keepout_upper_us");
        g_settings.pullUpRenderMsLower = getOptionalSettingMs("frame_time_pullup_lower_us");
        g_settings.pullUpRenderMsUpper = getOptionalSettingMs("frame_time_pullup_upper_us");
        g_settings.pullDownRenderMsLower = getOptionalSettingMs("frame_time_pulldown_lower_us");
        g_settings.pullDownRenderMsUpper = getOptionalSettingMs("frame_time_pulldown_upper_us");
        g_settings.biasRenderMs = getOptionalSettingMs("frame_time_override_offset");

        g_settings.filterLength = getSetting("frame_time_filter_length").value_or(15);
        TraceLoggingWrite(g_traceProvider, "Settings", TLArg(g_settings.filterLength, "frame_time_filter_length"));
    }

    pvrResult wrapper_initialise() {
        TraceLocalActivity(local);

        TraceLoggingWriteStart(local, "PVR_initialize");
        const auto& result = g_realPvrInterface.initialise();
        TraceLoggingWriteStop(local, "PVR_initialize", TLArg(ToString(result).c_str(), "result"));

        Log("PVR initialization: %s.\n", ToString(result).c_str());

        return result;
    }

    void wrapper_shutdown() {
        TraceLocalActivity(local);

        TraceLoggingWriteStart(local, "PVR_shutdown");
        g_realPvrInterface.shutdown();
        TraceLoggingWriteStop(local, "PVR_shutdown");
    }

    const char* wrapper_getVersionString() {
        TraceLocalActivity(local);

        TraceLoggingWriteStart(local, "PVR_getVersionString");
        const auto& result = g_realPvrInterface.getVersionString();
        TraceLoggingWriteStop(local, "PVR_getVersionString", TLArg(result));

        return result;
    }

    pvrResult wrapper_createHmd(pvrHmdHandle* phmdh) {
        TraceLocalActivity(local);

        TraceLoggingWriteStart(local, "PVR_createHmd");
        const auto& result = g_realPvrInterface.createHmd(phmdh);
        if (result == pvr_success && phmdh) {
            // Watch for changes in the registry.
            {
                std::unique_lock lock(g_globalLock);

                if (!g_registryWatcher) {
                    try {
                        g_registryWatcher =
                            wil::make_registry_watcher(HKEY_LOCAL_MACHINE,
                                                       std::wstring(RegPrefix.begin(), RegPrefix.end()).c_str(),
                                                       true,
                                                       [&](wil::RegistryChangeKind changeType) { refreshSettings(); });
                    } catch (std::exception&) {
                        // Ignore errors that can happen with UWP applications not able to write to the
                        // registry.
                    }
                }
            }

            // We want to query the refresh rate from the device so we can transpose the settings accordingly.
            pvrDisplayInfo info{};
            const auto code = g_realPvrInterface.getEyeDisplayInfo(*phmdh, pvrEye_Left, &info);
            if (code == pvr_success) {
                std::unique_lock lock(g_globalLock);

                TraceLoggingWriteTagged(
                    local, "PVR_createHmd_getEyeDisplayInfo", TLArg(info.refresh_rate, "refresh_rate"));

                Log("Detected refresh rate: %.0f Hz.\n", info.refresh_rate);

                g_actualRefreshRate = info.refresh_rate;
            } else {
                TraceLoggingWriteTagged(
                    local, "PVR_createHmd_getEyeDisplayInfo_Failed", TLArg(ToString(code).c_str(), "result"));
            }

            // Load initial settings.
            refreshSettings();
        }
        TraceLoggingWriteStop(local, "PVR_createHmd", TLArg(ToString(result).c_str(), "result"));

        return result;
    }

    pvrResult wrapper_endFrame(pvrHmdHandle hmdh,
                               long long frameIndex,
                               pvrLayerHeader const* const* layerPtrList,
                               unsigned int layerCount) {
        TraceLocalActivity(local);

        const auto clientFps = g_realPvrInterface.getFloatConfig(hmdh, "client_fps", -1.f);
        TraceLoggingWriteStart(local,
                               "PVR_endFrame",
                               TLArg(clientFps, "client_fps"),
                               TLArg(!!g_realPvrInterface.getIntConfig(hmdh, "dbg_asw_enable", -1), "dbg_asw_enable"),
                               TLArg(g_realPvrInterface.getIntConfig(hmdh, "dbg_force_framerate_divide_by", -1),
                                     "dbg_force_framerate_divide_by"),
                               TLArg(!!g_realPvrInterface.getIntConfig(hmdh, "asw_available", -1), "asw_available"),
                               TLArg(!!g_realPvrInterface.getIntConfig(hmdh, "asw_active", -1), "asw_active"));
        if (g_settings.writeToCsv) {
            if (!g_logStats.is_open()) {
                const std::time_t now = std::time(nullptr);
                char buf[1024];
                std::strftime(buf, sizeof(buf), "pvr_stats_%Y%m%d_%H%M%S", std::localtime(&now));
                std::string logFile = (g_localAppData / (std::string(buf) + ".csv")).string();
                g_logStats.open(logFile, std::ios_base::ate);

                // Write headers.
                g_logStats << "time;client_fps;openvr_client_render_ms;adjusted\n";
            }
            g_logStats << g_realPvrInterface.getTimeSeconds() << ";" << clientFps << ";" << g_latestClientRenderMs
                       << ";" << g_latestAdjustedClientRenderMs << "\n";
        } else {
            g_logStats.close();
        }
        const auto& result = g_realPvrInterface.endFrame(hmdh, frameIndex, layerPtrList, layerCount);
        TraceLoggingWriteStop(local, "PVR_endFrame", TLArg(ToString(result).c_str(), "result"));

        return result;
    }

    pvrResult wrapper_setFloatConfig(pvrHmdHandle hmdh, const char* key, float val) {
        TraceLocalActivity(local);

        TraceLoggingWriteStart(local, "PVR_setFloatConfig", TLArg(key), TLArg(val));

        // We only adjust the values for the frame timing for motion smoothing.
        // This is an undocumented PVR option. This call always seems to fail, in spite of having side effects.
        // According to Pimax, this value must be set to the last frame time prior to calling pvr_endFrame().
        if (std::string_view(key) == "openvr_client_render_ms") {
            std::unique_lock lock(g_globalLock);

            {
                const auto initialVal = val;

                // Alter frame times per desired tweaks.
                g_latestClientRenderMs = val;

                if (g_settings.biasRenderMs) {
                    val = std::max(0.f, val - g_settings.biasRenderMs.value());
                }

                if (g_settings.absoluteRenderMsFloor) {
                    val = std::max(val, g_settings.absoluteRenderMsFloor.value());
                }
                if (g_settings.absoluteRenderMsCeiling) {
                    val = std::min(val, g_settings.absoluteRenderMsCeiling.value());
                }

                static float lastAllowedRenderMs = 0.f;
                if (g_settings.keepoutRenderMsLower && g_settings.keepoutRenderMsUpper) {
                    // If we are in the keepout zone...
                    if (g_settings.keepoutRenderMsLower.value() < val &&
                        val < g_settings.keepoutRenderMsUpper.value()) {
                        // ...snap to the lower or upper bound using the keepout zone as hysteresis.
                        if (lastAllowedRenderMs <= g_settings.keepoutRenderMsLower.value()) {
                            val = g_settings.keepoutRenderMsLower.value();
                        } else {
                            val = g_settings.keepoutRenderMsUpper.value();
                        }
                    } else {
                        lastAllowedRenderMs = val;
                    }
                }

                if (g_settings.pullUpRenderMsLower && g_settings.pullUpRenderMsUpper) {
                    // If we are in the pullup zone...
                    if (g_settings.pullUpRenderMsLower.value() < val && val < g_settings.pullUpRenderMsUpper.value()) {
                        // ...snap to the upper bound.
                        val = g_settings.pullUpRenderMsUpper.value();
                    }
                }

                if (g_settings.pullDownRenderMsLower && g_settings.pullDownRenderMsUpper) {
                    // If we are in the pulldown zone...
                    if (g_settings.pullDownRenderMsLower.value() < val &&
                        val < g_settings.pullDownRenderMsUpper.value()) {
                        // ...snap to the lower bound.
                        val = g_settings.pullDownRenderMsLower.value();
                    }
                }

                if (val != initialVal) {
                    TraceLoggingWriteTagged(local, "PVR_setFloatConfigAdjusted", TLArg(val));
                }
            }

            {
                const auto initialVal = val;

                // Simple median filter to smooth out the values.
                g_ClientRenderMsFilter.push_back(val);
                while (g_ClientRenderMsFilter.size() > g_settings.filterLength) {
                    g_ClientRenderMsFilter.pop_front();
                }
                auto sortedFrameTimes = g_ClientRenderMsFilter;
                std::sort(sortedFrameTimes.begin(), sortedFrameTimes.end());

                val = sortedFrameTimes[sortedFrameTimes.size() / 2];

                if (val != initialVal) {
                    TraceLoggingWriteTagged(local, "PVR_setFloatConfigFiltered", TLArg(val));
                }
            }

            g_latestAdjustedClientRenderMs = val;
        }

        const auto& result = g_realPvrInterface.setFloatConfig(hmdh, key, val);
        TraceLoggingWriteStop(local, "PVR_setFloatConfig", TLArg(ToString(result).c_str(), "result"));

        return result;
    }

    // Entry point for patching the dispatch table.
    pvrInterface* wrapper_getPvrInterface(uint32_t major_ver, uint32_t minor_ver) {
        TraceLocalActivity(local);

        std::unique_lock lock(g_globalLock);

        pvrInterface* result = nullptr;

        wchar_t modulePathC[MAX_PATH]{};
        GetModuleFileName(nullptr, modulePathC, sizeof(modulePathC));
        const std::wstring_view modulePath(modulePathC);

        TraceLoggingWriteStart(local, "PVR_getInterface", TLArg(modulePathC), TLArg(major_ver), TLArg(minor_ver));
        if (!g_realPvrLibrary) {
            // The real PVR library is the one in the system folder.
            const std::string_view pvrClientDllName(PVRCLIENT_DLL_NAME);
            wchar_t realPvrLibraryPath[MAX_PATH];

            if (GetSystemDirectory(realPvrLibraryPath, _countof(realPvrLibraryPath)) &&
                !wcscat_s(realPvrLibraryPath, MAX_PATH, L"\\") &&
                !wcscat_s(realPvrLibraryPath,
                          MAX_PATH,
                          std::wstring(pvrClientDllName.begin(), pvrClientDllName.end()).c_str())) {
                *g_realPvrLibrary.put() = LoadLibrary(realPvrLibraryPath);
            }
        }
        if (g_realPvrLibrary) {
            const auto realGetPvrInterface =
                (getPvrInterface_Fn)(void*)GetProcAddress(g_realPvrLibrary.get(), PVR_GET_INTERFACE_FUNC_NAME);
            if (realGetPvrInterface) {
                result = realGetPvrInterface(major_ver, minor_ver);

                if (result) {
                    // We only intercept calls from the SteamVR driver.
                    const bool isVrServer =
#ifndef _DEBUG
                        modulePath.find(L"\\vrserver.exe") != std::string::npos;
#else
                        true;
#endif

                    // We only support the version of the PVR client library that we were built against.
                    const bool isExpectedVersion = major_ver == PVR_MAJOR_VERSION && minor_ver == PVR_MINOR_VERSION;

                    if (isVrServer && isExpectedVersion) {
                        if (!g_realPvrInterfaceValid) {
                            g_realPvrInterface = *result;
                            g_realPvrInterfaceValid = true;
                        }

                        result->initialise = wrapper_initialise;
                        result->shutdown = wrapper_shutdown;
                        result->getVersionString = wrapper_getVersionString;
                        result->createHmd = wrapper_createHmd;
                        result->endFrame = wrapper_endFrame;
                        result->setFloatConfig = wrapper_setFloatConfig;

                        Log("Hooked to `%ls'.\n", modulePath.data());
                    } else {
                        TraceLoggingWriteTagged(
                            local, "PVR_getInterface_SkipOverride", TLArg(isVrServer), TLArg(isExpectedVersion));

                        Log("Skipped hooking `%ls' (requested PVR version %u.%u).\n",
                            modulePath.data(),
                            major_ver,
                            minor_ver);
                    }
                }
            } else {
                TraceLoggingWriteTagged(local, "PVR_getInterface_GetProcAddress_Failed");
            }
        } else {
            TraceLoggingWriteTagged(local, "PVR_getInterface_LoadLibrary_Failed");
        }

        TraceLoggingWriteStop(local, "PVR_getInterface", TLPArg(result));

        return result;
    }

} // namespace

extern "C" __declspec(dllexport) pvrInterface* getPvrInterface(uint32_t major_ver, uint32_t minor_ver) {
    return wrapper_getPvrInterface(major_ver, minor_ver);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        TraceLoggingRegister(g_traceProvider);
        g_localAppData = std::filesystem::path(getenv("LOCALAPPDATA"));
        g_logStream.open((g_localAppData / "Pimax-Tuner.log"), std::ios_base::ate);

        Log("Built on %s %s with PVR %u.%u.\n", __DATE__, __TIME__, PVR_MAJOR_VERSION, PVR_MINOR_VERSION);

        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}
