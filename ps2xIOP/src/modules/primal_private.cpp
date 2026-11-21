// Primal (SCUS_971.42) game-private IOP RPC service.
//
// The retail disc carries FableIOPLibrary.irx on the IOP side, serving the
// game-owned SIDs 0x1000 (stream) .. 0x1003 (timer) family. The emulated IOP
// never loads that IRX, so sceSifBindRpc for these SIDs answered with
// serverData=0 and the later RPC calls were dropped at the EE SIF layer
// ([SIF:rpc] call without a bound server, SIF.cpp), which left the guest's
// frame gate (FUN_003a5b30 on 0x4F7124) latched non-zero forever.
//
// This HLE service makes the binds succeed (serverData != 0) and answers the
// calls: the timer (SID 0x1002, function 3) refreshes the guest clock struct
// in EE RAM; the stream SID 0x1000 is served on the EE side by the
// 0x330C90/0x330D00 overrides in game_overrides.h, so here it only needs a
// well-formed completion. Always active (no module aliases), like the ROM
// modules MCSERV/CDVDFS.

#include "../iop_service.h"
#include "../rpc_reply.h"

#include <array>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <iostream>
#include <memory>
#include <string_view>

namespace ps2x::iop::detail
{
    namespace
    {
        constexpr std::array<uint32_t, 4> kPrimalPrivateSids = {0x1000u, 0x1001u, 0x1002u, 0x1003u};
        constexpr uint32_t kTimerSid = 0x1002u;
        constexpr uint32_t kTimerGetTimeFunction = 3u;
        // Guest globals written by FUN_003296E0 (timer client builder):
        //   0x4886C8 = timer client struct, client+0x08 = 0xB8-byte clock struct
        constexpr uint32_t kTimerClientSlot = 0x004886C8u;
        constexpr uint32_t kClockPointerOffset = 0x08u;
        constexpr uint32_t kClockMsOffset = 0x10u;
        constexpr uint32_t kClockBcdOffset = 0x14u;
        constexpr uint32_t kClockCountdownOffset = 0x24u;
        constexpr uint32_t kClockWallOffset = 0x30u;

        inline uint32_t bcd(uint32_t v) { return ((v / 10u) << 4) | (v % 10u); }

        class PrimalPrivateService final : public IopService
        {
        public:
            explicit PrimalPrivateService(IopHost &host) : m_host(host) {}

            [[nodiscard]] std::string_view name() const override { return "PRIMAL_PRIVATE"; }
            [[nodiscard]] std::span<const uint32_t> sids() const override { return kPrimalPrivateSids; }

            void reset() override {}

            [[nodiscard]] RpcResult handleRpc(const RpcRequest &request) override
            {
                RpcResult response{};
                response.handled = true;
                response.resultAddress = request.receive.address;

                {
                    static uint32_t s_logCount = 0;
                    if (s_logCount < 100u)
                    {
                        ++s_logCount;
                        std::cerr << "[PRIMAL_PRIVATE] rpc #" << std::dec << s_logCount
                                  << " sid=0x" << std::hex << request.sid
                                  << " function=0x" << request.function
                                  << " sendSize=0x" << request.send.size << std::dec << std::endl;
                    }
                }

                if (request.sid == kTimerSid && request.function == kTimerGetTimeFunction)
                {
                    writeGuestClock();
                }

                const std::array<uint32_t, 1> ok{0u};
                (void)writeRpcWords(m_host, request.receive, ok);
                return response;
            }

        private:
            void writeGuestClock()
            {
                uint32_t client = 0u;
                if (!m_host.readGuest(kTimerClientSlot, &client, sizeof(client)) || client == 0u)
                    return;
                uint32_t clock = 0u;
                if (!m_host.readGuest(client + kClockPointerOffset, &clock, sizeof(clock)) || clock == 0u)
                    return;

                static const auto t0 = std::chrono::steady_clock::now();
                const auto now = std::chrono::steady_clock::now();
                const uint32_t ms = static_cast<uint32_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(now - t0).count());
                std::time_t wall = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
                std::tm parts{};
#if defined(_WIN32)
                localtime_s(&parts, &wall);
#else
                localtime_r(&wall, &parts);
#endif
                const uint32_t bcdTime = (bcd(static_cast<uint32_t>(parts.tm_hour)) << 16) |
                                         (bcd(static_cast<uint32_t>(parts.tm_min)) << 8) |
                                         bcd(static_cast<uint32_t>(parts.tm_sec));
                const uint32_t zero = 0u;
                (void)m_host.writeGuest(clock + kClockMsOffset, &ms, sizeof(ms));
                (void)m_host.writeGuest(clock + kClockBcdOffset, &bcdTime, sizeof(bcdTime));
                (void)m_host.writeGuest(clock + kClockBcdOffset + 4u, &zero, sizeof(zero));
                (void)m_host.writeGuest(clock + kClockCountdownOffset, &zero, sizeof(zero)); // frame due
                (void)m_host.writeGuest(clock + kClockWallOffset, &bcdTime, sizeof(bcdTime));
                (void)m_host.writeGuest(clock + kClockWallOffset + 4u, &zero, sizeof(zero));
            }

            IopHost &m_host;
        };
    }

    std::unique_ptr<IopService> createPrimalPrivateService(IopHost &host)
    {
        return std::make_unique<PrimalPrivateService>(host);
    }
}
