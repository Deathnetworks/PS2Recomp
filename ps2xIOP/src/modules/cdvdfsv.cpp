#include "../iop_service.h"
#include "../rpc_reply.h"

#include <array>
#include <cstdint>
#include <memory>
#include <mutex>
#include <sstream>
#include <string_view>

namespace ps2x::iop::detail
{
    namespace
    {
        // Service ids of the classic cdvdfsv IRX module.
        constexpr uint32_t kCdvdfsvSid = 0x80000592u;      // rpc1: cd init
        constexpr uint32_t kCdvdfsvDiskReadySid = 0x8000059Au; // rpc2: disk ready
        constexpr uint32_t kCdvdfsvScmdSid = 0x80000593u;  // rpc3: cdvd s-commands
        constexpr uint32_t kCdvdfsvNcmdSid = 0x80000595u;  // rpc5: cdvd n-commands
        constexpr uint32_t kCdvdfsvFsCallSid = 0x80000597u; // rpc4: file system calls

        constexpr uint32_t kMaxUnknownRpcLogs = 64u;

        // Versions reported by the cd init reply. The EE side checks them as
        // size hints, so they have to be larger than 256.
        constexpr uint32_t kCdvdfsvVersion = 0x00010000u;
        constexpr uint32_t kCdvdmanVersion = 0x00010000u;

        class CdvdfsvService final : public IopService
        {
        public:
            explicit CdvdfsvService(IopHost &host)
                : m_host(host)
            {
            }

            [[nodiscard]] std::string_view name() const override
            {
                return "cdvdfsv";
            }

            [[nodiscard]] std::span<const uint32_t> sids() const override
            {
                return m_sids;
            }

            void reset() override
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_unknownRpcLogCount = 0u;
            }

            [[nodiscard]] RpcResult handleRpc(const RpcRequest &request) override
            {
                RpcResult result{};
                result.handled = true;
                result.resultAddress = request.receive.address;

                if (request.sid == 0x8000000Au)
                {
                    logInfo(request, "cdvdman control call (func=0x" + std::to_string(request.function) + ")");
                    const std::array<uint32_t, 4> values{0u, 0u, 0u, 0u};
                    (void)writeRpcWords(m_host, request.receive, values);
                    return result;
                }
                switch (request.sid)
                {
                case kCdvdfsvSid:
                    return handleCdInit(request, result);
                case kCdvdfsvDiskReadySid:
                    return handleDiskReady(request, result);
                case kCdvdfsvScmdSid:
                case kCdvdfsvNcmdSid:
                    return handleCdvdCommand(request, result);
                case kCdvdfsvFsCallSid:
                    return handleFsCall(request, result);
                default:
                    logUnknown(request);
                    return result;
                }
            }

        private:
            [[nodiscard]] RpcResult handleCdInit(const RpcRequest &request, RpcResult result)
            {
                int32_t mode = 0;
                if (request.send.address != 0u && request.send.size >= sizeof(mode))
                {
                    (void)m_host.readGuest(request.send.address, &mode, sizeof(mode));
                }

                // cdvdfsv_rpc1_outpacket_t: retres, cdvdfsv version, cdvdman
                // version, debug mode.
                const std::array<uint32_t, 4> values{
                    1u,
                    kCdvdfsvVersion,
                    kCdvdmanVersion,
                    0u};
                (void)writeRpcWords(m_host, request.receive, values);
                logInfo(request, "cd init mode=" + std::to_string(mode));
                return result;
            }

            [[nodiscard]] RpcResult handleDiskReady(const RpcRequest &request, RpcResult result)
            {
                const std::array<uint32_t, 1> values{1u};
                (void)writeRpcWords(m_host, request.receive, values);
                logInfo(request, "disk ready");
                return result;
            }

            [[nodiscard]] RpcResult handleCdvdCommand(const RpcRequest &request, RpcResult result)
            {
                const std::array<uint32_t, 1> values{1u};
                (void)writeRpcWords(m_host, request.receive, values);
                logInfo(request, "cdvd command");
                return result;
            }

            [[nodiscard]] RpcResult handleFsCall(const RpcRequest &request, RpcResult result)
            {
                // cdvdfsv_rpc4_outpacket_t: retres plus padding.
                const std::array<uint32_t, 4> values{0u, 0u, 0u, 0u};
                (void)writeRpcWords(m_host, request.receive, values);
                logInfo(request, "file system call");
                return result;
            }

            void logInfo(const RpcRequest &request, const std::string &message)
            {
                std::ostringstream out;
                out << "CDVDFS " << message << " sid=0x" << std::hex << request.sid
                    << " function=0x" << request.function
                    << " send=0x" << request.send.address
                    << " size=0x" << request.send.size
                    << " receive=0x" << request.receive.address
                    << " size=0x" << request.receive.size;
                m_host.log(LogLevel::Info, out.str());
            }

            void logUnknown(const RpcRequest &request)
            {
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    if (m_unknownRpcLogCount >= kMaxUnknownRpcLogs)
                    {
                        return;
                    }
                    ++m_unknownRpcLogCount;
                }
                std::ostringstream out;
                out << "CDVDFS unknown RPC sid=0x" << std::hex << request.sid
                    << " function=0x" << request.function
                    << " send=0x" << request.send.address
                    << " size=0x" << request.send.size;
                m_host.log(LogLevel::Warning, out.str());
            }

            IopHost &m_host;
            mutable std::mutex m_mutex;
            uint32_t m_unknownRpcLogCount = 0u;
            const std::array<uint32_t, 6> m_sids{
                kCdvdfsvSid,
                kCdvdfsvDiskReadySid,
                kCdvdfsvScmdSid,
                kCdvdfsvNcmdSid,
                kCdvdfsvFsCallSid,
                0x8000000Au /* cdvdman control channel used by Primal's path-based reads */};
        };
    }

    std::unique_ptr<IopService> createCdvdfsvService(IopHost &host)
    {
        return std::make_unique<CdvdfsvService>(host);
    }
}
