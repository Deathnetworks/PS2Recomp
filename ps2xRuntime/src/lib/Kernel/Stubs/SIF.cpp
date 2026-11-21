#include "Common.h"
#include "SIF.h"
#include "../Syscalls/RPC.h"
#include "../../ps2_iop_transport.h"
#include "runtime/ps2_address.h"
#include "runtime/ee_scheduler.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <vector>

namespace ps2_stubs
{
    void sceSifCmdIntrHdlr(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        TODO_NAMED("sceSifCmdIntrHdlr", rdram, ctx, runtime);
    }

    void sceSifLoadModule(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        ps2_syscalls::SifLoadModule(rdram, ctx, runtime);
    }

    void sceSifSendCmd(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t srcAddr = getRegU32(ctx, 7); // $a3
        const uint32_t dstAddr = readStackU32(rdram, ctx, 16);
        const uint32_t size = readStackU32(rdram, ctx, 20);
        if (size != 0u && srcAddr != 0u && dstAddr != 0u)
        {
            std::vector<uint8_t> payload(size);
            bool valid = runtime != nullptr;
            for (uint32_t i = 0; i < size; ++i)
            {
                const uint8_t *src = getConstMemPtr(rdram, srcAddr + i);
                if (!src)
                {
                    valid = false;
                    break;
                }
                payload[i] = *src;
            }
            if (!valid || !runtime->writeIopMemory(dstAddr, payload.data(), payload.size()))
            {
                setReturnS32(ctx, 0);
                return;
            }
        }

        setReturnS32(ctx, 1);
    }

    namespace
    {
        struct Ps2SifDmaTransfer
        {
            uint32_t src = 0;
            uint32_t dest = 0;
            int32_t size = 0;
            int32_t attr = 0;
        };
        static_assert(sizeof(Ps2SifDmaTransfer) == 16u, "Unexpected SIF DMA descriptor size");

        std::mutex g_sifDmaTransferMutex;
        uint32_t g_nextSifDmaTransferId = 1u;
        std::mutex g_sifCmdStateMutex;
        std::unordered_map<uint32_t, uint32_t> g_sifRegs;
        std::unordered_map<uint32_t, uint32_t> g_sifSregs;
        struct SifCmdHandler
        {
            uint32_t function = 0u;
            uint32_t argument = 0u;
        };

        std::unordered_map<uint32_t, SifCmdHandler> g_sifCmdHandlers;
        uint32_t g_sifCmdBuffer = 0u;
        uint32_t g_sifSysCmdBuffer = 0u;
        bool g_sifCmdInitialized = false;
        uint32_t g_sifGetRegLogCount = 0u;
        uint32_t g_sifSetRegLogCount = 0u;

        // IOP side SIF command transport state.
        struct SifRpcServerState
        {
            uint32_t serverData = 0u;   // IOP RAM address of the server data block
            uint32_t buffer = 0u;       // IOP RAM address of the server data buffer
            uint32_t clientBuffer = 0u; // IOP RAM address of the client data buffer
        };

        uint32_t g_sifIopCommandBuffer = 0u; // IOP RAM address of the SIF command buffer
        uint32_t g_sifEePacketBuffer = 0u;   // EE address the IOP replies to
        std::unordered_map<uint32_t, SifRpcServerState> g_sifRpcServers;

        constexpr uint32_t kSifRegBootStatus = 0x4u;
        // SIF register map used by the hardware and by the classic PS2 SDK:
        //   0x00000002 SIF_REG_SUBADDR    - IOP side SIF packet buffer
        //   0x00000004 SIF_REG_BOOT_STATUS
        //   0x80000000 SIF_SYSREG_SUBADDR - IOP side SIF packet buffer
        //   0x80000001 SIF_SYSREG_MAINADDR- EE side cmd_data pointer
        //   0x80000002 SIF_SYSREG_RPCINIT - RPC initialised flag
        constexpr uint32_t kSifRegSubAddr = 0x2u;
        constexpr uint32_t kSifSysRegSubAddr = 0x80000000u;
        constexpr uint32_t kSifSysRegMainAddr = 0x80000001u;
        constexpr uint32_t kSifSysRegRpcInit = 0x80000002u;
        // SIF register 4 reports the state of the IOP side services.
        //   0x00020000 command interface initialised
        //   0x00040000 disc services ready
        constexpr uint32_t kSifBootReadyMask = 0x00060000u;
        // The IOP owns the service status bits, the guest only reads them.
        constexpr uint32_t kSifCdReadyMask = 0x00040000u;

        void seedDefaultSifRegsLocked()
        {
            g_sifRegs.clear();
            g_sifSregs.clear();
            g_sifCmdHandlers.clear();
            g_sifCmdBuffer = 0u;
            g_sifSysCmdBuffer = 0u;
            g_sifCmdInitialized = false;
            g_sifGetRegLogCount = 0u;
            g_sifSetRegLogCount = 0u;

            g_sifRegs[kSifRegBootStatus] = kSifBootReadyMask;
            g_sifRegs[kSifSysRegSubAddr] = 0u;
            g_sifRegs[kSifSysRegMainAddr] = 0u;
            g_sifRegs[kSifSysRegRpcInit] = 0u;
            g_sifIopCommandBuffer = 0u;
            g_sifEePacketBuffer = 0u;
            g_sifRpcServers.clear();
        }

        bool shouldTraceSifReg(uint32_t reg)
        {
            switch (reg)
            {
            case 0x2u:
            case 0x4u:
            case 0x80000000u:
            case 0x80000001u:
            case 0x80000002u:
                return true;
            default:
                return false;
            }
        }

        struct SifStateInitializer
        {
            SifStateInitializer()
            {
                std::lock_guard<std::mutex> lock(g_sifCmdStateMutex);
                seedDefaultSifRegsLocked();
            }
        } g_sifStateInitializer;

        uint32_t allocateSifDmaTransferId()
        {
            std::lock_guard<std::mutex> lock(g_sifDmaTransferMutex);
            uint32_t id = g_nextSifDmaTransferId++;
            if (id == 0u)
            {
                id = g_nextSifDmaTransferId++;
            }
            return id;
        }

        bool isCopyableGuestAddress(uint32_t addr)
        {
            if (Ps2AddressInRange(addr, PS2_SCRATCHPAD_BASE, PS2_SCRATCHPAD_SIZE))
            {
                return true;
            }

            if (addr < PS2_EE_UNCACHED_RAM_MIRROR_BASE)
            {
                return true;
            }

            if (Ps2IsUncachedRamMirrorAddress(addr))
            {
                return true;
            }

            if (Ps2IsKseg01Address(addr))
            {
                return true;
            }

            return false;
        }

        bool canAccessEeRange(const uint8_t *rdram, uint32_t address, uint32_t sizeBytes)
        {
            if (!rdram)
            {
                return false;
            }
            if (sizeBytes == 0u)
            {
                return true;
            }
            if (sizeBytes - 1u > std::numeric_limits<uint32_t>::max() - address)
            {
                return false;
            }
            for (uint32_t i = 0u; i < sizeBytes; ++i)
            {
                const uint32_t byteAddress = address + i;
                if (!isCopyableGuestAddress(byteAddress) || getConstMemPtr(rdram, byteAddress) == nullptr)
                {
                    return false;
                }
            }
            return true;
        }

        bool readEeRange(const uint8_t *rdram, uint32_t address, void *destination, uint32_t sizeBytes)
        {
            if ((!destination && sizeBytes != 0u) || !canAccessEeRange(rdram, address, sizeBytes))
                return false;
            auto *bytes = static_cast<uint8_t *>(destination);
            for (uint32_t i = 0u; i < sizeBytes; ++i)
            {
                const uint8_t *source = getConstMemPtr(rdram, address + i);
                if (!source)
                    return false;
                bytes[i] = *source;
            }
            return true;
        }

        bool writeEeRange(uint8_t *rdram, uint32_t address, const void *source, uint32_t sizeBytes)
        {
            if ((!source && sizeBytes != 0u) || !canAccessEeRange(rdram, address, sizeBytes))
                return false;
            ps2TraceGuestRangeWrite(rdram, address, sizeBytes, "SIF IOP-to-EE DMA", nullptr);
            const auto *bytes = static_cast<const uint8_t *>(source);
            for (uint32_t i = 0u; i < sizeBytes; ++i)
            {
                uint8_t *destination = getMemPtr(rdram, address + i);
                if (!destination)
                    return false;
                *destination = bytes[i];
            }
            return true;
        }

        // ------------------------------------------------------------------
        // IOP side SIF command transport.
        //
        // Games built with the classic PS2 SDK drive RPC through the library
        // protocol instead of the modern syscall level RPC: the EE DMAs a
        // SIF command packet into the IOP side SIF buffer and waits for an
        // RPC_END packet that the IOP delivers through the SIF0 DMA
        // interrupt. Only the modern path existed so far, so those games
        // waited for a reply that could never arrive.
        //
        // Command packet layout (as written by the guest SIF library):
        //   +0x00 u8  psize   - total packet size in bytes
        //   +0x04 u32 dsize   - size of the trailing extra data block
        //   +0x08 u32 cid     - command id
        //   +0x0C u32 opt     - command options (bit 0 = RPC init)
        //   +0x10      payload
        // ------------------------------------------------------------------

        constexpr uint32_t kSifCidChangeSaddr = 0x80000000u;
        constexpr uint32_t kSifCidInitCmd = 0x80000002u;
        constexpr uint32_t kSifCidRpcEnd = 0x80000008u;
        constexpr uint32_t kSifCidRpcBind = 0x80000009u;
        constexpr uint32_t kSifCidRpcCall = 0x8000000Au;
        constexpr uint32_t kSifCidRpcRdata = 0x8000000Cu;

        constexpr uint32_t kSifCmdHeaderSize = 16u;
        constexpr uint32_t kSifIopCommandBufferSize = 0x100u;
        constexpr uint32_t kSifRpcServerDataSize = 0x40u;
        constexpr uint32_t kSifRpcBufferSize = 0x2000u;

        uint32_t ensureSifIopCommandBuffer(PS2Runtime *runtime)
        {
            if (g_sifIopCommandBuffer != 0u)
                return g_sifIopCommandBuffer;
            if (!runtime)
                return 0u;
            const uint32_t address = runtime->allocateIopMemory(kSifIopCommandBufferSize, 16u);
            if (address != 0u)
                g_sifIopCommandBuffer = address;
            return g_sifIopCommandBuffer;
        }

        uint32_t readSifRegisterLocked(uint32_t reg)
        {
            const auto it = g_sifRegs.find(reg);
            return it == g_sifRegs.end() ? 0u : it->second;
        }

        uint32_t readEeWord(uint8_t *rdram, uint32_t address)
        {
            const uint8_t *const bytes = getConstMemPtr(rdram, address);
            if (!bytes)
                return 0u;
            return static_cast<uint32_t>(bytes[0]) |
                   (static_cast<uint32_t>(bytes[1]) << 8) |
                   (static_cast<uint32_t>(bytes[2]) << 16) |
                   (static_cast<uint32_t>(bytes[3]) << 24);
        }

        uint32_t readPacketWord(const uint8_t *packet, uint32_t packetSize, uint32_t offset)
        {
            if (!packet || offset + 4u > packetSize)
                return 0u;
            return static_cast<uint32_t>(packet[offset]) |
                   (static_cast<uint32_t>(packet[offset + 1u]) << 8) |
                   (static_cast<uint32_t>(packet[offset + 2u]) << 16) |
                   (static_cast<uint32_t>(packet[offset + 3u]) << 24);
        }

        void writePacketWord(std::vector<uint8_t> &packet, uint32_t offset, uint32_t value)
        {
            if (offset + 4u > packet.size())
                return;
            packet[offset] = static_cast<uint8_t>(value & 0xFFu);
            packet[offset + 1u] = static_cast<uint8_t>((value >> 8) & 0xFFu);
            packet[offset + 2u] = static_cast<uint8_t>((value >> 16) & 0xFFu);
            packet[offset + 3u] = static_cast<uint8_t>((value >> 24) & 0xFFu);
        }

        // The guest side cmd_data block (classic SDK layout):
        //   +0x00 pktbuf           - EE buffer that receives IOP packets
        //   +0x04 unused
        //   +0x08 iopbuf           - IOP side SIF buffer address
        //   +0x0C sys_cmd_handlers - command id -> handler table
        //   +0x10 nr_sys_handlers
        //   +0x14 usr_cmd_handlers
        //   +0x18 nr_usr_handlers
        //   +0x1C sregs            - EE array of IOP status registers
        struct SifGuestCmdData
        {
            uint32_t address = 0u;
            uint32_t packetBuffer = 0u;
            uint32_t iopBuffer = 0u;
            uint32_t sregs = 0u;
        };

        SifGuestCmdData readGuestCmdData(uint8_t *rdram)
        {
            SifGuestCmdData data{};
            uint32_t address = 0u;
            {
                std::lock_guard<std::mutex> lock(g_sifCmdStateMutex);
                address = readSifRegisterLocked(kSifSysRegMainAddr);
            }
            if (address == 0u)
                return data;

            data.address = address;
            data.packetBuffer = readEeWord(rdram, address + 0x00u);
            data.iopBuffer = readEeWord(rdram, address + 0x08u);
            data.sregs = readEeWord(rdram, address + 0x1Cu);
            return data;
        }

        void signalSifRpcReady(uint8_t *rdram)
        {
            const SifGuestCmdData cmdData = readGuestCmdData(rdram);
            if (cmdData.sregs == 0u)
                return;
            const uint32_t value = 1u;
            (void)writeEeRange(rdram, cmdData.sregs, &value, sizeof(value));
        }

        uint32_t guestPacketBuffer(uint8_t *rdram)
        {
            const SifGuestCmdData cmdData = readGuestCmdData(rdram);
            uint32_t destination = 0u;
            {
                std::lock_guard<std::mutex> lock(g_sifCmdStateMutex);
                destination = g_sifEePacketBuffer;
            }
            if (destination == 0u)
                destination = cmdData.packetBuffer;
            return destination;
        }

        // The guest picks the packet up in its SIF0 DMA handler. The size byte
        // stays set afterwards, so it has to be cleared once the packet was
        // consumed, otherwise the next DMA would replay the stale packet.
        void clearGuestPacketBuffer(uint8_t *rdram)
        {
            const uint32_t destination = guestPacketBuffer(rdram);
            if (destination == 0u)
                return;
            const uint8_t empty = 0u;
            (void)writeEeRange(rdram, destination, &empty, sizeof(empty));
        }

        void deliverSifPacket(PS2Runtime *runtime, uint8_t *rdram, const std::vector<uint8_t> &packet)
        {
            if (!runtime || packet.empty())
                return;

            const uint32_t destination = guestPacketBuffer(rdram);
            if (destination == 0u)
                return;
            if (!writeEeRange(rdram, destination, packet.data(), static_cast<uint32_t>(packet.size())))
                return;
        }

        void sendSifRpcEnd(PS2Runtime *runtime,
                           uint8_t *rdram,
                           uint32_t clientData,
                           uint32_t commandId,
                           uint32_t serverData,
                           uint32_t buffer,
                           uint32_t clientBuffer)
        {
            std::vector<uint8_t> packet(64u, 0u);
            packet[0] = static_cast<uint8_t>(packet.size() & 0xFFu);
            writePacketWord(packet, 0x08u, kSifCidRpcEnd);
            writePacketWord(packet, 0x1Cu, clientData);
            writePacketWord(packet, 0x20u, commandId);
            writePacketWord(packet, 0x24u, serverData);
            writePacketWord(packet, 0x28u, buffer);
            writePacketWord(packet, 0x2Cu, clientBuffer);
            deliverSifPacket(runtime, rdram, packet);
        }

        void handleSifRpcBind(PS2Runtime *runtime,
                              uint8_t *rdram,
                              const uint8_t *packet,
                              uint32_t packetSize)
        {
            const uint32_t clientData = readPacketWord(packet, packetSize, 0x1Cu);
            const uint32_t sid = readPacketWord(packet, packetSize, 0x20u);

            uint32_t serverData = 0u;
            uint32_t buffer = 0u;
            uint32_t clientBuffer = 0u;

            if (PS2IopTransport::canBindRpc(runtime, sid))
            {
                SifRpcServerState state;
                bool found = false;
                {
                    std::lock_guard<std::mutex> lock(g_sifCmdStateMutex);
                    const auto it = g_sifRpcServers.find(sid);
                    if (it != g_sifRpcServers.end())
                    {
                        state = it->second;
                        found = true;
                    }
                }

                if (!found)
                {
                    state.serverData = runtime->allocateIopMemory(kSifRpcServerDataSize, 16u);
                    state.buffer = runtime->allocateIopMemory(kSifRpcBufferSize, 16u);
                    state.clientBuffer = runtime->allocateIopMemory(kSifRpcBufferSize, 16u);
                    if (state.serverData != 0u && state.buffer != 0u && state.clientBuffer != 0u)
                    {
                        std::lock_guard<std::mutex> lock(g_sifCmdStateMutex);
                        g_sifRpcServers[sid] = state;
                    }
                    else
                    {
                        state = SifRpcServerState{};
                    }
                }

                serverData = state.serverData;
                buffer = state.buffer;
                clientBuffer = state.clientBuffer;
            }
            else
            {
                PS2_IF_AGRESSIVE_LOGS({
                    std::cerr << "[SIF:rpc] bind sid=0x" << std::hex << sid
                              << " has no IOP service, replying without server data"
                              << std::dec << std::endl;
                });
            }

            sendSifRpcEnd(runtime, rdram, clientData, kSifCidRpcBind, serverData, buffer, clientBuffer);
        }

        void handleSifRpcCall(PS2Runtime *runtime,
                              uint8_t *rdram,
                              const uint8_t *packet,
                              uint32_t packetSize)
        {
            const uint32_t clientData = readPacketWord(packet, packetSize, 0x1Cu);
            const uint32_t function = readPacketWord(packet, packetSize, 0x20u);
            const uint32_t sendSize = readPacketWord(packet, packetSize, 0x24u);
            const uint32_t receiveBuffer = readPacketWord(packet, packetSize, 0x28u);
            const uint32_t receiveSize = readPacketWord(packet, packetSize, 0x2Cu);
            const uint32_t mode = readPacketWord(packet, packetSize, 0x30u);
            const uint32_t serverData = readPacketWord(packet, packetSize, 0x34u);

            uint32_t sid = 0u;
            SifRpcServerState state;
            {
                std::lock_guard<std::mutex> lock(g_sifCmdStateMutex);
                for (const auto &entry : g_sifRpcServers)
                {
                    if (entry.second.serverData == serverData && serverData != 0u)
                    {
                        sid = entry.first;
                        state = entry.second;
                        break;
                    }
                }
            }

            {
                static uint32_t s_callLogCount = 0;
                if (s_callLogCount < 300u)
                {
                    ++s_callLogCount;
                    std::cerr << "[SIF:rpc-call] #" << std::dec << s_callLogCount
                              << " sd=0x" << std::hex << serverData << " sid=0x" << sid
                              << " function=0x" << function << " sendSize=0x" << sendSize
                              << std::dec << std::endl;
                }
            }

            if (sid == 0u)
            {
                PS2_IF_AGRESSIVE_LOGS({
                    std::cerr << "[SIF:rpc] call without a bound server (sd=0x" << std::hex << serverData
                              << " function=0x" << function << ")" << std::dec << std::endl;
                });
                sendSifRpcEnd(runtime, rdram, clientData, kSifCidRpcCall, serverData, 0u, 0u);
                return;
            }

            // The classic protocol keeps the request payload in the IOP side
            // server buffer and copies the result back into the guest receive
            // buffer before the RPC_END packet is sent.
            std::vector<uint8_t> parameters(sendSize, 0u);
            if (sendSize != 0u)
                (void)runtime->readIopMemory(state.buffer, parameters.data(), parameters.size());

            const uint32_t resultSize = receiveSize != 0u ? receiveSize : 4u;
            std::vector<uint8_t> result(resultSize, 0u);

            const uint32_t parameterScratch = sendSize != 0u ? runtime->guestMalloc(sendSize, 16u) : 0u;
            const uint32_t resultScratch = runtime->guestMalloc(resultSize, 16u);
            if (parameterScratch != 0u && sendSize != 0u)
                (void)writeEeRange(rdram, parameterScratch, parameters.data(), sendSize);

            ps2x::iop::RpcRequest request{};
            request.clientAddress = clientData;
            request.serverAddress = serverData;
            request.serverBuffer = state.buffer;
            request.sid = sid;
            request.function = function;
            request.mode = mode;
            request.send = {parameterScratch, sendSize};
            request.receive = {resultScratch, resultSize};

            const ps2x::iop::RpcResult rpcResult = PS2IopTransport::handleRpc(runtime, rdram, nullptr, request);
            (void)rpcResult;

            if (resultScratch != 0u)
            {
                (void)readEeRange(rdram, resultScratch, result.data(), result.size());
                (void)runtime->writeIopMemory(state.buffer, result.data(), result.size());
                if (receiveBuffer != 0u)
                    (void)writeEeRange(rdram, receiveBuffer, result.data(), result.size());
                runtime->guestFree(resultScratch);
            }
            if (parameterScratch != 0u)
                runtime->guestFree(parameterScratch);

            sendSifRpcEnd(runtime, rdram, clientData, kSifCidRpcCall, serverData, state.buffer, state.clientBuffer);
        }

        void dispatchSifIopCommand(PS2Runtime *runtime, uint8_t *rdram, uint32_t bufferAddress)
        {
            if (!runtime || bufferAddress == 0u)
                return;

            // The previous reply was consumed by the guest already, drop its
            // size byte so it cannot be replayed by the next DMA interrupt.
            clearGuestPacketBuffer(rdram);

            std::vector<uint8_t> buffer(kSifIopCommandBufferSize, 0u);
            if (!runtime->readIopMemory(bufferAddress, buffer.data(), buffer.size()))
                return;

            const uint32_t packetSize = buffer[0];
            if (packetSize < kSifCmdHeaderSize || packetSize > buffer.size())
                return;

            const uint32_t commandId = readPacketWord(buffer.data(), packetSize, 0x08u);
            const uint32_t option = readPacketWord(buffer.data(), packetSize, 0x0Cu);

            switch (commandId)
            {
            case kSifCidChangeSaddr:
            {
                const uint32_t replyAddress = readPacketWord(buffer.data(), packetSize, 0x10u);
                std::lock_guard<std::mutex> lock(g_sifCmdStateMutex);
                g_sifEePacketBuffer = replyAddress;
                break;
            }
            case kSifCidInitCmd:
                if ((option & 1u) != 0u)
                    signalSifRpcReady(rdram);
                break;
            case kSifCidRpcBind:
                handleSifRpcBind(runtime, rdram, buffer.data(), packetSize);
                break;
            case kSifCidRpcCall:
                handleSifRpcCall(runtime, rdram, buffer.data(), packetSize);
                break;
            case kSifCidRpcRdata:
            {
                const uint32_t clientData = readPacketWord(buffer.data(), packetSize, 0x1Cu);
                const uint32_t originalId = readPacketWord(buffer.data(), packetSize, 0x20u);
                sendSifRpcEnd(runtime, rdram, clientData, originalId, 0u, 0u, 0u);
                break;
            }
            default:
                break;
            }
        }
    }

    void resetSifState()
    {
        std::lock_guard<std::mutex> lock(g_sifCmdStateMutex);
        seedDefaultSifRegsLocked();
    }

    bool dispatchSifCommand(uint8_t *rdram,
                            PS2Runtime *runtime,
                            uint32_t commandId,
                            const void *packet,
                            size_t packetSize) noexcept
    {
        if (!rdram || !runtime || !packet || packetSize < 16u || packetSize > 112u)
            return false;

        SifCmdHandler registered{};
        {
            std::lock_guard<std::mutex> lock(g_sifCmdStateMutex);
            const auto handler = g_sifCmdHandlers.find(commandId);
            if (handler == g_sifCmdHandlers.end() || handler->second.function == 0u)
                return false;
            registered = handler->second;
        }

        if (!runtime->hasFunction(registered.function))
            return false;

        const uint32_t packetAddress = runtime->guestMalloc(static_cast<uint32_t>(packetSize), 16u);
        if (packetAddress == 0u)
            return false;

        uint8_t *const first = getMemPtr(rdram, packetAddress);
        uint8_t *const last = getMemPtr(rdram, packetAddress + static_cast<uint32_t>(packetSize - 1u));
        if (!first || !last || last < first || static_cast<size_t>(last - first) != packetSize - 1u)
        {
            runtime->guestFree(packetAddress);
            return false;
        }

        ps2TraceGuestRangeWrite(rdram, packetAddress, static_cast<uint32_t>(packetSize), "SIF command packet", nullptr);
        std::memcpy(first, packet, packetSize);

        try
        {
            GuestInvocation invocation{};
            invocation.kind = GuestInvocationKind::SifCommand;
            invocation.tag = commandId;
            invocation.context = runtime->cpu();
            invocation.context.pc = registered.function;
            SET_GPR_U32(&invocation.context, 4, packetAddress);
            SET_GPR_U32(&invocation.context, 5, registered.argument);
            SET_GPR_U32(&invocation.context, 6, 0u);
            SET_GPR_U32(&invocation.context, 7, 0u);
            SET_GPR_U32(&invocation.context, 29, 0u);
            SET_GPR_U32(&invocation.context, 31, 0u);
            invocation.onComplete = [runtime, packetAddress](const R5900Context &, R5900Context &)
            {
                runtime->guestFree(packetAddress);
            };
            runtime->eeScheduler().queueInvocation(std::move(invocation));
            return true;
        }
        catch (...)
        {
            runtime->guestFree(packetAddress);
            return false;
        }
    }

    void sceSifAddCmdHandler(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t cid = getRegU32(ctx, 4);
        const uint32_t handler = getRegU32(ctx, 5);
        const uint32_t argument = getRegU32(ctx, 6);
        std::lock_guard<std::mutex> lock(g_sifCmdStateMutex);
        g_sifCmdHandlers[cid] = SifCmdHandler{handler, argument};
        setReturnS32(ctx, 0);
    }

    void sceSifAllocIopHeap(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        (void)rdram;
        const uint32_t reqSize = getRegU32(ctx, 4);
        setReturnU32(ctx, runtime ? runtime->allocateIopMemory(reqSize, 64u) : 0u);
    }

    void sceSifAllocSysMemory(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        (void)rdram;
        const uint32_t size = getRegU32(ctx, 5);
        setReturnU32(ctx, runtime ? runtime->allocateIopMemory(size, 64u) : 0u);
    }

    void sceSifBindRpc(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        ps2_syscalls::SifBindRpc(rdram, ctx, runtime);
    }

    void sceSifCheckStatRpc(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        ps2_syscalls::SifCheckStatRpc(rdram, ctx, runtime);
    }

    void sceSifDmaStat(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        (void)rdram;
        (void)runtime;
        (void)getRegU32(ctx, 4); // trid

        // Transfers are applied immediately by sceSifSetDma in this runtime.
        setReturnS32(ctx, -1);
    }

    void sceSifExecRequest(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        setReturnS32(ctx, 0);
    }

    void sceSifExitCmd(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        std::lock_guard<std::mutex> lock(g_sifCmdStateMutex);
        seedDefaultSifRegsLocked();
        setReturnS32(ctx, 0);
    }

    void sceSifExitRpc(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        setReturnS32(ctx, 0);
    }

    void sceSifFreeIopHeap(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        (void)rdram;
        const uint32_t addr = getRegU32(ctx, 4);
        setReturnS32(ctx, runtime && runtime->freeIopMemory(addr) ? 0 : -1);
    }

    void sceSifFreeSysMemory(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        (void)rdram;
        const uint32_t addr = getRegU32(ctx, 4);
        setReturnS32(ctx, runtime && runtime->freeIopMemory(addr) ? 0 : -1);
    }

    void sceSifGetDataTable(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        std::lock_guard<std::mutex> lock(g_sifCmdStateMutex);
        setReturnU32(ctx, g_sifCmdBuffer);
    }

    void sceSifGetIopAddr(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        setReturnU32(ctx, getRegU32(ctx, 4));
    }

    void sceSifGetNextRequest(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        setReturnS32(ctx, 0);
    }

    void sceSifGetOtherData(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t rdAddr = getRegU32(ctx, 4);
        const uint32_t srcAddr = getRegU32(ctx, 5);
        const uint32_t dstAddr = getRegU32(ctx, 6);
        const int32_t sizeSigned = static_cast<int32_t>(getRegU32(ctx, 7));

        if (sizeSigned <= 0)
        {
            setReturnS32(ctx, 0);
            return;
        }

        const uint32_t size = static_cast<uint32_t>(sizeSigned);
        if (size > PS2_RAM_SIZE)
        {
            static uint32_t warnCount = 0;
            if (warnCount < 32u)
            {
                std::cerr << "sceSifGetOtherData rejected oversized transfer size=0x"
                          << std::hex << size << std::dec << std::endl;
                ++warnCount;
            }
            setReturnS32(ctx, -1);
            return;
        }

        if (runtime)
        {
            PS2IopTransport::notifyTransfer(runtime, rdram, {
                                                                ps2x::iop::SifTransferKind::GetOtherData,
                                                                ps2x::iop::SifTransferPhase::BeforeCopy,
                                                                srcAddr,
                                                                dstAddr,
                                                                size,
                                                            });
        }

        std::vector<uint8_t> payload(size);
        if (!runtime || !runtime->isIopMemoryRange(srcAddr, size) ||
            !canAccessEeRange(rdram, dstAddr, size) ||
            !runtime->readIopMemory(srcAddr, payload.data(), payload.size()) ||
            !writeEeRange(rdram, dstAddr, payload.data(), size))
        {
            static uint32_t warnCount = 0;
            if (warnCount < 32u)
            {
                PS2_IF_AGRESSIVE_LOGS({
                    std::cerr << "sceSifGetOtherData copy failed src=0x" << std::hex << srcAddr
                              << " dst=0x" << dstAddr
                              << " size=0x" << size
                              << std::dec << std::endl;
                });
                ++warnCount;
            }
            setReturnS32(ctx, -1);
            return;
        }

        // SifRpcReceiveData_t keeps src/dest/size at offsets 0x10/0x14/0x18.
        if (uint8_t *rd = getMemPtr(rdram, rdAddr))
        {
            std::memcpy(rd + 0x10u, &srcAddr, sizeof(srcAddr));
            std::memcpy(rd + 0x14u, &dstAddr, sizeof(dstAddr));
            std::memcpy(rd + 0x18u, &size, sizeof(size));
        }

        if (runtime)
        {
            PS2IopTransport::notifyTransfer(runtime, rdram, {
                                                                ps2x::iop::SifTransferKind::GetOtherData,
                                                                ps2x::iop::SifTransferPhase::AfterCopy,
                                                                srcAddr,
                                                                dstAddr,
                                                                size,
                                                            });
        }

        setReturnS32(ctx, 0);
    }

    void sceSifGetReg(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t reg = getRegU32(ctx, 4);
        uint32_t value = 0u;
        bool shouldLog = false;
        {
            std::lock_guard<std::mutex> lock(g_sifCmdStateMutex);
            auto it = g_sifRegs.find(reg);
            if (it != g_sifRegs.end())
            {
                value = it->second;
            }
            if (value == 0u && (reg == kSifSysRegSubAddr || reg == kSifRegSubAddr))
            {
                // The guest needs the address of the IOP side SIF buffer to
                // send command packets to.
                value = ensureSifIopCommandBuffer(runtime);
            }
            if (reg == kSifRegBootStatus)
            {
                // The disc services are always available in the runtime, the
                // guest waits for this bit before it talks to them.
                value |= kSifCdReadyMask;
            }
            shouldLog = shouldTraceSifReg(reg) && g_sifGetRegLogCount < 128u;
            if (shouldLog)
            {
                ++g_sifGetRegLogCount;
            }
        }
        if (shouldLog)
        {
            PS2_IF_AGRESSIVE_LOGS({
                auto flags = std::cerr.flags();
                std::cerr << "[sceSifGetReg] reg=0x" << std::hex << reg
                          << " value=0x" << value
                          << " pc=0x" << (ctx ? ctx->pc : 0u)
                          << " ra=0x" << (ctx ? getRegU32(ctx, 31) : 0u)
                          << std::dec << std::endl;
                std::cerr.flags(flags);
            });
        }
        setReturnU32(ctx, value);
    }

    void sceSifGetSreg(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t reg = getRegU32(ctx, 4);
        uint32_t value = 0u;
        {
            std::lock_guard<std::mutex> lock(g_sifCmdStateMutex);
            auto it = g_sifSregs.find(reg);
            if (it != g_sifSregs.end())
            {
                value = it->second;
            }
        }
        setReturnU32(ctx, value);
    }

    void sceSifInitCmd(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        std::lock_guard<std::mutex> lock(g_sifCmdStateMutex);
        g_sifCmdInitialized = true;
        setReturnS32(ctx, 0);
    }

    void sceSifInitIopHeap(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        // The physical IOP allocator is initialized by IopSubsystem::reset().
        setReturnS32(ctx, 0);
    }

    void sceSifInitRpc(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        ps2_syscalls::SifInitRpc(rdram, ctx, runtime);
    }

    void sceSifIsAliveIop(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        setReturnS32(ctx, 1);
    }

    void sceSifLoadElf(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        ps2_syscalls::sceSifLoadElf(rdram, ctx, runtime);
    }

    void sceSifLoadElfPart(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        ps2_syscalls::sceSifLoadElfPart(rdram, ctx, runtime);
    }

    void sceSifLoadFileReset(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        setReturnS32(ctx, 0);
    }

    void sceSifLoadIopHeap(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        setReturnS32(ctx, 0);
    }

    void sceSifLoadModuleBuffer(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        ps2_syscalls::sceSifLoadModuleBuffer(rdram, ctx, runtime);
    }

    void sceSifRebootIop(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        PS2IopTransport::reset(runtime);
        setReturnS32(ctx, 1);
    }

    void sceSifRegisterRpc(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        ps2_syscalls::SifRegisterRpc(rdram, ctx, runtime);
    }

    void sceSifRemoveCmdHandler(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t cid = getRegU32(ctx, 4);
        std::lock_guard<std::mutex> lock(g_sifCmdStateMutex);
        g_sifCmdHandlers.erase(cid);
        setReturnS32(ctx, 0);
    }

    void sceSifRemoveRpc(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        ps2_syscalls::SifRemoveRpc(rdram, ctx, runtime);
    }

    void sceSifRemoveRpcQueue(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        ps2_syscalls::SifRemoveRpcQueue(rdram, ctx, runtime);
    }

    void sceSifResetIop(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        PS2IopTransport::reset(runtime);
        setReturnS32(ctx, 1);
    }

    void sceSifRpcLoop(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        setReturnS32(ctx, 0);
    }

    void sceSifSetCmdBuffer(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t newBuffer = getRegU32(ctx, 4);
        uint32_t prev = 0u;
        {
            std::lock_guard<std::mutex> lock(g_sifCmdStateMutex);
            prev = g_sifCmdBuffer;
            g_sifCmdBuffer = newBuffer;
        }
        setReturnU32(ctx, prev);
    }

    void isceSifSetDChain(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        sceSifSetDChain(rdram, ctx, runtime);
    }

    void isceSifSetDma(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        sceSifSetDma(rdram, ctx, runtime);
    }

    void sceSifSetDChain(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        (void)rdram;
        (void)runtime;
        setReturnS32(ctx, 0);
    }

    void sceSifSetDma(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t dmatAddr = getRegU32(ctx, 4);
        const uint32_t count = getRegU32(ctx, 5);

        const uint32_t listAddr = getRegU32(ctx, 4);
        PS2_IF_AGRESSIVE_LOGS({
            std::cerr << "[sceSifSetDma:CALL] pc=0x" << std::hex << ctx->pc
                      << " ra=0x" << getRegU32(ctx, 31)
                      << " list=0x" << listAddr
                      << " count=" << std::dec << count
                      << std::endl;

            for (uint32_t i = 0; i < count; ++i)
            {
                const uint32_t desc = listAddr + i * 16;
                const uint32_t src = READ32(desc + 0);
                const uint32_t dst = READ32(desc + 4);
                const uint32_t size = READ32(desc + 8);
                const uint32_t attr = READ32(desc + 12);

                std::cerr << "[sceSifSetDma:DESC] i=" << i
                          << " src=0x" << std::hex << src
                          << " dst=0x" << dst
                          << " size=0x" << size
                          << " attr=0x" << attr
                          << " pc=0x" << ctx->pc
                          << " ra=0x" << getRegU32(ctx, 31)
                          << std::dec << std::endl;
            }
        });

        if (!dmatAddr || count == 0u || count > 32u)
        {
            setReturnS32(ctx, 0);
            return;
        }

        std::array<Ps2SifDmaTransfer, 32u> pending{};
        uint32_t pendingCount = 0u;
        bool ok = true;
        for (uint32_t i = 0; i < count; ++i)
        {
            const uint32_t entryAddr = dmatAddr + (i * static_cast<uint32_t>(sizeof(Ps2SifDmaTransfer)));
            const uint8_t *entry = getConstMemPtr(rdram, entryAddr);
            if (!entry)
            {
                ok = false;
                break;
            }

            Ps2SifDmaTransfer xfer{};
            std::memcpy(&xfer, entry, sizeof(xfer));
            if (xfer.size <= 0)
            {
                continue;
            }

            const uint32_t sizeBytes = static_cast<uint32_t>(xfer.size);
            if (sizeBytes > PS2_RAM_SIZE)
            {
                ok = false;
                break;
            }
            if (!runtime || !canAccessEeRange(rdram, xfer.src, sizeBytes) || !runtime->isIopMemoryRange(xfer.dest, sizeBytes))
            {
                ok = false;
                break;
            }

            pending[pendingCount++] = xfer;
        }

        if (ok)
        {
            for (uint32_t i = 0; i < pendingCount; ++i)
            {
                const Ps2SifDmaTransfer &xfer = pending[i];
                if (runtime)
                {
                    PS2IopTransport::notifyTransfer(runtime, rdram, {
                                                                        ps2x::iop::SifTransferKind::SetDma,
                                                                        ps2x::iop::SifTransferPhase::BeforeCopy,
                                                                        xfer.src,
                                                                        xfer.dest,
                                                                        static_cast<uint32_t>(xfer.size),
                                                                    });
                }
                const uint32_t sizeBytes = static_cast<uint32_t>(xfer.size);
                std::vector<uint8_t> payload(sizeBytes);
                if (!readEeRange(rdram, xfer.src, payload.data(), sizeBytes) || !runtime->writeIopMemory(xfer.dest, payload.data(), payload.size()))
                {
                    ok = false;
                    break;
                }
                if (runtime)
                {
                    PS2IopTransport::notifyTransfer(runtime, rdram, {
                                                                        ps2x::iop::SifTransferKind::SetDma,
                                                                        ps2x::iop::SifTransferPhase::AfterCopy,
                                                                        xfer.src,
                                                                        xfer.dest,
                                                                        static_cast<uint32_t>(xfer.size),
                                                                    });
                }

                uint32_t commandBuffer = 0u;
                {
                    std::lock_guard<std::mutex> lock(g_sifCmdStateMutex);
                    commandBuffer = g_sifIopCommandBuffer;
                }
                if (commandBuffer != 0u && xfer.dest == commandBuffer)
                {
                    // A classic SDK command packet reached the IOP side SIF
                    // buffer, answer it the way the IOP would.
                    dispatchSifIopCommand(runtime, rdram, commandBuffer);
                }
            }
        }

        if (!ok)
        {
            static uint32_t warnCount = 0;
            if (warnCount < 32u)
            {
                PS2_IF_AGRESSIVE_LOGS({
                    std::cerr << "sceSifSetDma failed dmat=0x" << std::hex << dmatAddr
                              << " count=0x" << count
                              << std::dec << std::endl;
                });
                ++warnCount;
            }
            setReturnS32(ctx, 0);
            return;
        }

        ps2_syscalls::dispatchDmacHandlersForCause(rdram, runtime, 5u);

        setReturnS32(ctx, static_cast<int32_t>(allocateSifDmaTransferId()));
    }

    void sceSifSetIopAddr(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        setReturnU32(ctx, getRegU32(ctx, 5));
    }

    void sceSifSetReg(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t reg = getRegU32(ctx, 4);
        const uint32_t value = getRegU32(ctx, 5);
        uint32_t prev = 0u;
        bool shouldLog = false;
        {
            std::lock_guard<std::mutex> lock(g_sifCmdStateMutex);
            auto it = g_sifRegs.find(reg);
            if (it != g_sifRegs.end())
            {
                prev = it->second;
            }
            g_sifRegs[reg] = value;
            shouldLog = shouldTraceSifReg(reg) && g_sifSetRegLogCount < 128u;
            if (shouldLog)
            {
                ++g_sifSetRegLogCount;
            }
        }
        if (shouldLog)
        {
            PS2_IF_AGRESSIVE_LOGS({
                auto flags = std::cerr.flags();
                std::cerr << "[sceSifSetReg] reg=0x" << std::hex << reg
                          << " prev=0x" << prev
                          << " value=0x" << value
                          << " pc=0x" << (ctx ? ctx->pc : 0u)
                          << " ra=0x" << (ctx ? getRegU32(ctx, 31) : 0u)
                          << std::dec << std::endl;
                std::cerr.flags(flags);
            });
        }
        setReturnU32(ctx, prev);
    }

    void sceSifSetRpcQueue(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        ps2_syscalls::SifSetRpcQueue(rdram, ctx, runtime);
    }

    void sceSifSetSreg(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t reg = getRegU32(ctx, 4);
        const uint32_t value = getRegU32(ctx, 5);
        uint32_t prev = 0u;
        {
            std::lock_guard<std::mutex> lock(g_sifCmdStateMutex);
            auto it = g_sifSregs.find(reg);
            if (it != g_sifSregs.end())
            {
                prev = it->second;
            }
            g_sifSregs[reg] = value;
        }
        setReturnU32(ctx, prev);
    }

    void sceSifSetSysCmdBuffer(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t newBuffer = getRegU32(ctx, 4);
        uint32_t prev = 0u;
        {
            std::lock_guard<std::mutex> lock(g_sifCmdStateMutex);
            prev = g_sifSysCmdBuffer;
            g_sifSysCmdBuffer = newBuffer;
        }
        setReturnU32(ctx, prev);
    }

    void sceSifStopDma(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        setReturnS32(ctx, 0);
    }

    void sceSifSyncIop(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        setReturnS32(ctx, 1);
    }

    void sceSifWriteBackDCache(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        setReturnS32(ctx, 0);
    }
}
