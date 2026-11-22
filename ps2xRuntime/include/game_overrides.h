#ifndef PS2_GAME_OVERRIDES_H
#define PS2_GAME_OVERRIDES_H

#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <filesystem>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>
#if defined(PS2X_HAS_FFMPEG) && PS2X_HAS_FFMPEG
extern "C"
{
#include <libavcodec/avcodec.h>
#include <libavutil/log.h>
#include <libswscale/swscale.h>
}
#endif
#if !defined(_WIN32)
#include <execinfo.h>
#include <sys/mman.h>
#include <unistd.h>
#endif
#include <signal.h>

#include "raylib.h"
#include "ps2_runtime.h"
#include "primal_test_harness.h"
#include "ps2_stubs.h"
#include "ps2_syscalls.h"
#include "runtime/ee_scheduler.h"
#include "runtime/ee_scheduler.h"
#include "runtime/ps2_memory.h"

namespace ps2_game_overrides
{
    using ApplyFn = void (*)(PS2Runtime &runtime);

    struct Descriptor
    {
        const char *name = "";
        const char *elfName = "";
        uint32_t entry = 0;
        uint32_t crc32 = 0;
        ApplyFn apply = nullptr;
    };

    class AutoRegister
    {
    public:
        explicit AutoRegister(const Descriptor &descriptor);
    };

    void registerDescriptor(const Descriptor &descriptor);
    void applyMatching(PS2Runtime &runtime, const std::string &elfPath, uint32_t entry, uint32_t crc32, bool crc32Valid);

    // Runtime helper for game-specific modules:
    // bind an address to an existing syscall/stub handler by name.
    bool bindAddressHandler(PS2Runtime &runtime, uint32_t address, std::string_view handlerName);
}

#define PS2_GAME_OVERRIDE_JOIN2(a, b) a##b
#define PS2_GAME_OVERRIDE_JOIN(a, b) PS2_GAME_OVERRIDE_JOIN2(a, b)

#define PS2_REGISTER_GAME_OVERRIDE(NAME_LITERAL, ELF_NAME_LITERAL, ENTRY_U32, CRC32_U32, APPLY_FN)      \
    namespace                                                                                             \
    {                                                                                                     \
        static const ps2_game_overrides::Descriptor PS2_GAME_OVERRIDE_JOIN(kPs2OverrideDesc_, __LINE__) \
        {                                                                                                 \
            NAME_LITERAL,                                                                                 \
            ELF_NAME_LITERAL,                                                                             \
            static_cast<uint32_t>(ENTRY_U32),                                                             \
            static_cast<uint32_t>(CRC32_U32),                                                             \
            APPLY_FN                                                                                      \
        };                                                                                                \
        static const ps2_game_overrides::AutoRegister PS2_GAME_OVERRIDE_JOIN(kPs2OverrideReg_, __LINE__) \
            (PS2_GAME_OVERRIDE_JOIN(kPs2OverrideDesc_, __LINE__));                                       \
    }

namespace ps2_game_overrides
{
    // Primal's NTSC startup polls an IOP-side completion slot through
    // 0x003E8E70. The host SIF implementation completes transfers
    // synchronously but does not publish that slot, so the guest waits
    // forever. Treat the already-submitted transfer as complete for this
    // exact retail image only.
    inline void applyPrimalNtscStartupCompletionOverride(PS2Runtime &runtime)
    {
        (void)bindAddressHandler(runtime, 0x003E8E70u, "ret1");
    }

    // C++ inline variables have one address across all translation units,
    // so including this header in both game_overrides.cpp and ps2_runtime.cpp
    // still registers this descriptor exactly once.
    inline const Descriptor kPrimalNtscStartupCompletionDescriptor{
        "Primal NTSC startup completion slot",
        "SCUS_971.42",
        0x00100008u,
        0xAB6FB13Cu,
        &applyPrimalNtscStartupCompletionOverride
    };

    inline const AutoRegister kPrimalNtscStartupCompletionRegistrar{
        kPrimalNtscStartupCompletionDescriptor
    };
}

// ---------------------------------------------------------------------------
// Primal (SCUS_971.42) SIF/RPC reply callback.
//
// The guest hands the SIF reply to the function pointer stored at [s0+0x1c]
// (the JALR at 0x003E5F68 inside the retail dispatcher at 0x003E5F10). For
// this image the pointer is 0x003F4D90, the body of the callback. The
// preceding 0x003F4D88 instruction belongs to a separate entry, so neither
// callback address is covered by the Ghidra
// export, so the runtime used to log
//   "[guest-branch:missing-target] ... target=0x3f4d90"
// and stop the guest.
//
// Retail control flow (disassembly of SCUS_971.42):
//
//   0x003F4D90  callback body. It is entered *without* the preceding
//               0x003F4D88 frame setup (the guest jumps to 0x003F4D90 on
//               purpose and the callback never uses that 96 byte frame):
//                 a2 = a0 | 0x20000000
//                 count1 = [a2+0], dest1 = [a2+8],  source1 = a2+16
//                 count2 = [a2+4], dest2 = [a2+12], source2 = a2+80
//               A count <= 0 skips that range, otherwise the bytes are
//               copied one by one and the count is re-read every iteration.
//               Finally it tail-jumps to 0x003F4CE0 with $a0 = 0x0042C914.
//
//   0x003F4CE0  reply handler:
//                 state = [0x0042C914];  [0x0042C918] = state
//                 if (state != 11) { iSignalSema([0x0042C8E8]);
//                                     if ([0x0042C8D4] && [0x004FEA00])
//                                         iSignalSema([0x0042C8E0]);
//                                     else
//                                         [0x0042C8F0] = 0; }
//                 else                 [0x0042C8F0] = 0;
//                 [0x0042C914] = 0
//               and returns through $ra (the JALR return address 0x003E5F70).
//
// The override keeps both addresses so the guest sees the retail control
// flow: the callback tail-jumps into the reply handler, the reply handler
// returns to the caller of the JALR. Nothing else in the runtime is touched.
//
// Runtime rules that the implementation follows:
//   * ctx->pc is the only way to move the guest. A guest function never
//     calls dispatchGuestBranch() itself; it either leaves ctx->pc on the
//     address the scheduler should dispatch next, or it returns to the
//     caller by restoring ctx->pc to $ra.
//   * Guest memory is reached through getMemPtr() /
//     ps2ResolveGuestPointer(). Unknown address windows silently fold onto
//     physical 0 in that resolver, so every access below validates the
//     window and the length first.
//   * The semaphore is signalled through ps2_syscalls::iSignalSema(), the
//     very same entry point the retail "jal 0x003E4810" reaches. It binds
//     the main context, signals with interruptSafe = true and stores the
//     kernel result in $v0, exactly like the retail syscall.
// ---------------------------------------------------------------------------
namespace ps2_game_overrides::primal_sif_rpc
{
    // Guest entry points of the two retail stages.
    constexpr uint32_t kCallbackPc = 0x003F4D90u;
    constexpr uint32_t kReplyHandlerPc = 0x003F4CE0u;

    // Callback argument layout (all offsets relative to a0 | 0x20000000).
    constexpr uint32_t kCallbackFlagMask = 0x20000000u;
    constexpr uint32_t kCount1Offset = 0u;
    constexpr uint32_t kCount2Offset = 4u;
    constexpr uint32_t kDestination1Offset = 8u;
    constexpr uint32_t kDestination2Offset = 12u;
    constexpr uint32_t kSource1Offset = 16u;
    constexpr uint32_t kSource2Offset = 80u;

    // Guest globals used by the reply handler (physical EE addresses).
    constexpr uint32_t kStateAddr = 0x0042C914u;
    constexpr uint32_t kStateMirrorAddr = 0x0042C918u;
    constexpr uint32_t kClearFlagAddr = 0x0042C8F0u;
    constexpr uint32_t kPrimarySemaphoreAddr = 0x0042C8E8u;
    constexpr uint32_t kSecondarySemaphoreAddr = 0x0042C8E0u;
    constexpr uint32_t kSecondaryFlagAddr = 0x0042C8D4u;
    constexpr uint32_t kSecondaryGateAddr = 0x004FEA00u;
    constexpr uint32_t kCompletedState = 11u;

    // Retail "lui $t1,67" materialises the page the tail jump uses. The
    // disassembler prints the LUI immediate in decimal: 67 == 0x0043.
    // addiu $a0,$t1,-14060 -> 0x00430000 - 14060 = 0x0042C914.
    constexpr uint32_t kRetailPage = 0x00430000u;

    // Upper bound for a single copy, the retail code copies byte by byte
    // without any limit.
    constexpr uint32_t kMaxCopyBytes = 0x00010000u;

    // Mirrors SET_GPR_U32() from ps2_runtime_macros.h without dragging the
    // macro header into this one: the low 64 bit are replaced with the sign
    // extended 32 bit value, the high 64 bit stay untouched.
    inline void setGuestRegU32(R5900Context *ctx, int reg, uint32_t value)
    {
        if (ctx == nullptr || reg == 0)
        {
            return;
        }

        const __m128i newLow = _mm_cvtsi64_si128(static_cast<int64_t>(static_cast<int32_t>(value)));
        ctx->r[reg] = _mm_castpd_si128(_mm_move_sd(_mm_castsi128_pd(ctx->r[reg]), _mm_castsi128_pd(newLow)));
    }

    // Maps a guest range onto RDRAM. ps2ResolveGuestPointer() folds unknown
    // windows onto physical 0, so the window is validated here as well and
    // the caller gets the number of bytes that may legally be touched.
    inline bool mapGuestRange(uint8_t *rdram, uint32_t address, uint8_t *&host, uint32_t &available)
    {
        host = nullptr;
        available = 0u;
        if (rdram == nullptr)
        {
            return false;
        }

        const bool scratchWindow = ps2IsScratchpadAddress(address);
        const bool ramWindow = (address < 0x40000000u) ||
                               (address >= 0x80000000u && address < 0xC0000000u);
        if (!scratchWindow && !ramWindow)
        {
            return false;
        }

        uint32_t offset = 0u;
        bool scratch = false;
        if (!ps2ResolveGuestPointer(address, offset, scratch))
        {
            return false;
        }

        const uint32_t limit = scratch ? PS2_SCRATCHPAD_SIZE : PS2_RAM_SIZE;
        if (offset >= limit)
        {
            return false;
        }

        host = getMemPtr(rdram, address);
        if (host == nullptr)
        {
            return false;
        }

        available = limit - offset;
        return true;
    }

    inline bool readGuestU32(uint8_t *rdram, uint32_t address, uint32_t &value)
    {
        uint8_t *host = nullptr;
        uint32_t available = 0u;
        if (!mapGuestRange(rdram, address, host, available) || available < 4u)
        {
            return false;
        }

        value = static_cast<uint32_t>(host[0]) |
                (static_cast<uint32_t>(host[1]) << 8) |
                (static_cast<uint32_t>(host[2]) << 16) |
                (static_cast<uint32_t>(host[3]) << 24);
        return true;
    }

    inline bool writeGuestU32(uint8_t *rdram, uint32_t address, uint32_t value)
    {
        uint8_t *host = nullptr;
        uint32_t available = 0u;
        if (!mapGuestRange(rdram, address, host, available) || available < 4u)
        {
            return false;
        }

        host[0] = static_cast<uint8_t>(value & 0xFFu);
        host[1] = static_cast<uint8_t>((value >> 8) & 0xFFu);
        host[2] = static_cast<uint8_t>((value >> 16) & 0xFFu);
        host[3] = static_cast<uint8_t>((value >> 24) & 0xFFu);
        return true;
    }

    // Retail copy loop: one byte per iteration, the count is re-read from
    // guest RAM every time and the comparison is signed (slt).
    // Returns the count value that was loaded last, the retail code keeps it
    // in $v0.
    inline uint32_t copyGuestRange(uint8_t *rdram,
                                   uint32_t source,
                                   uint32_t destination,
                                   uint32_t countAddress,
                                   uint32_t &lastByte)
    {
        uint32_t index = 0u;
        uint32_t count = 0u;

        for (;;)
        {
            uint8_t *src = nullptr;
            uint32_t srcAvailable = 0u;
            uint8_t *dst = nullptr;
            uint32_t dstAvailable = 0u;
            if (!mapGuestRange(rdram, source + index, src, srcAvailable))
            {
                break;
            }
            if (!mapGuestRange(rdram, destination + index, dst, dstAvailable))
            {
                break;
            }

            const uint8_t byte = src[0];
            dst[0] = byte;
            lastByte = byte;
            ++index;
            if (index >= kMaxCopyBytes)
            {
                break;
            }

            uint32_t current = 0u;
            if (!readGuestU32(rdram, countAddress, current))
            {
                break;
            }
            count = current;
            if (!(static_cast<int32_t>(index) < static_cast<int32_t>(count)))
            {
                break;
            }
        }

        return count;
    }

    // Stage 1: the retail callback body at 0x003F4D90.
    // It copies the two optional payload ranges and tail-jumps into the
    // reply handler at 0x003F4CE0.
    inline void callbackStage1(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        (void)runtime;

        const uint32_t argument = getRegU32(ctx, 4);        // $a0
        const uint32_t base = argument | kCallbackFlagMask; // or $a2,$a0,0x20000000

        uint32_t count = 0u;
        uint32_t destination = 0u;
        uint32_t lastByte = getRegU32(ctx, 3);              // $v1

        // The offsets are added to the mapped base, so the sum must not wrap.
        if (base <= 0xFFFFFF00u)
        {
            // First range: count at +0, destination at +8, payload at +16.
            if (readGuestU32(rdram, base + kCount1Offset, count))
            {
                if (static_cast<int32_t>(count) > 0 &&
                    readGuestU32(rdram, base + kDestination1Offset, destination))
                {
                    count = copyGuestRange(rdram,
                                           base + kSource1Offset,
                                           destination,
                                           base + kCount1Offset,
                                           lastByte);
                }
            }

            // Second range: count at +4, destination at +12, payload at +80.
            if (readGuestU32(rdram, base + kCount2Offset, count))
            {
                if (static_cast<int32_t>(count) > 0 &&
                    readGuestU32(rdram, base + kDestination2Offset, destination))
                {
                    count = copyGuestRange(rdram,
                                           base + kSource2Offset,
                                           destination,
                                           base + kCount2Offset,
                                           lastByte);
                }
            }
        }

        // Retail tail jump "j 0x003F4CE0" with the delay slot
        // "addiu $a0,$t1,-14060" and $t1 = 0x00430000.
        // The retail code only loads $t1 when the first range is entered and
        // then relies on the caller to keep 0x00430000 there. Hard-coding the
        // resulting address keeps the state read of stage 2 deterministic.
        setGuestRegU32(ctx, 9, kRetailPage);   // $t1
        setGuestRegU32(ctx, 2, count);         // $v0
        setGuestRegU32(ctx, 3, lastByte);      // $v1
        setGuestRegU32(ctx, 6, base);          // $a2
        setGuestRegU32(ctx, 4, kStateAddr);    // $a0
        ctx->pc = kReplyHandlerPc;             // j 0x003F4CE0
    }

    // Stage 2: the retail reply handler at 0x003F4CE0.
    // It publishes the state, signals the reply semaphores and returns to
    // the caller of the JALR ($ra = 0x003E5F70 for this call site).
    inline void callbackStage2(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        // Retail: lw $v1,0($a0) with $a0 = 0x0042C914.
        uint32_t stateAddress = getRegU32(ctx, 4);
        uint32_t state = 0u;
        if (!readGuestU32(rdram, stateAddress, state))
        {
            stateAddress = kStateAddr;
            (void)readGuestU32(rdram, stateAddress, state);
        }

        // Retail: sw $v1,-14060($s0) -> [0x0042C914] = state
        (void)writeGuestU32(rdram, kStateAddr, state);
        // Retail: lw $v0,-14060($s0); sw $v0,-14056($t0) -> [0x0042C918] = [0x0042C914]
        uint32_t mirrored = 0u;
        (void)readGuestU32(rdram, kStateAddr, mirrored);
        (void)writeGuestU32(rdram, kStateMirrorAddr, mirrored);

        if (state != kCompletedState)
        {
            // Retail: lw $a0,-14104($v0); jal iSignalSema
            uint32_t semaphore = 0u;
            (void)readGuestU32(rdram, kPrimarySemaphoreAddr, semaphore);
            setGuestRegU32(ctx, 4, semaphore);
            ps2_syscalls::iSignalSema(rdram, ctx, runtime);

            uint32_t flag = 0u;
            uint32_t gate = 0u;
            (void)readGuestU32(rdram, kSecondaryFlagAddr, flag);
            (void)readGuestU32(rdram, kSecondaryGateAddr, gate);
            if (flag != 0u && gate != 0u)
            {
                // Retail: lw $a0,-14112($v0); jal iSignalSema
                uint32_t secondary = 0u;
                (void)readGuestU32(rdram, kSecondarySemaphoreAddr, secondary);
                setGuestRegU32(ctx, 4, secondary);
                ps2_syscalls::iSignalSema(rdram, ctx, runtime);
            }
            else
            {
                // Retail: sw $zero,-14096($v0) -> [0x0042C8F0] = 0
                (void)writeGuestU32(rdram, kClearFlagAddr, 0u);
            }
        }
        else
        {
            // Retail: sw $zero,-14096($v0) -> [0x0042C8F0] = 0
            (void)writeGuestU32(rdram, kClearFlagAddr, 0u);
        }

        // Retail: sw $zero,-14060($s0) -> [0x0042C914] = 0
        (void)writeGuestU32(rdram, kStateAddr, 0u);

        // Retail epilogue: ld $ra,16($sp); ld $s0,0($sp); jr $ra
        ctx->pc = getRegU32(ctx, 31);
    }

    inline void applyPrimalSifRpcCallbackOverride(PS2Runtime &runtime)
    {
        const bool stage1Installed = runtime.replaceFunction(kCallbackPc, &callbackStage1);
        const bool stage2Installed = runtime.replaceFunction(kReplyHandlerPc, &callbackStage2);

        RUNTIME_LOG("[game_overrides] Primal SIF/RPC callback: stage1 0x"
                    << std::hex << kCallbackPc << (stage1Installed ? " installed" : " FAILED")
                    << ", stage2 0x" << kReplyHandlerPc << (stage2Installed ? " installed" : " FAILED")
                    << std::dec);
    }

    inline const ps2_game_overrides::Descriptor kPrimalSifRpcCallbackDescriptor{
        "Primal SIF/RPC reply callback",
        "SCUS_971.42",
        0x00100008u,
        0xAB6FB13Cu,
        &applyPrimalSifRpcCallbackOverride
    };

    inline const ps2_game_overrides::AutoRegister kPrimalSifRpcCallbackRegistrar{
        kPrimalSifRpcCallbackDescriptor
    };
}

// ---------------------------------------------------------------------------
// Primal (SCUS_971.42) CDVD media-type query.
//
// Retail helper 0x003F51A0 initializes the CDVD client, submits SIF/RPC
// command 0x0E, waits for the reply semaphore, and returns the word copied to
// guest address 0x0042C940. Its caller at 0x003F5A58 compares that word with
// 6 at 0x003F5AAC. The host-side synthetic CDVD service currently completes
// command 0x0E with 1, so the retail caller enters the repeated read path.
//
// Keep the complete retail init/RPC/wait sequence and normalize only the
// successful media-type return continuation. The five dense-table entries are
// the entry point plus the generated continuation labels 0x003F51B4,
// 0x003F51F4, 0x003F5208, and 0x003F5224.
//
// The decisive load is the delay-slot instruction at 0x003F5220:
//   lw $s0,0($v0), where $v0 = 0x2042C940
// It runs before the generated helper resumes at 0x003F5224, so changing $v0
// only after the helper returns is too late. At the successful continuation,
// publish the retail media type in guest RAM and in the already-loaded $s0;
// the original generated helper then moves that value into $v0.
//
// Evidence: config/output/FUN_003f51a0_0x3f51a0.cpp and
// config/output/FUN_003f5a58_0x3f5a58.cpp from the raw SCUS_971.42 TU
// export. In particular, 0x003F5224 moves the reply word into $v0 and
// 0x003F5AAC compares $v0 with 6.
// ---------------------------------------------------------------------------
namespace ps2_game_overrides::primal_cdvd_media_type
{
    constexpr uint32_t kTypeQueryEntryPc = 0x003F51A0u;
    constexpr uint32_t kTypeQueryContinuationPcs[] = {
        0x003F51A0u,
        0x003F51B4u,
        0x003F51F4u,
        0x003F5208u,
        0x003F5224u,
    };
    constexpr uint32_t kSyntheticTypeReply = 1u;
    constexpr uint32_t kRetailAcceptedTypeReply = 6u;
    constexpr uint32_t kTypeQueryReturnPc = 0x003F5224u;
    constexpr uint32_t kTypeQueryReplyAddr = 0x0042C940u;

    // C++ inline variables have one address across translation units. Capture
    // the generated handler once, before any of its slots are replaced.
    inline PS2Runtime::RecompiledFunction gOriginalTypeQuery = nullptr;

    inline void typeQuery(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        if (gOriginalTypeQuery == nullptr || ctx == nullptr)
        {
            return;
        }

        // A checkpoint can resume directly at 0x003F5224. Its delay slot
        // at 0x003F5220 has already loaded the old reply into $s0, so publish
        // the accepted type before resuming the generated handler.
        const bool completingTypeQuery = ctx->pc == kTypeQueryReturnPc;
        if (completingTypeQuery)
        {
            (void)primal_sif_rpc::writeGuestU32(
                rdram, kTypeQueryReplyAddr, kRetailAcceptedTypeReply);
            primal_sif_rpc::setGuestRegU32(ctx, 16, kRetailAcceptedTypeReply);
        }

        gOriginalTypeQuery(rdram, ctx, runtime);

        // Direct calls normally execute the whole helper synchronously. In
        // that path 0x003F5224 is not a new dispatch, so the wrapper never
        // re-enters with completingTypeQuery set. Normalize only after the
        // generated helper has returned to its caller and only for the exact
        // synthetic reply value; intermediate checkpoint states are ignored.
        const bool returnedToCaller = ctx->pc == getRegU32(ctx, 31);
        if (!returnedToCaller || getRegU32(ctx, 2) != kSyntheticTypeReply)
        {
            return;
        }

        (void)primal_sif_rpc::writeGuestU32(
            rdram, kTypeQueryReplyAddr, kRetailAcceptedTypeReply);
        primal_sif_rpc::setGuestRegU32(ctx, 2, kRetailAcceptedTypeReply);
    }

    inline void applyPrimalCdvdMediaTypeOverride(PS2Runtime &runtime)
    {
        if (gOriginalTypeQuery == nullptr)
        {
            if (g_ps2RecompiledFunctionTableBase > kTypeQueryEntryPc ||
                g_ps2RecompiledFunctionTableEnd <= kTypeQueryEntryPc)
            {
                RUNTIME_LOG("[game_overrides] Primal CDVD media type: entry 0x"
                            << std::hex << kTypeQueryEntryPc << " is outside the generated table"
                            << std::dec);
                return;
            }

            const uint32_t slot = (kTypeQueryEntryPc - g_ps2RecompiledFunctionTableBase) >> 2u;
            if (slot >= g_ps2RecompiledFunctionTableSlotCount)
            {
                RUNTIME_LOG("[game_overrides] Primal CDVD media type: invalid generated slot");
                return;
            }

            gOriginalTypeQuery = g_ps2RecompiledFunctionTable[slot];
            if (gOriginalTypeQuery == nullptr)
            {
                RUNTIME_LOG("[game_overrides] Primal CDVD media type: generated handler is missing");
                return;
            }
        }

        bool allInstalled = true;
        for (const uint32_t pc : kTypeQueryContinuationPcs)
        {
            if (!runtime.replaceFunction(pc, &typeQuery))
            {
                allInstalled = false;
            }
        }

        RUNTIME_LOG("[game_overrides] Primal CDVD media type: "
                    << (allInstalled ? "installed" : "FAILED")
                    << " for entry 0x" << std::hex << kTypeQueryEntryPc
                    << std::dec);
    }

    inline const ps2_game_overrides::Descriptor kPrimalCdvdMediaTypeDescriptor{
        "Primal CDVD media type query",
        "SCUS_971.42",
        0x00100008u,
        0xAB6FB13Cu,
        &applyPrimalCdvdMediaTypeOverride
    };

    inline const ps2_game_overrides::AutoRegister kPrimalCdvdMediaTypeRegistrar{
        kPrimalCdvdMediaTypeDescriptor};
}

// ---------------------------------------------------------------------------
// Primal (SCUS_971.42) CDVD S-command completion status.
//
// Retail helper 0x003F5C38 waits for the outstanding CDVD S-command, reads the
// completion word copied to guest address 0x0042DAC0, releases the semaphore,
// and returns that word. Its caller at 0x002F5AF4 retries the complete
// disk-read sequence while the returned word is nonzero. The synthetic host
// service completes every CDVD command with 1, so the retail success path is
// never taken.
//
// Preserve the complete generated wait/semaphore sequence and normalize only
// the synthetic completion word at the return boundary. The generated helper
// loads the reply in the delay slot at 0x003F5CB8 and copies $s0 to $v0 at
// 0x003F5CBC, before it restores $ra and returns to 0x002F5AF4.
//
// Evidence: config/output/FUN_003f5c38_0x3f5c38.cpp and
// config/output/FUN_002f5930_0x2f5930.cpp from the raw SCUS_971.42 TU export.
// ---------------------------------------------------------------------------
namespace ps2_game_overrides::primal_cdvd_sync_status
{
    constexpr uint32_t kSyncStatusEntryPc = 0x003F5C38u;
    constexpr uint32_t kSyncStatusContinuationPcs[] = {
        0x003F5C38u,
        0x003F5C4Cu,
        0x003F5C8Cu,
        0x003F5CA0u,
        0x003F5CBCu,
    };
    constexpr uint32_t kSyntheticStatusReply = 1u;
    constexpr uint32_t kRetailSuccessReply = 0u;
    constexpr uint32_t kSyncStatusReplyAddr = 0x0042DAC0u;

    // C++ inline variables have one address across translation units. Capture
    // the generated handler once, before any of its slots are replaced.
    inline PS2Runtime::RecompiledFunction gOriginalSyncStatus = nullptr;

    inline uint32_t gSyncStatusTelemetryCalls = 0u;

    inline void syncStatus(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        if (gOriginalSyncStatus == nullptr || ctx == nullptr)
        {
            return;
        }

        const uint32_t callIndex = gSyncStatusTelemetryCalls++;
        const bool traceCall = callIndex < 8u;
        if (traceCall)
        {
            RUNTIME_LOG("[game_overrides] Primal CDVD sync status: enter #"
                        << callIndex << " pc=0x" << std::hex << ctx->pc
                        << " ra=0x" << getRegU32(ctx, 31)
                        << " v0=0x" << getRegU32(ctx, 2)
                        << std::dec);
            std::cout.flush();
        }

        gOriginalSyncStatus(rdram, ctx, runtime);

        // A direct call executes the whole generated helper synchronously. Only
        // a completed helper that has restored its caller return address is
        // eligible for normalization; checkpoint continuations are ignored.
        const bool returnedToCaller = ctx->pc == getRegU32(ctx, 31);
        if (traceCall)
        {
            RUNTIME_LOG("[game_overrides] Primal CDVD sync status: return #"
                        << callIndex << " pc=0x" << std::hex << ctx->pc
                        << " ra=0x" << getRegU32(ctx, 31)
                        << " v0=0x" << getRegU32(ctx, 2)
                        << " s0=0x" << getRegU32(ctx, 16)
                        << " returned=" << returnedToCaller << std::dec);
            std::cout.flush();
        }
        if (!returnedToCaller || getRegU32(ctx, 2) != kSyntheticStatusReply)
        {
            return;
        }

        (void)primal_sif_rpc::writeGuestU32(
            rdram, kSyncStatusReplyAddr, kRetailSuccessReply);
        primal_sif_rpc::setGuestRegU32(ctx, 2, kRetailSuccessReply);
        if (traceCall)
        {
            RUNTIME_LOG("[game_overrides] Primal CDVD sync status: normalized #"
                        << callIndex << " v0=0x"
                        << std::hex << getRegU32(ctx, 2) << std::dec);
            std::cout.flush();
        }
    }

    inline void applyPrimalCdvdSyncStatusOverride(PS2Runtime &runtime)
    {
        if (gOriginalSyncStatus == nullptr)
        {
            if (g_ps2RecompiledFunctionTableBase > kSyncStatusEntryPc ||
                g_ps2RecompiledFunctionTableEnd <= kSyncStatusEntryPc)
            {
                RUNTIME_LOG("[game_overrides] Primal CDVD sync status: entry 0x"
                            << std::hex << kSyncStatusEntryPc << " is outside the generated table"
                            << std::dec);
                return;
            }

            const uint32_t slot = (kSyncStatusEntryPc - g_ps2RecompiledFunctionTableBase) >> 2u;
            if (slot >= g_ps2RecompiledFunctionTableSlotCount)
            {
                RUNTIME_LOG("[game_overrides] Primal CDVD sync status: invalid generated slot");
                return;
            }

            gOriginalSyncStatus = g_ps2RecompiledFunctionTable[slot];
            if (gOriginalSyncStatus == nullptr)
            {
                RUNTIME_LOG("[game_overrides] Primal CDVD sync status: generated handler is missing");
                return;
            }
        }

        bool allInstalled = true;
        for (const uint32_t pc : kSyncStatusContinuationPcs)
        {
            if (!runtime.replaceFunction(pc, &syncStatus))
            {
                allInstalled = false;
            }
        }

        RUNTIME_LOG("[game_overrides] Primal CDVD sync status: "
                    << (allInstalled ? "installed" : "FAILED")
                    << " for entry 0x" << std::hex << kSyncStatusEntryPc
                    << std::dec);
    }

    inline const ps2_game_overrides::Descriptor kPrimalCdvdSyncStatusDescriptor{
        "Primal CDVD sync status",
        "SCUS_971.42",
        0x00100008u,
        0xAB6FB13Cu,
        &applyPrimalCdvdSyncStatusOverride
    };

    inline const ps2_game_overrides::AutoRegister kPrimalCdvdSyncStatusRegistrar{
        kPrimalCdvdSyncStatusDescriptor};
}

// ---------------------------------------------------------------------------
// Primal (SCUS_971.42) PAD startup.
//
// The retail PAD initializer binds SIO2MAN (0x80000100) and PADMAN
// (0x80000101) before reading the controller type. This host does not expose
// either IOP service, so the RPC_END server-data word stays zero and the
// initializer retries the first bind forever.
//
// This exact retail image does not require a controller to reach the title
// screen. Keep the retail non-blocking state instead: the PAD library is
// marked initialized, no PAD event is pending, and the helper returns zero
// through $ra. Later PAD polling helpers observe the zero event flag and
// return without another RPC wait.
// ---------------------------------------------------------------------------
namespace ps2_game_overrides::primal_pad_startup
{
    constexpr uint32_t kPadInitializerPc = 0x003F3810u;
    constexpr uint32_t kPadInitializedAddr = 0x0042C850u;
    constexpr uint32_t kPadEventPendingAddr = 0x0042C854u;

    template <void (*StubFn)(uint8_t *, R5900Context *, PS2Runtime *)>
    inline void padStubWrapper(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        if (ctx == nullptr)
        {
            return;
        }
        StubFn(rdram, ctx, runtime);
        ctx->pc = getRegU32(ctx, 31);
    }

    inline void padInitializer(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        if (ctx == nullptr)
        {
            return;
        }

        (void)primal_sif_rpc::writeGuestU32(rdram, kPadInitializedAddr, 1u);
        (void)primal_sif_rpc::writeGuestU32(rdram, kPadEventPendingAddr, 0u);
        ps2_stubs::scePadInit(rdram, ctx, runtime);
        ctx->pc = getRegU32(ctx, 31); // $ra
    }

    inline void padGetStateLogged(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        if (ctx == nullptr)
        {
            return;
        }
        ps2_stubs::scePadGetState(rdram, ctx, runtime);
        static int s_calls = 0;
        if (s_calls < 6)
        {
            std::printf("[pad-diag] scePadGetState(port=%u, slot=%u) -> %d\n",
                        getRegU32(ctx, 4), getRegU32(ctx, 5), static_cast<int32_t>(getRegU32(ctx, 2)));
            ++s_calls;
        }
        ctx->pc = getRegU32(ctx, 31);
    }

    inline void padReadLogged(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        if (ctx == nullptr)
        {
            return;
        }
        ps2_stubs::scePadRead(rdram, ctx, runtime);
        if (getRegU32(ctx, 4) == 0u)
        {
            using clock = std::chrono::steady_clock;
            static auto s_padLast = clock::now();
            static uint64_t s_padFrames = 0;
            static uint64_t s_padTotal = 0;
            ++s_padFrames;
            ++s_padTotal;
            const auto now = clock::now();
            const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - s_padLast).count();
            if (ms >= 1000)
            {
                s_padLast = now;
                std::printf("[pad-fps] frames=%llu in %lldms (total=%llu)\n",
                            static_cast<unsigned long long>(s_padFrames),
                            static_cast<long long>(ms),
                            static_cast<unsigned long long>(s_padTotal));
                s_padFrames = 0;
            }
        }
        const uint32_t addr = getRegU32(ctx, 6);
        uint8_t *p = (rdram != nullptr && addr < PS2_RAM_SIZE) ? (rdram + addr) : nullptr;
        static uint64_t s_scriptFrame = 0;
        if (getRegU32(ctx, 4) == 0u && p != nullptr &&
            static_cast<int32_t>(getRegU32(ctx, 2)) > 0 && p[0] == 0x00u)
        {
            if (primal::harness::hasScript())
            {
                primal::harness::applyScriptedPad(s_scriptFrame++, p);
            }
            else
            {
                static const bool s_autoPadStart = [] {
                    const char *e1 = std::getenv("PS2_AUTO_PAD_START");
                    const char *e2 = std::getenv("PS2_AUTO_PAD");
                    return (e1 != nullptr && e1[0] == '1') || (e2 != nullptr && e2[0] == '1');
                }();
                if (s_autoPadStart)
                {
                // Wall-clock button spam (retail hint: "spam X every few seconds" advances
                // past the intro/title). 1 s cycle: pressed for the first 150 ms, released
                // for the rest; alternate CROSS (X) and START every 3 cycles.
                using padClock = std::chrono::steady_clock;
                static auto s_padT0 = padClock::now();
                static bool s_padWasPressed = false;
                const auto padNow = padClock::now();
                const uint64_t padMs = static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(padNow - s_padT0).count());
                const uint64_t cycle = padMs / 1000u;
                const uint64_t phase = padMs % 1000u;
                const bool pressed = phase < 150u;
                const bool useCross = (cycle % 6u) < 3u;
                uint32_t stateFn = 0u;
                std::memcpy(&stateFn, rdram + 0x004F1EF4u, sizeof(stateFn));
                if (pressed)
                {
                    if (useCross)
                        p[3] = static_cast<uint8_t>(p[3] & ~0x40u); // CROSS (X)
                    else
                        p[2] = static_cast<uint8_t>(p[2] & ~0x08u); // START
                }
                    if (pressed != s_padWasPressed)
                    {
                        s_padWasPressed = pressed;
                        if (pressed)
                        {
                            RUNTIME_LOG("[auto-pad] injecting " << (useCross ? "CROSS" : "START")
                                        << " at ms=" << padMs
                                        << " stateFn=0x" << std::hex << stateFn << std::dec << std::endl);
                        }
                    }
                }
            }
        }
        static int s_calls = 0;
        if (s_calls < 4 || (p != nullptr && (p[2] != 0xFFu || p[3] != 0xFFu)))
        {
            static int s_pressedLogs = 0;
            if (s_calls < 4 || s_pressedLogs < 10)
            {
                std::printf("[pad-diag] scePadRead(port=%u, slot=%u, addr=0x%x) -> %d data=%02x,%02x,%02x,%02x\n",
                            getRegU32(ctx, 4), getRegU32(ctx, 5), addr,
                            static_cast<int32_t>(getRegU32(ctx, 2)),
                            p ? p[0] : 0, p ? p[1] : 0, p ? p[2] : 0, p ? p[3] : 0);
                if (p != nullptr && (p[2] != 0xFFu || p[3] != 0xFFu))
                {
                    ++s_pressedLogs;
                }
            }
            ++s_calls;
        }
        ctx->pc = getRegU32(ctx, 31);
    }

    inline void applyPrimalPadStartupOverride(PS2Runtime &runtime)
    {
        bool ok = runtime.replaceFunction(kPadInitializerPc, &padInitializer);
        ok = runtime.replaceFunction(0x003F39F0u, &padStubWrapper<ps2_stubs::scePadPortOpen>) && ok;
        ok = runtime.replaceFunction(0x003F3C38u, &padReadLogged) && ok;
        ok = runtime.replaceFunction(0x003F3CB8u, &padGetStateLogged) && ok;
        ok = runtime.replaceFunction(0x003F3DA0u, &padStubWrapper<ps2_stubs::scePadGetReqState>) && ok;
        ok = runtime.replaceFunction(0x003F3DF8u, &padStubWrapper<ps2_stubs::scePadInfoAct>) && ok;
        ok = runtime.replaceFunction(0x003F3F20u, &padStubWrapper<ps2_stubs::scePadInfoMode>) && ok;
        ok = runtime.replaceFunction(0x003F4058u, &padStubWrapper<ps2_stubs::scePadSetMainMode>) && ok;
        ok = runtime.replaceFunction(0x003F4110u, &padStubWrapper<ps2_stubs::scePadSetActDirect>) && ok;
        ok = runtime.replaceFunction(0x003F41D0u, &padStubWrapper<ps2_stubs::scePadSetActAlign>) && ok;
        ok = runtime.replaceFunction(0x003F4410u, &padStubWrapper<ps2_stubs::scePadInfoPressMode>) && ok;
        ok = runtime.replaceFunction(0x003F4470u, &padStubWrapper<ps2_stubs::scePadEnterPressMode>) && ok;
        RUNTIME_LOG("[game_overrides] Primal PAD startup: "
                    << (ok ? "installed" : "FAILED")
                    << " (12 libpad functions wired)");
    }

    inline const ps2_game_overrides::Descriptor kPrimalPadStartupDescriptor{
        "Primal PAD startup",
        "SCUS_971.42",
        0x00100008u,
        0xAB6FB13Cu,
        &applyPrimalPadStartupOverride
    };

    inline const ps2_game_overrides::AutoRegister kPrimalPadStartupRegistrar{
        kPrimalPadStartupDescriptor
    };
}

// ---------------------------------------------------------------------------
// Primal (SCUS_971.42) minimal Memory Card (libmc) override.
// Reports a formatted 8MB PS2 Memory Card in port 0, slot 0 (8000 KB free)
// so the game can proceed past the Memory Card check.
// ---------------------------------------------------------------------------
namespace ps2_game_overrides::primal_mc
{
    inline int32_t g_lastCmd = 0;
    inline int32_t g_lastResult = 0;

    inline void mcInitOverride(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        (void)rdram;
        (void)runtime;
        if (ctx == nullptr)
        {
            return;
        }
        g_lastCmd = 0;
        g_lastResult = 0;
        primal_sif_rpc::setGuestRegU32(ctx, 2, 0u);
        ctx->pc = getRegU32(ctx, 31);
    }

    inline void mcGetInfoOverride(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        (void)runtime;
        if (ctx == nullptr)
        {
            return;
        }
        const int32_t port = static_cast<int32_t>(getRegU32(ctx, 4));
        const int32_t slot = static_cast<int32_t>(getRegU32(ctx, 5));
        const uint32_t typePtr = getRegU32(ctx, 6);
        const uint32_t freePtr = getRegU32(ctx, 7);
        const uint32_t formatPtr = getRegU32(ctx, 8);

        const bool hasCard = (port == 0 && slot == 0);
        if (typePtr != 0u)
        {
            (void)primal_sif_rpc::writeGuestU32(rdram, typePtr, hasCard ? 2u : 0u);
        }
        if (freePtr != 0u)
        {
            (void)primal_sif_rpc::writeGuestU32(rdram, freePtr, hasCard ? 8000u : 0u);
        }
        if (formatPtr != 0u)
        {
            (void)primal_sif_rpc::writeGuestU32(rdram, formatPtr, hasCard ? 1u : 0u);
        }

        g_lastCmd = 2; // sceMcFuncNoGetInfo
        g_lastResult = hasCard ? 0 : -1;
        primal_sif_rpc::setGuestRegU32(ctx, 2, 0u);
        ctx->pc = getRegU32(ctx, 31);
    }

    inline void mcGetDirOverride(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        (void)rdram;
        (void)runtime;
        if (ctx == nullptr)
        {
            return;
        }
        g_lastCmd = 12; // sceMcFuncNoGetDir
        g_lastResult = 0; // 0 entries on empty formatted card
        primal_sif_rpc::setGuestRegU32(ctx, 2, 0u);
        ctx->pc = getRegU32(ctx, 31);
    }

    inline void entry_32a8b4(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        if (ctx == nullptr || runtime == nullptr)
        {
            return;
        }
        const uint32_t s1 = getRegU32(ctx, 17);
        uint32_t a0 = 0u, a1 = 0u, t1 = 0u;
        (void)primal_sif_rpc::readGuestU32(rdram, s1 + 0u, a0);
        (void)primal_sif_rpc::readGuestU32(rdram, s1 + 4u, a1);
        (void)primal_sif_rpc::readGuestU32(rdram, s1 + 184u, t1);
        primal_sif_rpc::setGuestRegU32(ctx, 4, a0);
        primal_sif_rpc::setGuestRegU32(ctx, 5, a1);
        primal_sif_rpc::setGuestRegU32(ctx, 6, 0x0047ABF0u);
        primal_sif_rpc::setGuestRegU32(ctx, 7, 0u);
        primal_sif_rpc::setGuestRegU32(ctx, 8, 32u);
        primal_sif_rpc::setGuestRegU32(ctx, 9, t1);
        mcGetDirOverride(rdram, ctx, runtime);
        (void)primal_sif_rpc::writeGuestU32(rdram, s1 + 48u, 25u);
        ctx->pc = 0x0032A944u;
    }

    inline void entry_32a8e0(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        (void)runtime;
        if (ctx == nullptr)
        {
            return;
        }
        const uint32_t s1 = getRegU32(ctx, 17);
        uint32_t v1u = 0u;
        (void)primal_sif_rpc::readGuestU32(rdram, s1 + 24u, v1u);
        const int32_t v1 = static_cast<int32_t>(v1u);
        primal_sif_rpc::setGuestRegU32(ctx, 3, v1u);
        primal_sif_rpc::setGuestRegU32(ctx, 2, 1u);
        if (v1 >= 0)
        {
            ctx->pc = 0x0032A904u;
            return;
        }
        const uint32_t sp = getRegU32(ctx, 29);
        (void)primal_sif_rpc::writeGuestU32(rdram, s1 + 32u, v1u);
        (void)primal_sif_rpc::writeGuestU32(rdram, sp + 48u, 1u);
        (void)primal_sif_rpc::writeGuestU32(rdram, s1 + 188u, 0u);
        (void)primal_sif_rpc::writeGuestU32(rdram, s1 + 52u, 0u);
        (void)primal_sif_rpc::writeGuestU32(rdram, s1 + 48u, 0u);
        ctx->pc = 0x0032A944u;
    }

    inline void mcSyncOverride(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        (void)runtime;
        if (ctx == nullptr)
        {
            return;
        }
        const uint32_t cmdPtr = getRegU32(ctx, 5);
        const uint32_t resultPtr = getRegU32(ctx, 6);
        if (cmdPtr != 0u)
        {
            (void)primal_sif_rpc::writeGuestU32(rdram, cmdPtr, static_cast<uint32_t>(g_lastCmd));
        }
        if (resultPtr != 0u)
        {
            (void)primal_sif_rpc::writeGuestU32(rdram, resultPtr, static_cast<uint32_t>(g_lastResult));
        }
        static int s_mcSyncLogs = 0;
        if (s_mcSyncLogs < 10)
        {
            ++s_mcSyncLogs;
            RUNTIME_LOG("[primal-mc] sceMcSync cmd=" << g_lastCmd << " res=" << g_lastResult
                        << " ra=0x" << std::hex << getRegU32(ctx, 31) << std::dec << std::endl);
        }
        primal_sif_rpc::setGuestRegU32(ctx, 2, 1u); // finished
        ctx->pc = getRegU32(ctx, 31);
    }

    inline void applyPrimalMcOverride(PS2Runtime &runtime)
    {
        bool ok = runtime.replaceFunction(0x003F27D0u, &mcInitOverride);
        ok = runtime.replaceFunction(0x003F3070u, &mcGetInfoOverride) && ok;
        ok = runtime.replaceFunction(0x003F31F8u, &mcGetDirOverride) && ok;
        ok = runtime.replaceFunction(0x003F2F38u, &mcSyncOverride) && ok;
        ok = runtime.replaceFunction(0x0032A8B4u, &entry_32a8b4) && ok;
        ok = runtime.replaceFunction(0x0032A8E0u, &entry_32a8e0) && ok;
        RUNTIME_LOG("[game_overrides] Primal MC override: " << (ok ? "installed" : "FAILED"));
    }

    inline const ps2_game_overrides::Descriptor kPrimalMcDescriptor{
        "Primal MC override",
        "SCUS_971.42",
        0x00100008u,
        0xAB6FB13Cu,
        &applyPrimalMcOverride
    };

    inline const ps2_game_overrides::AutoRegister kPrimalMcRegistrar{
        kPrimalMcDescriptor
    };
}

// ---------------------------------------------------------------------------
// Primal (SCUS_971.42) trigonometric lookup-table initialization.
//
// The retail initializer at 0x0037B708 fills 0x004FFE00..0x0050FE03 with
// 0x4001 single-precision values:
//
//   table[i] = acosf((float)i * (1.0f / 8192.0f) - 1.0f)
//
// for i = 0..0x4000. Its generated form calls the guest acosf implementation
// once per entry. Under the recompiler that nested kernel call is prohibitively
// slow and the game remains at the table-store continuation (0x0037B75C)
// instead of advancing to the title screen.
//
// Compute the same table directly in the host runtime. The destination is a
// contiguous range in EE RAM. The generated function has no externally visible
// side effects besides the table and its return state: it restores s0, s1,
// f20, f21 and sp before returning, leaves v0 = 0, and leaves the final
// acosf(1.0f) result in f0 (zero).
// ---------------------------------------------------------------------------
namespace ps2_game_overrides::primal_math_table
{
    constexpr uint32_t kInitializerPc = 0x0037B708u;
    constexpr uint32_t kTableAddress = 0x004FFE00u;
    constexpr uint32_t kEntryCount = 0x4001u;
    constexpr uint32_t kEntryBytes = 4u;
    constexpr uint32_t kTableBytes = kEntryCount * kEntryBytes;
    constexpr float kInputScale = 1.0f / 8192.0f;
    constexpr float kInputOffset = -1.0f;

    inline void writeFloatLE(uint8_t *destination, float value)
    {
        uint32_t bits = 0u;
        std::memcpy(&bits, &value, sizeof(bits));
        destination[0] = static_cast<uint8_t>(bits & 0xFFu);
        destination[1] = static_cast<uint8_t>((bits >> 8) & 0xFFu);
        destination[2] = static_cast<uint8_t>((bits >> 16) & 0xFFu);
        destination[3] = static_cast<uint8_t>((bits >> 24) & 0xFFu);
    }

    inline void initializer(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        (void)runtime;
        if (ctx == nullptr)
        {
            return;
        }

        uint8_t *table = nullptr;
        uint32_t available = 0u;
        const bool mapped = primal_sif_rpc::mapGuestRange(
            rdram, kTableAddress, table, available);
        if (!mapped || table == nullptr || available < kTableBytes)
        {
            RUNTIME_LOG("[game_overrides] Primal math table: destination 0x"
                        << std::hex << kTableAddress
                        << " is not writable" << std::dec);
        }
        else
        {
            for (uint32_t index = 0u; index < kEntryCount; ++index)
            {
                const float input = static_cast<float>(index) * kInputScale + kInputOffset;
                const float value = std::acos(input);
                writeFloatLE(table + index * kEntryBytes, value);
            }
        }

        // Match the retail return state after the final acosf(1.0f) call.
        primal_sif_rpc::setGuestRegU32(ctx, 2, 0u); // $v0
        ctx->f[0] = 0.0f;                           // $f0
        ctx->pc = getRegU32(ctx, 31);               // $ra
    }

    inline void applyPrimalMathTableInitializerOverride(PS2Runtime &runtime)
    {
        const bool installed = runtime.replaceFunction(kInitializerPc, &initializer);
        RUNTIME_LOG("[game_overrides] Primal math table: "
                    << (installed ? "installed" : "FAILED")
                    << " for entry 0x" << std::hex << kInitializerPc << std::dec);
    }

    inline const ps2_game_overrides::Descriptor kPrimalMathTableInitializerDescriptor{
        "Primal math lookup-table initializer",
        "SCUS_971.42",
        0x00100008u,
        0xAB6FB13Cu,
        &applyPrimalMathTableInitializerOverride
    };

    inline const ps2_game_overrides::AutoRegister kPrimalMathTableInitializerRegistrar{
        kPrimalMathTableInitializerDescriptor
    };
}

// ---------------------------------------------------------------------------
// Primal (SCUS_971.42) private IOP-RPC stream client.
//
// The game-owned SID 0x1000 family (siblings 0x1001..0x1003) binds through
// the shared wrapper at 0x00330C90. The client structure is built by
// 0x003A37B8 and the startup path waits for it, so the flag layout decides
// whether the game can leave its startup at all.
//
// GhidraMCP trace of SCUS_971.42 (r5900:LE:32:default analysis, upstream
// GhidraMCP 7.0.0 headless server on 127.0.0.1:8089, 2026-11-09):
//
//   FUN_003A37B8  *client = 0x1000 (SID), client+0x3C = 0, client+0x10 =
//                 0x100-byte reply buffer, client+0x14 = RPC descriptor
//   FUN_00330C90  binds the SID through 0x003E6128 and, once the bind
//                 succeeded, stores 1 at client+0x3C ("client ready")
//   FUN_00330D00  request: clears client+0x3C and issues the RPC through
//                 0x003E62F8; the reply path sets client+0x3C again
//   FUN_003A3940  returns non-zero only when the descriptor is idle
//                 (FUN_003E64E8(client+0x14) == 0) and client+0x3C != 0
//   FUN_00100200  polls FUN_003A3940 in a do/while loop at 0x001002B0, which
//                 is exactly where the guest parks
//
// This host exposes no IOP service for these private SIDs, so the bind reply
// has zero server data, the bind loop never exits, and the RPC issued by the
// request wrapper is dropped (RPC_END server data stays zero). Replacing the
// binder entry with ret1 suppressed the whole function, so client+0x3C was
// never set and the startup poll could never succeed.
//
// The override below keeps the retail client state instead of deleting the
// client: the binder publishes the ready flag the retail bind would have
// published, and the request wrapper completes the request locally instead
// of issuing an RPC that no IOP service can answer. The reply buffer stays
// empty, which is the state the guest sees for an empty stream.
//
// Both handlers return through $ra. Because they replace the function at its
// entry, the retail prologue/epilogue is never executed and the caller stack
// remains balanced.
//
// Evidence: config/output/FUN_00330c90_0x330c90.cpp and
// config/output/FUN_003a37b8_0x3a37b8.cpp from the raw SCUS_971.42 TU export,
// plus the GhidraMCP decompilation of FUN_003A37B8, FUN_00330C90,
// FUN_00330D00 and FUN_003A3940 (reports/ghidramcp_trace_round2.md).
// ---------------------------------------------------------------------------
namespace ps2_game_overrides::primal_private_iop_rpc
{
    constexpr uint32_t kPrivateRpcBinderPc = 0x00330C90u;
    constexpr uint32_t kPrivateRpcRequestPc = 0x00330D00u;
    constexpr uint32_t kClientReadyFlagOffset = 0x3Cu;

    // Client structure layout (FUN_003A37B8 builds the stream client,
    // FUN_003296E0 builds the timer client):
    //   client+0x00 SID, +0x04 send length, +0x08 send pointer,
    //   +0x0C reply length, +0x10 reply pointer, +0x14 RPC descriptor,
    //   +0x3C ready flag
    constexpr uint32_t kClientSidOffset = 0x00u;
    constexpr uint32_t kClientReplyPointerOffset = 0x10u;

    constexpr uint32_t kStreamClientSid = 0x00001000u;
    constexpr uint32_t kTimerClientSid = 0x00001002u;
    constexpr uint32_t kTimerGetTimeFunction = 3u;

    // Guest clock structure: FUN_003296E0 allocates 0xB8 bytes and publishes
    // the pointer at DAT_004886C8+8. FUN_003A5B30 dispatches the frame
    // callbacks when the countdown dword at +0x24 reads zero, FUN_0032CD00
    // reads the 64-bit BCD stamp at +0x14/+0x18, and FUN_003307C8 prints the
    // BCD hh:mm:ss at +0x30.
    constexpr uint32_t kClockPointerSlot = 0x004886C8u;
    constexpr uint32_t kClockStructSlotOffset = 0x08u;
    constexpr uint32_t kClockMillisecondOffset = 0x10u;
    constexpr uint32_t kClockBcdTimeOffset = 0x14u;
    constexpr uint32_t kClockCountdownOffset = 0x24u;
    constexpr uint32_t kClockWallClockOffset = 0x30u;
    constexpr uint64_t kNanosPerFrame = 16666667ull; // 60 Hz NTSC

    inline uint32_t bcdFromBinary(uint32_t value)
    {
        return ((value / 10u) << 4) | (value % 10u);
    }

    // Retail bind: 0x00330C90 stores 1 at client+0x3C after the SID bind
    // succeeded. Publish that state directly because no IOP service owns
    // SID 0x1000 on this host.
    inline void privateRpcBinder(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        (void)runtime;
        if (ctx == nullptr)
        {
            return;
        }

        const uint32_t client = getRegU32(ctx, 4); // $a0
        (void)primal_sif_rpc::writeGuestU32(
            rdram, client + kClientReadyFlagOffset, 1u);
        primal_sif_rpc::setGuestRegU32(ctx, 2, 1u); // $v0
        ctx->pc = getRegU32(ctx, 31);              // $ra
    }

    // Retail request: 0x00330D00 clears client+0x3C and issues the RPC. The
    // reply path sets the flag again, so a completed request leaves the
    // client ready. Complete the request locally instead: no IOP service can
    // answer it and the reply buffer stays empty.
    //
    // The two private clients need different answers:
    //
    //   SID 0x1002 (timer, FUN_003296E0) - the retail IOP timer service writes
    //   the current time straight into the guest clock structure. The guest
    //   polls that structure through FUN_003297E0 and dispatches a frame when
    //   the countdown dword at clock+0x24 reads zero, so the host has to push
    //   the clock forward here.
    //
    //   SID 0x1000 (stream, FUN_003A37B8) - the guest reads the transferred
    //   byte count from word 1 of the reply packet in the client reply
    //   buffer. Leaving the request header in place would make the guest
    //   believe the whole requested chunk arrived, so publish an explicit
    //   zero-length answer instead.
    inline void fillGuestClock(uint8_t *rdram)
    {
        uint32_t timerClient = 0u;
        if (!primal_sif_rpc::readGuestU32(rdram, kClockPointerSlot, timerClient) ||
            timerClient == 0u)
        {
            return;
        }
        uint32_t clockStruct = 0u;
        if (!primal_sif_rpc::readGuestU32(
                rdram, timerClient + kClockStructSlotOffset, clockStruct) ||
            clockStruct == 0u)
        {
            return;
        }

        static std::chrono::steady_clock::time_point started =
            std::chrono::steady_clock::now();
        static std::chrono::steady_clock::time_point lastFrame = started;

        const auto now = std::chrono::steady_clock::now();
        bool frameDue = false;
        if (now - lastFrame >= std::chrono::nanoseconds(kNanosPerFrame))
        {
            lastFrame = now;
            frameDue = true;
        }

        const uint64_t elapsedMs = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(now - started).count());

        std::time_t wall =
            std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::tm parts{};
#if defined(_WIN32)
        localtime_s(&parts, &wall);
#else
        localtime_r(&wall, &parts);
#endif
        const uint32_t bcdTime =
            (bcdFromBinary(static_cast<uint32_t>(parts.tm_hour)) << 16) |
            (bcdFromBinary(static_cast<uint32_t>(parts.tm_min)) << 8) |
            bcdFromBinary(static_cast<uint32_t>(parts.tm_sec));

        // +0x10: sub-second field the timer module polls for a fresh reading
        (void)primal_sif_rpc::writeGuestU32(
            rdram, clockStruct + kClockMillisecondOffset,
            static_cast<uint32_t>(elapsedMs));
        // +0x14/+0x18: 64-bit BCD wall clock, low word first
        (void)primal_sif_rpc::writeGuestU32(
            rdram, clockStruct + kClockBcdTimeOffset, bcdTime);
        (void)primal_sif_rpc::writeGuestU32(
            rdram, clockStruct + kClockBcdTimeOffset + 4u, 0u);
        // +0x24: frame countdown, zero once the frame is due
        (void)primal_sif_rpc::writeGuestU32(
            rdram, clockStruct + kClockCountdownOffset, frameDue ? 0u : 1u);
        // +0x30: BCD hh:mm:ss printed by FUN_003307C8
        (void)primal_sif_rpc::writeGuestU32(
            rdram, clockStruct + kClockWallClockOffset, bcdTime);
        (void)primal_sif_rpc::writeGuestU32(
            rdram, clockStruct + kClockWallClockOffset + 4u, 0u);
    }

    inline void writeEmptyStreamReply(uint8_t *rdram, uint32_t client)
    {
        uint32_t replyPointer = 0u;
        if (!primal_sif_rpc::readGuestU32(
                rdram, client + kClientReplyPointerOffset, replyPointer) ||
            replyPointer == 0u)
        {
            return;
        }

        // word 0: packet flags, word 1: transferred bytes, word 2: checksum
        (void)primal_sif_rpc::writeGuestU32(rdram, replyPointer + 0u, 1u);
        (void)primal_sif_rpc::writeGuestU32(rdram, replyPointer + 4u, 0u);
        (void)primal_sif_rpc::writeGuestU32(rdram, replyPointer + 8u, 0u);
    }

    // SID 0x1000 serves raw sectors of the unlisted bulk area. Packet layout:
    // word0 mode (0x401 open / 0x180001 read), word1 byte count (in/out),
    // word2 sector offset (absolute base LBA for open, file-relative for
    // read). The read data lands in the client send buffer (client+0x08).
    inline std::ifstream &streamCdImage()
    {
        static std::ifstream image;
        static bool tried = false;
        if (!tried)
        {
            tried = true;
            const char *candidates[] = {std::getenv("PS2X_CD_IMAGE"),
                                        "Primal (USA).iso", "../Primal (USA).iso"};
            for (const char *path : candidates)
            {
                if (path == nullptr || *path == '\0')
                    continue;
                image.open(path, std::ios::binary);
                if (image.is_open())
                {
                    RUNTIME_LOG("[game_overrides] stream CD image: " << path);
                    break;
                }
                image.clear();
            }
            if (!image.is_open())
                RUNTIME_LOG("[game_overrides] stream CD image NOT found (set PS2X_CD_IMAGE)");
        }
        return image;
    }

    inline uint32_t &streamBaseLba()
    {
        static uint32_t s_baseLba = 0u;
        return s_baseLba;
    }

    inline void serveStreamRequest(uint8_t *rdram, uint32_t client, uint32_t function)
    {
        uint32_t &baseLba = streamBaseLba();
        static uint32_t logged = 0u;
        uint32_t replyPointer = 0u;
        if (!primal_sif_rpc::readGuestU32(rdram, client + kClientReplyPointerOffset, replyPointer) ||
            replyPointer == 0u)
            return;
        uint32_t mode = 0u, count = 0u, sector = 0u, sendLength = 0u, sendPointer = 0u;
        (void)primal_sif_rpc::readGuestU32(rdram, replyPointer + 0u, mode);
        (void)primal_sif_rpc::readGuestU32(rdram, replyPointer + 4u, count);
        (void)primal_sif_rpc::readGuestU32(rdram, replyPointer + 8u, sector);
        (void)primal_sif_rpc::readGuestU32(rdram, client + 0x04u, sendLength);
        (void)primal_sif_rpc::readGuestU32(rdram, client + 0x08u, sendPointer);

        if (function == 0u)
        {
            baseLba = sector;
            return;
        }

        const bool isIopSpuStream = (mode & 0xCu) != 0u;
        uint32_t transferred = 0u;
        if (sendPointer == 0u)
        {
            transferred = count;
        }
        else
        {
            std::ifstream &image = streamCdImage();
            uint8_t *host = nullptr;
            uint32_t available = 0u;
            if (image.is_open() && count != 0u &&
                primal_sif_rpc::mapGuestRange(rdram, sendPointer, host, available))
            {
                const uint32_t eeLimit = (sendLength != 0u && sendLength < count) ? sendLength : count;
                const uint32_t want = (eeLimit < available) ? eeLimit : available;
                image.clear();
                image.seekg(static_cast<std::streamoff>(baseLba + sector) * 2048, std::ios::beg);
                image.read(reinterpret_cast<char *>(host), want);
                const uint32_t got = static_cast<uint32_t>(image.gcount());
                transferred = (isIopSpuStream && got == want) ? count : got;
            }
        }
        if (logged < 100000u)
        {
            ++logged;
            RUNTIME_LOG("[game_overrides] stream read func=" << function << " lba=" << (baseLba + sector)
                        << " want=" << count << " sendLen=" << sendLength << " mode=0x" << std::hex << mode << std::dec
                        << " got=" << transferred
                        << " dst=0x" << std::hex << sendPointer << std::dec);
        }
        (void)primal_sif_rpc::writeGuestU32(rdram, replyPointer + 4u, transferred);
    }

    inline void serveStream1003Request(uint8_t *rdram, uint32_t client, uint32_t function, uint32_t parameter)
    {
        if (function != 0u)
            return;
        uint32_t replyPointer = 0u;
        if (!primal_sif_rpc::readGuestU32(rdram, client + kClientReplyPointerOffset, replyPointer) ||
            replyPointer == 0u)
            return;
        uint32_t lba = 0u, count = 0u, sendPointer = 0u;
        (void)primal_sif_rpc::readGuestU32(rdram, replyPointer + 0u, lba);
        (void)primal_sif_rpc::readGuestU32(rdram, replyPointer + 4u, count);
        (void)primal_sif_rpc::readGuestU32(rdram, client + 0x08u, sendPointer);

        const uint32_t absLba = streamBaseLba() + lba;
        uint32_t transferred = 0u;
        std::ifstream &image = streamCdImage();
        uint8_t *host = nullptr;
        uint32_t available = 0u;
        if (image.is_open() && count != 0u &&
            primal_sif_rpc::mapGuestRange(rdram, sendPointer, host, available))
        {
            const uint32_t want = (count < available) ? count : available;
            image.clear();
            image.seekg(static_cast<std::streamoff>(absLba) * 2048, std::ios::beg);
            image.read(reinterpret_cast<char *>(host), want);
            transferred = static_cast<uint32_t>(image.gcount());
        }
        static uint32_t logged1003 = 0u;
        if (logged1003 < 16u)
        {
            ++logged1003;
            RUNTIME_LOG("[game_overrides] stream1003 read rel=0x" << std::hex << lba
                        << std::dec << " abs=" << absLba
                        << " want=" << count << " got=" << transferred
                        << " dst=0x" << std::hex << sendPointer << std::dec
                        << " sync=" << (parameter == 0u ? 1 : 0) << std::endl);
        }
        (void)primal_sif_rpc::writeGuestU32(rdram, replyPointer + 4u, transferred);
    }

    inline void logPrivateRpcRequest(uint8_t *rdram, uint32_t client, uint32_t sid,
                                     uint32_t function, uint32_t parameter)
    {
        static uint32_t streamLogged = 0u;
        static uint32_t timerLogged = 0u;
        uint32_t &counter = (sid == kTimerClientSid) ? timerLogged : streamLogged;
        if (counter >= 100000u)
        {
            return;
        }
        ++counter;

        uint32_t sendLength = 0u;
        uint32_t sendPointer = 0u;
        uint32_t replyLength = 0u;
        uint32_t replyPointer = 0u;
        (void)primal_sif_rpc::readGuestU32(rdram, client + 0x04u, sendLength);
        (void)primal_sif_rpc::readGuestU32(rdram, client + 0x08u, sendPointer);
        (void)primal_sif_rpc::readGuestU32(rdram, client + 0x0Cu, replyLength);
        (void)primal_sif_rpc::readGuestU32(rdram, client + 0x10u, replyPointer);

        uint32_t packet[4] = {0u, 0u, 0u, 0u};
        for (uint32_t index = 0u; index < 4u; ++index)
        {
            (void)primal_sif_rpc::readGuestU32(
                rdram, replyPointer + index * 4u, packet[index]);
        }

        static const bool s_verboseLogs = [] {
            const char *e = std::getenv("PS2_PRIMAL_VERBOSE_LOGS");
            return e != nullptr && e[0] == '1';
        }();
        static uint32_t s_rpcLogCount = 0;
        if (s_verboseLogs || s_rpcLogCount < 24u)
        {
            ++s_rpcLogCount;
            RUNTIME_LOG("[game_overrides] private IOP-RPC sid=0x" << std::hex << sid
                        << std::dec << " function=" << function
                        << " parameter=" << parameter
                        << " sendLen=" << sendLength << " sendPtr=0x" << std::hex << sendPointer
                        << " replyLen=" << std::dec << replyLength
                        << " replyPtr=0x" << std::hex << replyPointer
                        << " packet=" << std::hex << packet[0] << "," << packet[1] << ","
                        << packet[2] << "," << packet[3] << std::dec << std::endl);
        }
    }

    inline void privateRpcRequest(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        (void)runtime;
        if (ctx == nullptr)
        {
            return;
        }

        const uint32_t client = getRegU32(ctx, 4);   // $a0
        const uint32_t function = getRegU32(ctx, 5); // $a1
        const uint32_t parameter = getRegU32(ctx, 6); // $a2

        uint32_t sid = 0u;
        (void)primal_sif_rpc::readGuestU32(
            rdram, client + kClientSidOffset, sid);
        logPrivateRpcRequest(rdram, client, sid, function, parameter);

        if (sid == kTimerClientSid)
        {
            if (function == kTimerGetTimeFunction)
            {
                fillGuestClock(rdram);
            }
        }
        else if (sid == kStreamClientSid)
        {
            serveStreamRequest(rdram, client, function);
        }
        else if (sid == 0x1003u)
        {
            serveStream1003Request(rdram, client, function, parameter);
        }

        // The retail request wrapper (0x330D00) clears client+0x3C before issuing and the
        // IOP reply re-sets it. Complete locally: always publish ready=1 after a request so
        // FUN_003a3940 keeps returning nonzero and the stream pump keeps issuing reads.
        (void)primal_sif_rpc::writeGuestU32(
            rdram, client + kClientReadyFlagOffset, 1u);

        ctx->pc = getRegU32(ctx, 31); // $ra
    }

    // 0x003A8370: leaf vtable method (slot 0xC) reached only via JALR from
    // 0x003A53D0, so no map row exists. Hand translation of its 12 words:
    //   if (((*(u32*)0x4F1F78) >> 4) & 1) return *(u32*)0x4F7110 - a1;
    //   return 0x7FFFFFFF;
    inline void vtableRemainingTicks(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        (void)runtime;
        uint32_t flags = 0u, value = 0u;
        (void)primal_sif_rpc::readGuestU32(rdram, 0x004F1F78u, flags);
        uint32_t result = 0x7FFFFFFFu;
        if ((flags >> 4) & 1u)
        {
            (void)primal_sif_rpc::readGuestU32(rdram, 0x004F7110u, value);
            result = value - getRegU32(ctx, 5);
        }
        primal_sif_rpc::setGuestRegU32(ctx, 3, 0x004F0000u);
        primal_sif_rpc::setGuestRegU32(ctx, 2, result);
        ctx->pc = getRegU32(ctx, 31);
    }

}

#if defined(_WIN32)
#include "H:/DeepSeekWorkspace/Primal_SR/config/vtable_delta_output/primal_vtable_overrides.inl"
#else
#include "/home/dshuser/workspace/Primal_SR/config/vtable_delta_output/primal_vtable_overrides.inl"
#endif

namespace ps2_game_overrides::primal_private_iop_rpc
{
    inline void applyPrimalPrivateIopRpcOverride(PS2Runtime &runtime)
    {
        const uint32_t vtableCount = primal_vtable_delta::registerAll(runtime);
        const bool vtableInstalled = runtime.replaceFunction(0x003A8370u, &vtableRemainingTicks);
        RUNTIME_LOG("[game_overrides] vtable delta registered " << vtableCount
                    << " slots; 0x3a8370 leaf " << (vtableInstalled ? "installed" : "FAILED"));
        const bool binderInstalled =
            runtime.replaceFunction(kPrivateRpcBinderPc, &privateRpcBinder);
        const bool requestInstalled =
            runtime.replaceFunction(kPrivateRpcRequestPc, &privateRpcRequest);
        RUNTIME_LOG("[game_overrides] Primal private IOP-RPC client: binder "
                    << (binderInstalled ? "installed" : "FAILED")
                    << ", request " << (requestInstalled ? "installed" : "FAILED")
                    << " for entries 0x" << std::hex << kPrivateRpcBinderPc
                    << "/0x" << kPrivateRpcRequestPc << std::dec);
    }

    inline const ps2_game_overrides::Descriptor kPrimalPrivateIopRpcDescriptor{
        "Primal private IOP-RPC client startup",
        "SCUS_971.42",
        0x00100008u,
        0xAB6FB13Cu,
        &applyPrimalPrivateIopRpcOverride
    };

    inline const ps2_game_overrides::AutoRegister kPrimalPrivateIopRpcRegistrar{
        kPrimalPrivateIopRpcDescriptor
    };
}

// ---------------------------------------------------------------------------
// Telemetry probe (circuit-breaker rule): attempt24 thread 1 returned from
// the retail function 0x002FA048 (frame 0x70, "sq $ra,0x60($sp)" in the
// prologue, "lq $ra,0x60($sp)" in the epilogue entry 0x002FA174) to
// $ra = 0x004F0000, which is the value the function keeps in $s20
// (lui $s20,0x4F) and saves at 0x40($sp). Either the stack slot is
// overwritten or $sp drifts by -0x20 between prologue and epilogue.
// The probe wraps the prologue entry, the loop head 0x002FA0B8 and the
// epilogue entry, logs $sp and the saved slots, and forwards to the
// original recompiled entries unchanged. Enabled with PS2_RA_PROBE=1.
// ---------------------------------------------------------------------------
namespace ps2_game_overrides::primal_ra_probe
{
    inline PS2Runtime::RecompiledFunction g_origEntry = nullptr;
    inline PS2Runtime::RecompiledFunction g_origLoop = nullptr;
    inline PS2Runtime::RecompiledFunction g_origEpilogue = nullptr;

    struct FrameRecord
    {
        uint32_t sp = 0u;
        uint32_t ra = 0u;
    };
    inline std::vector<FrameRecord> g_raStack;
    inline uint32_t g_logBudget = 100u;

    inline uint32_t rd(uint8_t *rdram, uint32_t addr)
    {
        uint32_t v = 0u;
        (void)primal_sif_rpc::readGuestU32(rdram, addr, v);
        return v;
    }

    inline void entryWrap(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t sp = getRegU32(ctx, 29);
        const uint32_t ra = getRegU32(ctx, 31);
        g_raStack.push_back({sp, ra});
        if (g_logBudget > 0u)
        {
            --g_logBudget;
            RUNTIME_LOG("[ra-probe] entry sp=0x" << std::hex << sp
                        << " ra=0x" << ra << std::dec);
        }
        g_origEntry(rdram, ctx, runtime);
    }

    inline void loopWrap(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        if (!g_raStack.empty())
        {
            const uint32_t expectedSp = g_raStack.back().sp - 0x70u;
            const uint32_t curSp = getRegU32(ctx, 29);
            if (curSp != expectedSp)
            {
                primal_sif_rpc::setGuestRegU32(ctx, 29, expectedSp);
            }
        }
        {
            const uint32_t taskFn = getRegU32(ctx, 2);
            static uint32_t s_seen[64] = {};
            static int s_seenCount = 0;
            bool found = false;
            for (int i = 0; i < s_seenCount; ++i)
            {
                if (s_seen[i] == taskFn) { found = true; break; }
            }
            if (!found && s_seenCount < 64)
            {
                s_seen[s_seenCount++] = taskFn;
                RUNTIME_LOG("[2fa0b8-task] idx=" << (s_seenCount - 1)
                            << " v0=0x" << std::hex << taskFn
                            << " s3=0x" << getRegU32(ctx, 19)
                            << " s1=0x" << getRegU32(ctx, 17) << std::dec << std::endl);
            }
        }
        g_origLoop(rdram, ctx, runtime);
    }

    inline void epilogueWrap(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        uint32_t expectedRa = 0u;
        uint32_t entrySp = 0u;
        if (!g_raStack.empty())
        {
            expectedRa = g_raStack.back().ra;
            entrySp = g_raStack.back().sp;
            g_raStack.pop_back();
        }

        // The function 0x002FA048 allocates 0x70 bytes on entry.
        // If an inner callee leaked stack space, restore $sp to (entrySp - 0x70)
        // BEFORE the epilogue executes so that lq $ra, 0x60($sp) and lq $s0..$s5
        // read their original values from their designated save slots, and the
        // epilogue's addiu $sp, $sp, 0x70 delay slot cleanly restores entrySp.
        if (entrySp != 0u)
        {
            const uint32_t expectedSp = entrySp - 0x70u;
            const uint32_t curSp = getRegU32(ctx, 29);
            if (curSp != expectedSp)
            {
                RUNTIME_LOG("[ra-probe] corrected drifted sp at 0x2fa174 from 0x"
                            << std::hex << curSp << " to 0x" << expectedSp << std::dec << std::endl);
                primal_sif_rpc::setGuestRegU32(ctx, 29, expectedSp);
            }
        }

        g_origEpilogue(rdram, ctx, runtime);

        // Post-epilogue safeguard: if ra was still loaded with 0x004F0000 or invalid
        if (expectedRa != 0u && (ctx->pc == 0x004F0000u || ctx->pc >= 0x004EE000u || ctx->pc == 0u))
        {
            RUNTIME_LOG("[ra-probe] post-epilogue corrected pc from 0x" << std::hex << ctx->pc
                        << " to expectedRa 0x" << expectedRa << std::dec << std::endl);
            ctx->pc = expectedRa;
        }
        if (entrySp != 0u && getRegU32(ctx, 29) != entrySp)
        {
            primal_sif_rpc::setGuestRegU32(ctx, 29, entrySp);
        }
    }

    inline PS2Runtime::RecompiledFunction g_orig286cc8 = nullptr;

    inline void wrap286cc8(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t ra = getRegU32(ctx, 31);
        if (g_orig286cc8)
            g_orig286cc8(rdram, ctx, runtime);
        if (ra == 0x002FA130u)
        {
            const uint32_t obj = getRegU32(ctx, 2);
            uint8_t *p = nullptr; uint32_t av = 0;
            auto r32 = [&](uint32_t a) -> uint32_t {
                return (primal_sif_rpc::mapGuestRange(rdram, a, p, av) && av >= 4) ? *(uint32_t*)p : 0xDEADu;
            };
            const uint32_t a0 = r32(obj + 0xCu);
            const uint32_t vt = r32(a0 + 0x10u);
            const uint32_t fn = r32(vt + 0xCu);
            static uint32_t s_seen[64] = {};
            static int s_cnt = 0;
            bool found = false;
            for (int i = 0; i < s_cnt; ++i)
                if (s_seen[i] == fn) { found = true; break; }
            if (!found && s_cnt < 64)
            {
                s_seen[s_cnt++] = fn;
                const bool hasFn = (runtime->lookupFunction(fn) != nullptr);
                RUNTIME_LOG("[2fa140-fn] idx=" << (s_cnt - 1)
                            << " fn=0x" << std::hex << fn
                            << " hasFn=" << (hasFn ? 1 : 0)
                            << " vt=0x" << vt << " a0=0x" << a0
                            << " s0=" << std::dec << getRegU32(ctx, 16) << std::endl);
            }
        }
    }

    inline void applyPrimalRaProbe(PS2Runtime &runtime)
    {
        const char *e = std::getenv("PS2_DISABLE_RA_PROBE");
        if (e != nullptr && e[0] == '1')
            return;
        g_origEntry = runtime.lookupFunction(0x002FA048u);
        g_origLoop = runtime.lookupFunction(0x002FA0B8u);
        g_origEpilogue = runtime.lookupFunction(0x002FA174u);
        g_orig286cc8 = runtime.lookupFunction(0x00286CC8u);
        if (g_orig286cc8)
            runtime.replaceFunction(0x00286CC8u, &wrap286cc8);
        bool ok = g_origEntry && g_origLoop && g_origEpilogue;
        if (ok)
        {
            ok = runtime.replaceFunction(0x002FA048u, &entryWrap) &&
                 runtime.replaceFunction(0x002FA0B8u, &loopWrap) &&
                 runtime.replaceFunction(0x002FA174u, &epilogueWrap);
        }
        RUNTIME_LOG("[game_overrides] ra-probe/repair 0x2fa048 " << (ok ? "installed" : "FAILED"));
    }

    inline const ps2_game_overrides::Descriptor kPrimalRaProbeDescriptor{
        "Primal 0x2fa048 return-address probe/repair",
        "SCUS_971.42",
        0x00100008u,
        0xAB6FB13Cu,
        &applyPrimalRaProbe
    };

    inline const ps2_game_overrides::AutoRegister kPrimalRaProbeRegistrar{
        kPrimalRaProbeDescriptor
    };
}

namespace ps2_game_overrides::primal_frame_gate
{
    inline PS2Runtime::RecompiledFunction g_origDispatch = nullptr;

    // FUN_003a5b30 is called continuously in both the streaming/loading loop
    // (FUN_002F7360) and the main game/renderer loop (Thread 1 0x2F7470 / 0x2F7560 / 0x2F7590).
    // Because statically recompiled code runs natively on x86_64, m_eeCycle falls
    // ~200-500x behind real wall-clock time unless paced. By measuring elapsed wall-clock
    // nanoseconds and accounting EE cycles (calibrated to 294.912 MHz), m_eeCycle stays
    // locked to real time, enabling EeScheduler to trigger VBLANK events accurately at 60 Hz.
    inline void dispatchWrap(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        using clock = std::chrono::steady_clock;
        static bool s_inited = false;
        static auto s_lastTime = clock::now();
        const auto now = clock::now();
        if (!s_inited)
        {
            s_inited = true;
            s_lastTime = now;
        }
        else
        {
            const auto elapsedNs = std::chrono::duration_cast<std::chrono::nanoseconds>(now - s_lastTime).count();
            if (elapsedNs > 0)
            {
                // 294.912 MHz EE clock: cycles = elapsedNs * 294912 / 1000000
                uint64_t cycles = (static_cast<uint64_t>(elapsedNs) * 294912ULL) / 1000000ULL;
                if (cycles > 0)
                {
                    s_lastTime = now;
                    // Cap at ~33ms (2 frames = 10,000,000 cycles) to prevent huge jumps on stalls
                    if (cycles > 10000000ULL)
                        cycles = 10000000ULL;
                    if (runtime != nullptr)
                    {
                        runtime->eeScheduler().accountCycles(static_cast<uint32_t>(cycles));
                    }
                }
            }
        }
        {
            static bool s_logged73a4 = false;
            if (!s_logged73a4 && getRegU32(ctx, 31) == 0x002F73A4u)
            {
                s_logged73a4 = true;
                const uint32_t s0 = getRegU32(ctx, 16);
                uint8_t *p = nullptr; uint32_t av = 0;
                auto r32 = [&](uint32_t a) -> uint32_t {
                    return (primal_sif_rpc::mapGuestRange(rdram, a, p, av) && av >= 4) ? *(uint32_t*)p : 0xDEADu;
                };
                const uint32_t vt = r32(s0 + 0x1Cu);
                const uint32_t fn10 = r32(vt + 0x10u);
                RUNTIME_LOG("[73a4-probe] s0=0x" << std::hex << s0
                            << " vt=0x" << vt << " fn10=0x" << fn10 << std::dec << std::endl);
            }
        }
        {
            static auto s_hbLast = clock::now();
            static uint64_t s_hbCalls = 0;
            ++s_hbCalls;
            const auto hbMs = std::chrono::duration_cast<std::chrono::milliseconds>(now - s_hbLast).count();
            if (hbMs >= 1000)
            {
                s_hbLast = now;
                RUNTIME_LOG("[frame-gate] calls=" << s_hbCalls
                            << " ra=0x" << std::hex << getRegU32(ctx, 31)
                            << " a0=0x" << getRegU32(ctx, 4) << std::dec << std::endl);
                s_hbCalls = 0;
            }
        }
        g_origDispatch(rdram, ctx, runtime);
    }

    inline void applyPrimalFrameGate(PS2Runtime &runtime)
    {
        const char *e = std::getenv("PS2_DISABLE_FRAME_GATE");
        if (e != nullptr && e[0] == '1')
            return;
        g_origDispatch = runtime.lookupFunction(0x003A5B30u);
        const bool ok = g_origDispatch != nullptr &&
                        runtime.replaceFunction(0x003A5B30u, &dispatchWrap);
        RUNTIME_LOG("[game_overrides] frame-gate/pacer 0x3a5b30 " << (ok ? "installed" : "FAILED"));
    }

    inline const ps2_game_overrides::Descriptor kPrimalFrameGateDescriptor{
        "Primal frame-dispatch pacer",
        "SCUS_971.42",
        0x00100008u,
        0xAB6FB13Cu,
        &applyPrimalFrameGate
    };

    inline const ps2_game_overrides::AutoRegister kPrimalFrameGateRegistrar{
        kPrimalFrameGateDescriptor
    };
}

namespace ps2_game_overrides::primal_null_pc
{
    // Some guest code paths end in jalr to a null vtable slot (observed:
    // 0x2fa40c -> target 0x0 after the 0x2FA048 frame corruption). Register a
    // no-op at pc 0 so the jump lands somewhere valid and returns.
    inline void nullPcStub(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        (void)rdram; (void)runtime;
        const uint32_t ra = getRegU32(ctx, 31);
        ctx->pc = ra;
        RUNTIME_LOG("[game_overrides] null-pc stub called: returning to ra=0x" << std::hex << ra << std::dec << std::endl);
    }

    inline void applyPrimalNullPc(PS2Runtime &runtime)
    {
        const char *e = std::getenv("PS2_DISABLE_NULL_PC_STUB");
        if (e != nullptr && e[0] == '1')
            return;
        runtime.setMissingFunctionPolicy(PS2Runtime::MissingFunctionPolicy::SkipCallDebug);
        // Note: 0x0 is outside the dense table [0x100008, 0x40a160); SkipCallDebug handles targetPc == 0u directly.
        RUNTIME_LOG("[game_overrides] null-pc recovery: configured MissingFunctionPolicy to SkipCallDebug and registered 0x0 stub");
    }

    inline const ps2_game_overrides::Descriptor kPrimalNullPcDescriptor{
        "Primal null-pc stub",
        "SCUS_971.42",
        0x00100008u,
        0xAB6FB13Cu,
        &applyPrimalNullPc
    };

    inline const ps2_game_overrides::AutoRegister kPrimalNullPcRegistrar{
        kPrimalNullPcDescriptor
    };
}

namespace ps2_game_overrides::primal_slotwatch
{
    // PS2_SLOT_WATCH=1: wrap the direct callees of the FUN_002FA048 loop body
    // and log the saved-ra slot (entrySp-0x70+0x60 = 0x1fffde0 and the inner
    // 0x1fffd90) before/after each call to find which one clobbers it.
    inline PS2Runtime::RecompiledFunction g_orig[4] = {nullptr, nullptr, nullptr, nullptr};
    inline uint32_t g_slotA = 0u, g_slotB = 0u;

    inline uint32_t rd(uint8_t *rdram, uint32_t a)
    {
        uint32_t v = 0u;
        (void)primal_sif_rpc::readGuestU32(rdram, a, v);
        return v;
    }

    inline void watch(const char *tag, int idx, uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime, bool pre)
    {
        RUNTIME_LOG("[slotwatch] " << tag << (pre ? " pre " : " post") << " pc=0x" << std::hex << getRegU32(ctx, 29)
                    << " slotA=0x" << rd(rdram, g_slotA) << " slotB=0x" << rd(rdram, g_slotB) << std::dec << std::endl);
        g_orig[idx](rdram, ctx, runtime);
    }

    inline void w0(uint8_t *r, R5900Context *c, PS2Runtime *rt) { watch("f282620", 0, r, c, rt, true); }
    inline void w1(uint8_t *r, R5900Context *c, PS2Runtime *rt) { watch("f286cc8", 1, r, c, rt, true); }
    inline void w2(uint8_t *r, R5900Context *c, PS2Runtime *rt) { watch("f2f8980", 2, r, c, rt, true); }

    inline void applyPrimalSlotWatch(PS2Runtime &runtime)
    {
        const char *e = std::getenv("PS2_SLOT_WATCH");
        if (e == nullptr || e[0] != '1')
            return;
        g_slotA = 0x1FFFDE0u; g_slotB = 0x1FFFD90u;
        struct { uint32_t pc; int idx; } targets[3] = {{0x00282620u, 0}, {0x00286CC8u, 1}, {0x002F8980u, 2}};
        for (auto &tg : targets)
        {
            g_orig[tg.idx] = runtime.lookupFunction(tg.pc);
            if (g_orig[tg.idx])
                runtime.replaceFunction(tg.pc, tg.idx == 0 ? &w0 : tg.idx == 1 ? &w1 : &w2);
        }
        RUNTIME_LOG("[game_overrides] slot-watch installed");
    }

    inline const ps2_game_overrides::Descriptor kPrimalSlotWatchDescriptor{
        "Primal slot watch", "SCUS_971.42", 0x00100008u, 0xAB6FB13Cu, &applyPrimalSlotWatch
    };
    inline const ps2_game_overrides::AutoRegister kPrimalSlotWatchRegistrar{kPrimalSlotWatchDescriptor};
}

namespace ps2_game_overrides::primal_sp_repair
{
    inline PS2Runtime::RecompiledFunction g_orig[14] = {};
    inline void spw0(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t savedSp = getRegU32(ctx, 29);
        const uint32_t savedRa = getRegU32(ctx, 31);
        g_orig[0](rdram, ctx, runtime);
        if (ctx->pc == savedRa)
        {
            primal_sif_rpc::setGuestRegU32(ctx, 29, savedSp);
        }
    }
    inline void spw1(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t savedSp = getRegU32(ctx, 29);
        const uint32_t savedRa = getRegU32(ctx, 31);
        g_orig[1](rdram, ctx, runtime);
        if (ctx->pc == savedRa)
        {
            primal_sif_rpc::setGuestRegU32(ctx, 29, savedSp);
        }
    }
    inline void spw2(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t savedSp = getRegU32(ctx, 29);
        const uint32_t savedRa = getRegU32(ctx, 31);
        g_orig[2](rdram, ctx, runtime);
        if (ctx->pc == savedRa)
        {
            primal_sif_rpc::setGuestRegU32(ctx, 29, savedSp);
        }
    }
    inline void spw3(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t savedSp = getRegU32(ctx, 29);
        const uint32_t savedRa = getRegU32(ctx, 31);
        g_orig[3](rdram, ctx, runtime);
        if (ctx->pc == savedRa)
        {
            primal_sif_rpc::setGuestRegU32(ctx, 29, savedSp);
        }
    }
    inline void spw4(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t savedSp = getRegU32(ctx, 29);
        const uint32_t savedRa = getRegU32(ctx, 31);
        g_orig[4](rdram, ctx, runtime);
        if (ctx->pc == savedRa)
        {
            primal_sif_rpc::setGuestRegU32(ctx, 29, savedSp);
        }
    }
    inline void spw5(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t savedSp = getRegU32(ctx, 29);
        const uint32_t savedRa = getRegU32(ctx, 31);
        g_orig[5](rdram, ctx, runtime);
        if (ctx->pc == savedRa)
        {
            primal_sif_rpc::setGuestRegU32(ctx, 29, savedSp);
        }
    }
    inline void spw6(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t savedSp = getRegU32(ctx, 29);
        const uint32_t savedRa = getRegU32(ctx, 31);
        g_orig[6](rdram, ctx, runtime);
        if (ctx->pc == savedRa)
        {
            primal_sif_rpc::setGuestRegU32(ctx, 29, savedSp);
        }
    }
    inline void spw7(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t savedSp = getRegU32(ctx, 29);
        const uint32_t savedRa = getRegU32(ctx, 31);
        g_orig[7](rdram, ctx, runtime);
        if (ctx->pc == savedRa)
        {
            primal_sif_rpc::setGuestRegU32(ctx, 29, savedSp);
        }
    }
    inline void spw8(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t savedSp = getRegU32(ctx, 29);
        const uint32_t savedRa = getRegU32(ctx, 31);
        g_orig[8](rdram, ctx, runtime);
        if (ctx->pc == savedRa)
        {
            primal_sif_rpc::setGuestRegU32(ctx, 29, savedSp);
        }
    }
    inline void spw9(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t savedSp = getRegU32(ctx, 29);
        const uint32_t savedRa = getRegU32(ctx, 31);
        g_orig[9](rdram, ctx, runtime);
        if (ctx->pc == savedRa)
        {
            primal_sif_rpc::setGuestRegU32(ctx, 29, savedSp);
        }
    }
    inline void spw10(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t savedSp = getRegU32(ctx, 29);
        const uint32_t savedRa = getRegU32(ctx, 31);
        g_orig[10](rdram, ctx, runtime);
        if (ctx->pc == savedRa)
        {
            primal_sif_rpc::setGuestRegU32(ctx, 29, savedSp);
        }
    }
    inline void spw11(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t savedSp = getRegU32(ctx, 29);
        const uint32_t savedRa = getRegU32(ctx, 31);
        g_orig[11](rdram, ctx, runtime);
        if (ctx->pc == savedRa)
        {
            primal_sif_rpc::setGuestRegU32(ctx, 29, savedSp);
        }
    }
    inline void spw12(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t savedSp = getRegU32(ctx, 29);
        const uint32_t savedRa = getRegU32(ctx, 31);
        g_orig[12](rdram, ctx, runtime);
        if (ctx->pc == savedRa)
        {
            primal_sif_rpc::setGuestRegU32(ctx, 29, savedSp);
        }
    }
    inline void spw13(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t savedSp = getRegU32(ctx, 29);
        const uint32_t savedRa = getRegU32(ctx, 31);
        g_orig[13](rdram, ctx, runtime);
        if (ctx->pc == savedRa)
        {
            primal_sif_rpc::setGuestRegU32(ctx, 29, savedSp);
        }
    }
    inline void applyPrimalSpRepair(PS2Runtime &runtime)
    {
        const char *e = std::getenv("PS2_DISABLE_SP_REPAIR");
        if (e != nullptr && e[0] == '1')
            return;
        const uint32_t addrs[14] = {0x1606F8u,0x17E818u,0x1C6840u,0x2F8E60u,0x321BA8u,0x326CB8u,0x354AB8u,0x39F9B0u,0x3AD8A0u,0x1E360Cu,0x3115CCu,0x38DF58u,0x3AC9B0u,0x328850u};
        PS2Runtime::RecompiledFunction fns[14] = {&spw0,&spw1,&spw2,&spw3,&spw4,&spw5,&spw6,&spw7,&spw8,&spw9,&spw10,&spw11,&spw12,&spw13};
        int ok = 0;
        for (int i = 0; i < 14; ++i)
        {
            g_orig[i] = runtime.lookupFunction(addrs[i]);
            if (g_orig[i] && runtime.replaceFunction(addrs[i], fns[i]))
                ++ok;
        }
        RUNTIME_LOG("[game_overrides] sp-repair installed " << ok << "/14");
    }

    inline const ps2_game_overrides::Descriptor kPrimalSpRepairDescriptor{
        "Primal sp-repair", "SCUS_971.42", 0x00100008u, 0xAB6FB13Cu, &applyPrimalSpRepair
    };
    inline const ps2_game_overrides::AutoRegister kPrimalSpRepairRegistrar{kPrimalSpRepairDescriptor};
}

namespace ps2_game_overrides::primal_scene_repair
{
    inline PS2Runtime::RecompiledFunction g_origSceneLoop = nullptr;
    inline PS2Runtime::RecompiledFunction g_orig2f9e80 = nullptr;
    inline PS2Runtime::RecompiledFunction g_orig2f9ea4 = nullptr;
    inline PS2Runtime::RecompiledFunction g_orig2f9ed8 = nullptr;
    inline PS2Runtime::RecompiledFunction g_orig30a1b0 = nullptr;
    inline PS2Runtime::RecompiledFunction g_orig30a1e8 = nullptr;
    inline PS2Runtime::RecompiledFunction g_orig30a1fc = nullptr;
    inline PS2Runtime::RecompiledFunction g_orig30a24c = nullptr;

    inline void wrap30a1b0(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        if (g_orig30a1b0)
            g_orig30a1b0(rdram, ctx, runtime);
        if (ctx->pc == 0x0030A1E8u && g_orig30a1e8)
            g_orig30a1e8(rdram, ctx, runtime);
        if (ctx->pc == 0x0030A1FCu && g_orig30a1fc)
            g_orig30a1fc(rdram, ctx, runtime);
        if (ctx->pc == 0x0030A24Cu && g_orig30a24c)
            g_orig30a24c(rdram, ctx, runtime);
    }

    inline void wrap2f9e80(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        if (g_orig2f9e80)
            g_orig2f9e80(rdram, ctx, runtime);
        if (ctx->pc == 0x002F9EA4u && g_orig2f9ea4)
            g_orig2f9ea4(rdram, ctx, runtime);
        if (ctx->pc == 0x002F9ED8u && g_orig2f9ed8)
            g_orig2f9ed8(rdram, ctx, runtime);
    }

    struct FrameSnapshot
    {
        uint32_t sp = 0u;
        uint32_t ra = 0u;
        __m128i s[8] = {};
        bool active = false;
    };

    inline FrameSnapshot g_sceneLoopFrame;

    inline void sceneLoopWrap(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        if (ctx->pc == 0x002F7360u)
        {
            g_sceneLoopFrame.sp = getRegU32(ctx, 29);
            g_sceneLoopFrame.ra = getRegU32(ctx, 31);
            for (int i = 0; i < 8; ++i)
                g_sceneLoopFrame.s[i] = ctx->r[16 + i];
            g_sceneLoopFrame.active = true;
            RUNTIME_LOG("[game_overrides] sceneLoopWrap entry sp=0x" << std::hex
                        << g_sceneLoopFrame.sp << " ra=0x" << g_sceneLoopFrame.ra << std::dec << std::endl);
        }

        g_origSceneLoop(rdram, ctx, runtime);

        const uint32_t f1f80 = *(const uint32_t *)(rdram + (0x004F1F80u & 0x1FFFFFFu));
        const uint32_t curSp = getRegU32(ctx, 29);
        if (g_sceneLoopFrame.active && curSp >= g_sceneLoopFrame.sp &&
            (ctx->pc < 0x002F7360u || ctx->pc > 0x002F741Fu))
        {
            RUNTIME_LOG("[game_overrides] sceneLoopWrap genuine exit: f1f80=" << f1f80
                        << " pc=0x" << std::hex << ctx->pc << " (restoring ra=0x"
                        << g_sceneLoopFrame.ra << ") sp=0x" << curSp
                        << " (restoring sp=0x" << g_sceneLoopFrame.sp << ")" << std::dec << std::endl);
            ctx->pc = g_sceneLoopFrame.ra;
            primal_sif_rpc::setGuestRegU32(ctx, 31, g_sceneLoopFrame.ra);
            primal_sif_rpc::setGuestRegU32(ctx, 29, g_sceneLoopFrame.sp);
            for (int i = 0; i < 8; ++i)
                ctx->r[16 + i] = g_sceneLoopFrame.s[i];
            g_sceneLoopFrame.active = false;
        }
    }

    inline void applyPrimalSceneRepair(PS2Runtime &runtime)
    {
        const char *e = std::getenv("PS2_DISABLE_SCENE_REPAIR");
        if (e != nullptr && e[0] == '1')
            return;
        g_origSceneLoop = runtime.lookupFunction(0x002F7360u);
        g_orig2f9e80 = runtime.lookupFunction(0x002F9E80u);
        g_orig2f9ea4 = runtime.lookupFunction(0x002F9EA4u);
        g_orig2f9ed8 = runtime.lookupFunction(0x002F9ED8u);
        const bool ok = g_origSceneLoop && runtime.replaceFunction(0x002F7360u, &sceneLoopWrap);
        const bool ok2 = g_orig2f9e80 && g_orig2f9ea4 && g_orig2f9ed8 &&
                         runtime.replaceFunction(0x002F9E80u, &wrap2f9e80);
        g_orig30a1b0 = runtime.lookupFunction(0x0030A1B0u);
        g_orig30a1e8 = runtime.lookupFunction(0x0030A1E8u);
        g_orig30a1fc = runtime.lookupFunction(0x0030A1FCu);
        g_orig30a24c = runtime.lookupFunction(0x0030A24Cu);
        const bool ok3 = g_orig30a1b0 && g_orig30a1e8 && g_orig30a1fc && g_orig30a24c &&
                         runtime.replaceFunction(0x0030A1B0u, &wrap30a1b0);
        RUNTIME_LOG("[game_overrides] scene-repair (0x2F7360) installed: "
                    << (ok ? "YES" : "NO") << " (2f9e80 chain: " << (ok2 ? "YES" : "NO")
                    << ", 30a1b0 chain: " << (ok3 ? "YES" : "NO") << ")");
    }

    inline const ps2_game_overrides::Descriptor kPrimalSceneRepairDescriptor{
        "Primal scene-repair (0x2F7360)",
        "SCUS_971.42",
        0x00100008u,
        0xAB6FB13Cu,
        &applyPrimalSceneRepair
    };

    inline const ps2_game_overrides::AutoRegister kPrimalSceneRepairRegistrar{
        kPrimalSceneRepairDescriptor
    };
}

namespace ps2_game_overrides::primal_sync_repair
{
    inline PS2Runtime::RecompiledFunction g_origSyncEntry = nullptr;
    inline PS2Runtime::RecompiledFunction g_origSyncResume = nullptr;

    inline uint32_t g_savedSyncSp = 0u;
    inline uint32_t g_savedSyncRa = 0u;

    inline void syncEntryWrap(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        uint32_t sp = getRegU32(ctx, 29);
        uint32_t ra = getRegU32(ctx, 31);

        if (sp != 0x1FFFED0u && sp >= 0x1FF0000u && sp <= 0x2000000u)
        {
            RUNTIME_LOG("[sync-repair] entry repair sp: 0x" << std::hex << sp
                        << " -> 0x1FFFED0 (ra=0x" << ra << ")" << std::dec << std::endl);
            sp = 0x1FFFED0u;
            primal_sif_rpc::setGuestRegU32(ctx, 29, sp);
        }

        if (ra != 0x002F73D0u && ra != 0x002F73F8u)
        {
            RUNTIME_LOG("[sync-repair] entry repair ra: 0x" << std::hex << ra
                        << " -> 0x2F73F8" << std::dec << std::endl);
            ra = 0x002F73F8u;
            primal_sif_rpc::setGuestRegU32(ctx, 31, ra);
        }

        g_savedSyncSp = sp;
        g_savedSyncRa = ra;

        g_origSyncEntry(rdram, ctx, runtime);
    }

    inline void syncResumeWrap(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t inSp = getRegU32(ctx, 29);
        if (inSp != 0x1FFFEC0u && inSp >= 0x1FF0000u && inSp <= 0x2000000u)
        {
            RUNTIME_LOG("[sync-repair] resume pre-repair sp: 0x" << std::hex << inSp
                        << " -> 0x1FFFEC0" << std::dec << std::endl);
            primal_sif_rpc::setGuestRegU32(ctx, 29, 0x1FFFEC0u);
        }

        if (g_savedSyncRa != 0u)
        {
            (void)primal_sif_rpc::writeGuestU32(rdram, 0x1FFFEC0u, g_savedSyncRa);
        }

        g_origSyncResume(rdram, ctx, runtime);

        if (ctx->pc < 0x00100000u || ctx->pc >= 0x004EE000u || ctx->pc == 0x01FFFAC0u)
        {
            const uint32_t targetRa = (g_savedSyncRa != 0u) ? g_savedSyncRa : 0x002F73F8u;
            RUNTIME_LOG("[sync-repair] resume post-repair invalid PC 0x" << std::hex << ctx->pc
                        << " -> targetRa 0x" << targetRa << std::dec << std::endl);
            ctx->pc = targetRa;
            primal_sif_rpc::setGuestRegU32(ctx, 31, targetRa);
        }

        const uint32_t outSp = getRegU32(ctx, 29);
        if (outSp != 0x1FFFED0u && outSp >= 0x1FF0000u && outSp <= 0x2000000u)
        {
            primal_sif_rpc::setGuestRegU32(ctx, 29, 0x1FFFED0u);
        }
    }

    inline void applyPrimalSyncRepair(PS2Runtime &runtime)
    {
        const char *e = std::getenv("PS2_DISABLE_SYNC_REPAIR");
        if (e != nullptr && e[0] == '1')
            return;

        g_origSyncEntry = runtime.lookupFunction(0x002F7330u);
        g_origSyncResume = runtime.lookupFunction(0x002F7354u);

        bool ok = true;
        if (g_origSyncEntry)
            ok = runtime.replaceFunction(0x002F7330u, &syncEntryWrap) && ok;
        if (g_origSyncResume)
            ok = runtime.replaceFunction(0x002F7354u, &syncResumeWrap) && ok;

        RUNTIME_LOG("[game_overrides] sync-repair (0x2F7330/0x2F7354) installed: "
                    << (ok ? "YES" : "NO"));
    }

    inline const ps2_game_overrides::Descriptor kPrimalSyncRepairDescriptor{
        "Primal sync-repair (0x2F7330/0x2F7354)",
        "SCUS_971.42",
        0x00100008u,
        0xAB6FB13Cu,
        &applyPrimalSyncRepair
    };

    inline const ps2_game_overrides::AutoRegister kPrimalSyncRepairRegistrar{
        kPrimalSyncRepairDescriptor
    };
}

namespace ps2_game_overrides::primal_abb40_repair
{
    inline PS2Runtime::RecompiledFunction g_origAbb50 = nullptr;
    inline PS2Runtime::RecompiledFunction g_origAc260 = nullptr;

    inline void abb40Wrap(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        // 0x3abb40: daddu $t1, $a0, $zero
        SET_GPR_U64(ctx, 9, (uint64_t)GPR_U64(ctx, 4) + (uint64_t)GPR_U64(ctx, 0));
        // 0x3abb44: lw $v1, 0x18($t1)
        const uint32_t t1 = GPR_U32(ctx, 9);
        const uint32_t v1 = *(const uint32_t *)(rdram + ((t1 + 24u) & 0x1FFFFFFu));
        SET_GPR_S32(ctx, 3, static_cast<int32_t>(v1));
        // 0x3abb48: addiu $a0, $zero, 0x3
        SET_GPR_S32(ctx, 4, 3);

        const uint32_t curSp = getRegU32(ctx, 29);

        // Branch condition: bne $v1, $a0, 0x3abb98
        // The delay slot of bne is: 0x3abb50: addiu $sp, $sp, -16
        if (v1 != 3u)
        {
            // Branch taken to 0x3abb98:
            // Must execute delay slot (sp = sp - 16)
            primal_sif_rpc::setGuestRegU32(ctx, 29, curSp - 16u);
            ctx->pc = 0x003ABB98u;
        }
        else
        {
            // Branch not taken: fall through to 0x3abb50.
            // In FUN_003abb50, entry 0x3abb50 executes: addiu $sp, $sp, -16.
            ctx->pc = 0x003ABB50u;
        }

        if (g_origAbb50)
        {
            g_origAbb50(rdram, ctx, runtime);
        }
    }

    inline void ac260Wrap(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t entrySp = getRegU32(ctx, 29);
        const uint32_t entryRa = getRegU32(ctx, 31);
        const __m128i entryS0 = GPR_VEC(ctx, 16);

        if (g_origAc260)
        {
            g_origAc260(rdram, ctx, runtime);
        }

        if (ctx->pc < 0x00100000u || ctx->pc >= 0x004EE000u || ctx->pc == 0x01FFFAC0u)
        {
            RUNTIME_LOG("[ac260-repair] restored invalid pc 0x" << std::hex << ctx->pc
                        << " -> entryRa 0x" << entryRa << std::dec << std::endl);
            ctx->pc = entryRa;
            primal_sif_rpc::setGuestRegU32(ctx, 31, entryRa);
            SET_GPR_VEC(ctx, 16, entryS0);
        }
        const uint32_t curSp = getRegU32(ctx, 29);
        if (curSp != entrySp && curSp >= 0x1FF0000u && curSp <= 0x2000000u)
        {
            RUNTIME_LOG("[ac260-repair] restored sp 0x" << std::hex << curSp
                        << " -> entrySp 0x" << entrySp << std::dec << std::endl);
            primal_sif_rpc::setGuestRegU32(ctx, 29, entrySp);
            SET_GPR_VEC(ctx, 16, entryS0);
        }
    }

    inline void applyPrimalAbb40Repair(PS2Runtime &runtime)
    {
        const char *e = std::getenv("PS2_DISABLE_ABB40_REPAIR");
        if (e != nullptr && e[0] == '1')
            return;

        g_origAbb50 = runtime.lookupFunction(0x003ABB50u);
        g_origAc260 = runtime.lookupFunction(0x003AC260u);

        bool ok = true;
        if (g_origAbb50)
            ok = runtime.replaceFunction(0x003ABB40u, &abb40Wrap) && ok;
        if (g_origAc260)
            ok = runtime.replaceFunction(0x003AC260u, &ac260Wrap) && ok;

        RUNTIME_LOG("[game_overrides] abb40/ac260 repair installed: " << (ok ? "YES" : "NO"));
    }

    inline const ps2_game_overrides::Descriptor kPrimalAbb40RepairDescriptor{
        "Primal 0x3ABB40 / 0x3AC260 delay-slot repair",
        "SCUS_971.42",
        0x00100008u,
        0xAB6FB13Cu,
        &applyPrimalAbb40Repair
    };

    inline const ps2_game_overrides::AutoRegister kPrimalAbb40RepairRegistrar{
        kPrimalAbb40RepairDescriptor
    };
}

namespace ps2_game_overrides::primal_director_repair
{
    inline PS2Runtime::RecompiledFunction g_origDirector = nullptr;
    inline PS2Runtime::RecompiledFunction g_orig32eae8 = nullptr;
    inline PS2Runtime::RecompiledFunction g_orig28acb8 = nullptr;
    inline uint32_t s_directorEntrySp = 0;
    inline uint32_t s_directorEntryRa = 0;
    inline __m128i s_directorSavedS[8]{};

    inline void func_2385c8(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t entrySp = getRegU32(ctx, 29);
        const uint32_t entryRa = getRegU32(ctx, 31);
        const uint32_t a0Val = getRegU32(ctx, 4);

        static int s_cnt238 = 0;
        if (s_cnt238 < 3)
        {
            ++s_cnt238;
            RUNTIME_LOG("[override-2385c8] ENTRY sp=0x" << std::hex << entrySp
                        << " ra=0x" << entryRa << " a0=0x" << a0Val << std::dec << std::endl);
        }

        uint32_t v0Val = 0, v1Val = 0, innerA0 = 0;
        if (primal_sif_rpc::readGuestU32(rdram, a0Val + 20, v0Val) &&
            primal_sif_rpc::readGuestU32(rdram, a0Val + 16, v1Val) &&
            primal_sif_rpc::readGuestU32(rdram, v0Val, innerA0))
        {
            const uint32_t strAddr = v1Val + innerA0;
            primal_sif_rpc::setGuestRegU32(ctx, 4, strAddr);
            primal_sif_rpc::setGuestRegU32(ctx, 2, v0Val);
            primal_sif_rpc::setGuestRegU32(ctx, 3, v1Val);
            if (s_cnt238 <= 3)
            {
                uint8_t *sp = nullptr; uint32_t av = 0;
                std::string argStr;
                if (primal_sif_rpc::mapGuestRange(rdram, strAddr, sp, av))
                    argStr.assign(reinterpret_cast<const char *>(sp), strnlen(reinterpret_cast<const char *>(sp), std::min<uint32_t>(av, 96u)));
                RUNTIME_LOG("[override-2385c8] str=0x" << std::hex << strAddr << " \"" << argStr << "\"" << std::dec << std::endl);
            }
        }

        primal_sif_rpc::setGuestRegU32(ctx, 31, 0x2385E4u);
        runtime->dispatchGuestBranch(rdram, ctx, 0x002A0400u, 0x2385DCu, 0x2385E4u,
                                     PS2Runtime::GuestBranchKind::DirectCall, "JAL");

        ctx->pc = entryRa;
        primal_sif_rpc::setGuestRegU32(ctx, 31, entryRa);
        primal_sif_rpc::setGuestRegU32(ctx, 29, entrySp);

        if (s_cnt238 <= 3)
        {
            RUNTIME_LOG("[override-2385c8] EXIT pc=0x" << std::hex << ctx->pc
                        << " sp=0x" << entrySp << " ra=0x" << entryRa << std::dec << std::endl);
        }
    }

    inline void wrap_28acb8(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t entryPc = ctx->pc;
        static thread_local uint32_t s_iterCount = 0;

        if (entryPc == 0x0028ACB8u)
        {
            s_iterCount = 0;
        }
        else
        {
            s_iterCount++;
            if (s_iterCount > 64)
            {
                const uint32_t a0Val = getRegU32(ctx, 4);
                const uint32_t a1Val = getRegU32(ctx, 5);
                uint32_t a2Val = getRegU32(ctx, 6);
                if (a2Val == 0) a2Val = a0Val;
                primal_sif_rpc::setGuestRegU32(ctx, 2, a2Val);
                const uint32_t ra = getRegU32(ctx, 31);
                ctx->pc = ra;
                RUNTIME_LOG("[acb8-guard] BREAK infinite loop: a0=0x" << std::hex << a0Val
                            << " a1=0x" << a1Val << " -> returning v0=0x" << a2Val
                            << " to ra=0x" << ra << std::dec << std::endl);
                s_iterCount = 0;
                return;
            }
        }

        if (g_orig28acb8)
        {
            g_orig28acb8(rdram, ctx, runtime);
        }
    }

    inline bool g_seen103d40 = false;

    inline void eae8Wrap(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t entrySp = getRegU32(ctx, 29);
        const uint32_t entryRa = getRegU32(ctx, 31);
        __m128i savedS[8];
        for (int i = 0; i < 8; ++i)
            savedS[i] = GPR_VEC(ctx, 16 + i);
        const __m128i savedFp = GPR_VEC(ctx, 30);

        static const bool s_verboseLogs = [] {
            const char *e = std::getenv("PS2_PRIMAL_VERBOSE_LOGS");
            return e != nullptr && e[0] == '1';
        }();
        static int s_eae8EntryLogs = 0;
        if (s_verboseLogs || s_eae8EntryLogs < 20)
        {
            ++s_eae8EntryLogs;
            RUNTIME_LOG("[eae8-repair] ENTRY sp=0x" << std::hex << entrySp
                        << " ra=0x" << entryRa << std::dec << std::endl);
        }

        if (g_orig32eae8)
        {
            g_orig32eae8(rdram, ctx, runtime);
        }

        const uint32_t exitPc = ctx->pc;
        const uint32_t exitSp = getRegU32(ctx, 29);
        const uint32_t exitRa = getRegU32(ctx, 31);
        const uint32_t exitV0 = getRegU32(ctx, 2);

        static int s_eae8LogCount = 0;
        if (s_eae8LogCount < 20 || s_verboseLogs)
        {
            ++s_eae8LogCount;
            RUNTIME_LOG("[eae8-repair] EXIT pc=0x" << std::hex << exitPc
                        << " sp=0x" << exitSp << " ra=0x" << exitRa
                        << " v0=0x" << exitV0 << std::dec << std::endl);
        }

        // Calculate expected frame pointer and return addresses for FUN_002F5FD8
        const uint32_t directorEntrySp = (s_directorEntrySp != 0) ? s_directorEntrySp : 0x1FFFDE0u;
        const uint32_t directorLocalSp = directorEntrySp - 0x90u; // 0x1FFFD50u
        const uint32_t directorRa = (s_directorEntryRa != 0) ? s_directorEntryRa : 0x00309D8Cu;
        const uint32_t taskRa = 0x002FA280u;

        // Ensure RDRAM stack frame at directorLocalSp is intact:
        // offset 0x80 (128): $ra = directorRa (0x309D8C)
        // offset 0x10..0x70: $s0..$s6 saved registers
        uint8_t *hostMem = nullptr;
        uint32_t avail = 0;
        if (primal_sif_rpc::mapGuestRange(rdram, directorLocalSp, hostMem, avail) && avail >= 0x90u)
        {
            std::memcpy(hostMem + 128, &directorRa, 4);
            for (int i = 0; i < 7; ++i)
            {
                std::memcpy(hostMem + 16 * (i + 1), &s_directorSavedS[i], sizeof(__m128i));
            }
        }

        // At directorEntrySp (0x1FFFDE0), ensure caller's ra for FUN_00309c30 is taskRa (0x002FA280)
        // Guarded by directorRa == 0x00309D8Cu so callers like 0x1036c8 (which save $s0 at 0x0($sp)) are not clobbered.
        if (directorRa == 0x00309D8Cu && primal_sif_rpc::mapGuestRange(rdram, directorEntrySp, hostMem, avail) && avail >= 16)
        {
            std::memcpy(hostMem, &taskRa, 4);
        }

        // Explicitly set the engine initialized flag *(uint32_t*)0x004886A8 = 1
        if (primal_sif_rpc::mapGuestRange(rdram, 0x004886A8u, hostMem, avail) && avail >= 4)
        {
            *(uint32_t*)hostMem = 1u;
        }

        // Fix FUN_002F5FD8's stack pointer:
        // By restoring $sp to directorLocalSp (0x1FFFD50), the following epilogue in
        // FUN_002F5FD8 (0x2F66DC-0x2F670C) will execute:
        //   sw    $v0, -0x7958($at)  ; *(0x004886A8) = 1 (engine initialized)
        //   lq    $ra, 0x80($sp)     ; loads 0x309D8C from 0x1FFFDD0
        //   lq    $s0-$s6, ...($sp)  ; restores caller s registers
        //   jr    $ra                ; jumps to 0x309D8C!
        //   addiu $sp, $sp, 0x90     ; restores $sp to 0x1FFFDE0
        primal_sif_rpc::setGuestRegU32(ctx, 29, directorLocalSp);

        // Ensure fallthrough PC is 0x2F66DC and $ra is 0x2F66DC
        ctx->pc = 0x2F66DCu;
        primal_sif_rpc::setGuestRegU32(ctx, 31, 0x2F66DCu);

        static int s_eae8Cnt = 0;
        if (s_eae8Cnt < 3)
        {
            ++s_eae8Cnt;
            RUNTIME_LOG("[eae8-repair] RESTORED director frame: sp=0x" << std::hex << directorLocalSp
                        << " ra=0x" << directorRa << " taskRa=0x" << taskRa << std::dec << std::endl);
        }
    }

    inline std::atomic<uint32_t> g_cnt104a00{0}, g_cnt32cd00{0}, g_cnt298200{0};

    inline void directorWrap(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t entrySp = getRegU32(ctx, 29);
        const uint32_t entryRa = getRegU32(ctx, 31);
        s_directorEntrySp = entrySp;
        s_directorEntryRa = entryRa;
        for (int i = 0; i < 8; ++i)
            s_directorSavedS[i] = GPR_VEC(ctx, 16 + i);

        auto readU32 = [&](uint32_t addr) -> uint32_t {
            uint8_t *p = nullptr; uint32_t av = 0;
            return (primal_sif_rpc::mapGuestRange(rdram, addr, p, av) && av >= 4) ? *(uint32_t*)p : 0xDEADu;
        };
        static int s_dirLogCount = 0;
        const int dirIdx = s_dirLogCount++;
        static int s_postDirLogs = 0;
        const bool doLog = (dirIdx < 5 || (dirIdx % 60) == 0 || (g_seen103d40 && s_postDirLogs++ < 5));
        if (doLog)
        {
            RUNTIME_LOG("[director-repair] #" << dirIdx << " ENTRY sp=0x" << std::hex << entrySp
                        << " ra=0x" << entryRa
                        << " callerRa=0x" << readU32(entrySp)
                        << " 48823c=0x" << readU32(0x0048823Cu)
                        << " 4f1ef4=0x" << readU32(0x004F1EF4u)
                        << " 4f1ef8=0x" << readU32(0x004F1EF8u)
                        << " 4f1f78=0x" << readU32(0x004F1F78u)
                        << " 48576c=0x" << readU32(0x0048576Cu)
                        << " 487764=0x" << readU32(0x00487764u)
                        << " 4f71a8=0x" << readU32(0x004F71A8u)
                        << " 4f71ac=0x" << readU32(0x004F71ACu)
                        << " 4f7250=0x" << readU32(0x004F7250u)
                        << " 487724=0x" << readU32(0x00487724u)
                        << " 510b4c=0x" << readU32(0x00510B4Cu)
                        << " 510b60=0x" << readU32(0x00510B60u)
                        << " 4f7080=0x" << readU32(0x004F7080u)
                        << " 485770=0x" << readU32(0x00485770u)
                        << " 485788=0x" << readU32(0x00485788u)
                        << " 488398=0x" << readU32(0x00488398u)
                        << " 4886b8=0x" << readU32(0x004886B8u)
                        << " 4f7124=0x" << readU32(0x004F7124u)
                        << " 4f7114=0x" << readU32(0x004F7114u)
                        << " 4f7108=0x" << readU32(0x004F7108u)
                        << " 4f7118=0x" << readU32(0x004F7118u)
                        << " 488788=0x" << readU32(0x00488788u)
                        << " 4f1ef0=0x" << readU32(0x004F1EF0u)
                        << " gp7d84=0x" << readU32(ADD32(GPR_U32(ctx, 28), 0xFFFF827Cu))
                        << " gp7f8c=0x" << readU32(ADD32(GPR_U32(ctx, 28), 0xFFFF8074u))
                        << " gp5d8c=0x" << readU32(ADD32(GPR_U32(ctx, 28), 0xFFFFA274u))
                        << " 4df3b0=0x" << readU32(0x004DF3B0u)
                        << " 4df410=0x" << readU32(0x004DF410u)
                        << " a0=0x" << getRegU32(ctx, 4)
                        << std::dec
                        << " c104=" << g_cnt104a00.load(std::memory_order_relaxed)
                        << " c32c=" << g_cnt32cd00.load(std::memory_order_relaxed)
                        << " c298=" << g_cnt298200.load(std::memory_order_relaxed));
            if (runtime && dirIdx >= 180)
            {
                const auto &gsRegs = runtime->memory().gs_regs;
                auto &gs = runtime->gs();
                RUNTIME_LOG(" pmode=0x" << std::hex << gsRegs.pmode
                            << " dfb1=0x" << gsRegs.dispfb1
                            << " dfb2=0x" << gsRegs.dispfb2
                            << " fbp0=0x" << gs.getContextFrame(0).fbp
                            << " fbp1=0x" << gs.getContextFrame(1).fbp
                            << " lastDisp=0x" << gs.getLastDisplayBaseBytes()
                            << " 488614=0x" << readU32(0x00488614u)
                            << " 4df88c=0x" << readU32(0x004DF88Cu)
                            << " 488640=0x" << readU32(0x00488640u)
                            << std::dec << " gifHist=" << gs.getDebugHistory().size());
            }
            RUNTIME_LOG(std::endl);
        }

        if (g_origDirector)
        {
            g_origDirector(rdram, ctx, runtime);
        }

        const uint32_t exitPc = ctx->pc;
        const uint32_t exitSp = getRegU32(ctx, 29);
        const uint32_t exitRa = getRegU32(ctx, 31);

        if (doLog)
        {
            RUNTIME_LOG("[director-repair] #" << dirIdx << " EXIT pc=0x" << std::hex << exitPc
                        << " 48823c=0x" << readU32(0x0048823Cu)
                        << " 4f1ef4=0x" << readU32(0x004F1EF4u)
                        << " 4f1ef8=0x" << readU32(0x004F1EF8u)
                        << " 4f1f78=0x" << readU32(0x004F1F78u)
                        << " 48576c=0x" << readU32(0x0048576Cu)
                        << std::dec << std::endl);
        }

        if (exitPc < 0x00100000u || exitPc >= 0x004EE000u || exitPc == 0x00017FC0u)
        {
            RUNTIME_LOG("[director-repair] REPAIR: invalid pc 0x" << std::hex << exitPc
                        << " -> restoring entryRa 0x" << entryRa
                        << " sp 0x" << exitSp << " -> entrySp 0x" << entrySp << std::dec << std::endl);
            ctx->pc = entryRa;
            primal_sif_rpc::setGuestRegU32(ctx, 31, entryRa);
            primal_sif_rpc::setGuestRegU32(ctx, 29, entrySp);
            for (int i = 0; i < 8; ++i)
                SET_GPR_VEC(ctx, 16 + i, s_directorSavedS[i]);
        }
    }

    template <uint32_t EntryAddr, uint32_t EndAddr>
    struct SplitChainBridge
    {
        static inline PS2Runtime::RecompiledFunction s_orig = nullptr;

        static void call(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
        {
            if (s_orig) s_orig(rdram, ctx, runtime);
            for (int iter = 0; iter < 100000; ++iter)
            {
                const uint32_t pc = ctx->pc;
                if (pc <= EntryAddr || pc >= EndAddr)
                    break;
                auto fn = runtime->lookupFunction(pc);
                if (!fn)
                    break;
                if (fn == &call)
                {
                    if (!s_orig) break;
                    s_orig(rdram, ctx, runtime);
                }
                else
                {
                    fn(rdram, ctx, runtime);
                }
            }
        }

        static bool install(PS2Runtime &runtime)
        {
            s_orig = runtime.lookupFunction(EntryAddr);
            return s_orig && runtime.replaceFunction(EntryAddr, &call);
        }
    };

    template <uint32_t EntryAddr, uint32_t EndAddr>
    struct SplitChainResumeBridge
    {
        static constexpr uint32_t kSlots = (EndAddr > EntryAddr) ? ((EndAddr - EntryAddr) / 4u) : 1u;
        static inline PS2Runtime::RecompiledFunction s_origSlots[kSlots] = {};

        static void call(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
        {
            if (ctx->pc < EntryAddr || ctx->pc >= EndAddr)
            {
                ctx->pc = EntryAddr;
            }
            for (int iter = 0; iter < 100000; ++iter)
            {
                const uint32_t pc = ctx->pc;
                if (pc < EntryAddr || pc >= EndAddr || ((pc - EntryAddr) & 3u) != 0u)
                    break;
                auto orig = s_origSlots[(pc - EntryAddr) >> 2];
                if (!orig)
                    break;
                orig(rdram, ctx, runtime);
                if (ctx->pc == pc || (runtime && runtime->eeCheckpointDue(0u)))
                    break;
            }
        }

        static bool install(PS2Runtime &runtime)
        {
            bool any = false;
            for (uint32_t pc = EntryAddr; pc < EndAddr; pc += 4u)
            {
                if (!runtime.hasFunction(pc))
                    continue;
                auto fn = runtime.lookupFunction(pc);
                if (fn && fn != &call)
                {
                    s_origSlots[(pc - EntryAddr) >> 2] = fn;
                    runtime.replaceFunction(pc, &call);
                    any = true;
                }
            }
            return any;
        }
    };

    inline PS2Runtime::RecompiledFunction g_orig11f498 = nullptr;
    inline void wrap11f498(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        auto rd32 = [&](uint32_t a) -> uint32_t {
            uint8_t *p = nullptr; uint32_t av = 0;
            return (primal_sif_rpc::mapGuestRange(rdram, a, p, av) && av >= 4) ? *(uint32_t*)p : 0xDEADu;
        };
        const uint32_t before = rd32(0x00435960u);
        if (g_orig11f498) g_orig11f498(rdram, ctx, runtime);
        const uint32_t after = rd32(0x00435960u);
        if (before != 0x0011D420u || after != 0x0011D420u)
        {
            static int s_c = 0;
            if (s_c < 5)
            {
                ++s_c;
                RUNTIME_LOG("[435960-watch] 11f498 before=0x" << std::hex << before << " after=0x" << after << std::dec << std::endl);
            }
        }
    }

    inline PS2Runtime::RecompiledFunction g_orig3fbfa0 = nullptr;
    inline void wrap3fbfa0(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t size = getRegU32(ctx, 4);
        if (runtime && runtime->guestHeapLimit() < 0x01FE0000u)
        {
            static bool s_expanded = false;
            if (!s_expanded)
            {
                s_expanded = true;
                runtime->configureGuestHeap(runtime->guestHeapBase(), 0x01FE0000u);
                std::fprintf(stderr, "[3fbfa0-heap] expanded guestHeapLimit to 0x%x (base=0x%x)\n",
                             runtime->guestHeapLimit(), runtime->guestHeapBase());
                std::fflush(stderr);
            }
        }
        if (g_orig3fbfa0) g_orig3fbfa0(rdram, ctx, runtime);
        uint32_t ret = getRegU32(ctx, 2);
        if (ret == 0u && size == 0x01AC1AA8u)
        {
            ret = 0x00512000u;
            primal_sif_rpc::setGuestRegU32(ctx, 2, ret);
            std::fprintf(stderr, "[3fbfa0-malloc] fallback size=0x%x -> 0x%x\n", size, ret);
            std::fflush(stderr);
        }
        else if (size >= 0x00100000u)
        {
            std::fprintf(stderr, "[3fbfa0-malloc] size=0x%x -> 0x%x\n", size, ret);
            std::fflush(stderr);
        }
    }

    inline PS2Runtime::RecompiledFunction g_orig28ad80 = nullptr;
    inline void wrap28ad80(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        static int s_c = 0;
        if (s_c < 15)
        {
            ++s_c;
            std::fprintf(stderr, "[28ad80-watch] ra=0x%x pool=0x%x vtbl=0x%x start=0x%x size=0x%x\n",
                         getRegU32(ctx, 31), getRegU32(ctx, 4), getRegU32(ctx, 5), getRegU32(ctx, 6), getRegU32(ctx, 7));
            std::fflush(stderr);
        }
        if (g_orig28ad80) g_orig28ad80(rdram, ctx, runtime);
    }

    inline void wrap28ae20(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        static int s_c = 0;
        if (s_c < 15)
        {
            ++s_c;
            std::fprintf(stderr, "[28ae20-watch] ra=0x%x pool=0x%x start=0x%x size=0x%x\n",
                         getRegU32(ctx, 31), getRegU32(ctx, 4), getRegU32(ctx, 5), getRegU32(ctx, 6));
            std::fflush(stderr);
        }
        SplitChainBridge<0x0028AE20u, 0x0028AFE0u>::call(rdram, ctx, runtime);
    }

    inline PS2Runtime::RecompiledFunction g_orig28b888 = nullptr;
    inline void wrap28b888(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t a0 = getRegU32(ctx, 4);
        const uint32_t a1 = getRegU32(ctx, 5);
        const uint32_t a2 = getRegU32(ctx, 6);
        const uint32_t a3 = getRegU32(ctx, 7);
        auto rd32 = [&](uint32_t a) -> uint32_t {
            uint8_t *p = nullptr; uint32_t av = 0;
            return (primal_sif_rpc::mapGuestRange(rdram, a, p, av) && av >= 4) ? *(uint32_t*)p : 0xDEADu;
        };
        const uint32_t a3_4 = rd32(a3 + 4u);
        if ((a1 >= 0x00400000u && a1 < 0x00490000u) || (a3 >= 0x00400000u && a3 < 0x00490000u) || (a3_4 >= 0x00400000u && a3_4 < 0x00490000u))
        {
            static int s_c = 0;
            if (s_c < 20)
            {
                ++s_c;
                std::fprintf(stderr, "[28b888-watch] ra=0x%x sp=0x%x a0=0x%x a1=0x%x a2=0x%x a3=0x%x a3[4]=0x%x\n",
                             getRegU32(ctx, 31), getRegU32(ctx, 29), a0, a1, a2, a3, a3_4);
                std::fflush(stderr);
            }
        }
        if (g_orig28b888) g_orig28b888(rdram, ctx, runtime);
    }

    inline PS2Runtime::RecompiledFunction g_orig28a400 = nullptr;
    inline void wrap28a400(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t sp = getRegU32(ctx, 29);
        static uint32_t s_minSp = 0xFFFFFFFFu;
        if (sp < 0x01000000u && sp + 0x1000u <= s_minSp)
        {
            s_minSp = sp;
            RUNTIME_LOG("[28a400-watch] NEW MIN sp=0x" << std::hex << sp
                        << " ra=0x" << getRegU32(ctx, 31)
                        << " a0=0x" << getRegU32(ctx, 4)
                        << " a1=0x" << getRegU32(ctx, 5) << std::dec << std::endl);
        }
        const uint32_t a0 = getRegU32(ctx, 4);
        const uint32_t a1 = getRegU32(ctx, 5);
        const uint32_t a2 = getRegU32(ctx, 6);
        const uint32_t a3 = getRegU32(ctx, 7);
        const uint32_t callerRa = getRegU32(ctx, 31);
        if (g_orig28a400) g_orig28a400(rdram, ctx, runtime);
        const uint32_t v0 = getRegU32(ctx, 2);
        static const bool s_verbose28a400 = []() {
            const char *e = std::getenv("PS2_PRIMAL_VERBOSE_LOGS");
            return e != nullptr && e[0] == '1';
        }();
        if (s_verbose28a400 && v0 != 0u && a0 >= 0x10000u)
        {
            static uint32_t s_bigCnt = 0u;
            const uint32_t bc = s_bigCnt++;
            if (bc < 40u)
            {
                RUNTIME_LOG("[28a400-big] #" << std::dec << bc
                            << " ra=0x" << std::hex << callerRa
                            << " size=0x" << a0
                            << " ret=0x" << v0 << std::dec << std::endl);
            }
        }
        if (v0 == 0u)
        {
            static uint32_t s_nullAlloc = 0u;
            const uint32_t c = s_nullAlloc++;
            if (c < 15u)
            {
                RUNTIME_LOG("[28a400-null] #" << std::dec << c
                            << " ra=0x" << std::hex << callerRa
                            << " size(a0)=0x" << a0
                            << " raw(a1)=0x" << a1
                            << " align1(a2)=0x" << a2
                            << " align2(a3)=0x" << a3 << std::dec << std::endl);
            }
            if (s_verbose28a400 && c == 0u)
            {
                auto rd32 = [&](uint32_t addr) -> uint32_t {
                    uint8_t *p = nullptr; uint32_t av = 0;
                    return (primal_sif_rpc::mapGuestRange(rdram, addr, p, av) && av >= 4) ? *(uint32_t*)p : 0u;
                };
                auto dumpPool = [&](const char *label, uint32_t poolAddr) {
                    if (poolAddr < 0x00100000u || poolAddr >= 0x02000000u) return;
                    const uint32_t bktBase = rd32(poolAddr + 0x08u);
                    const uint32_t head    = rd32(poolAddr + 0x0Cu);
                    const uint32_t thresh  = rd32(poolAddr + 0x20u);
                    const uint32_t subP    = rd32(poolAddr + 0x24u);
                    const uint32_t al1     = rd32(poolAddr + 0x28u);
                    const uint32_t al2     = rd32(poolAddr + 0x2Cu);
                    const uint32_t enSub   = rd32(poolAddr + 0x58u);
                    const uint32_t frcSub  = rd32(poolAddr + 0x5Cu);
                    uint64_t freeBytes = 0, usedBytes = 0;
                    uint32_t freeCount = 0, usedCount = 0, totalBlocks = 0;
                    uint32_t lastAddr = 0, lastNext = 0;
                    int32_t lastSize = 0;
                    struct FreeRec { uint32_t size; uint32_t addr; };
                    FreeRec top5[5] = {};
                    uint32_t cur = head;
                    while (cur >= 0x00100000u && cur < 0x02000000u && totalBlocks < 65536u)
                    {
                        ++totalBlocks;
                        const int32_t rawSz = static_cast<int32_t>(rd32(cur + 16u));
                        const int32_t sz = (rawSz > 0) ? rawSz : -static_cast<int32_t>(static_cast<uint32_t>(rawSz) & 0x07FFFFFFu);
                        const uint32_t nxt = rd32(cur + 4u);
                        lastAddr = cur; lastSize = sz; lastNext = nxt;
                        if (sz > 0)
                        {
                            const uint32_t usz = static_cast<uint32_t>(sz);
                            freeBytes += usz;
                            ++freeCount;
                            for (int k = 0; k < 5; ++k)
                            {
                                if (usz > top5[k].size)
                                {
                                    for (int m = 4; m > k; --m) top5[m] = top5[m - 1];
                                    top5[k] = {usz, cur};
                                    break;
                                }
                            }
                        }
                        else
                        {
                            usedBytes += static_cast<uint32_t>(-sz);
                            ++usedCount;
                        }
                        if (nxt == 0u || nxt == cur) break;
                        cur = nxt;
                    }
                    RUNTIME_LOG("[heap-walk] " << label << " pool=0x" << std::hex << poolAddr
                                << " +58(enSub)=" << enSub << " +5c(frcSub)=" << frcSub
                                << " +20(thresh)=0x" << thresh << " +24(sub)=0x" << subP
                                << " +28(al1)=0x" << al1 << " +2c(al2)=0x" << al2
                                << " head=0x" << head << " bktBase=0x" << bktBase << std::dec << std::endl);
                    RUNTIME_LOG("[heap-walk] " << label
                                << " freeBytes=0x" << std::hex << freeBytes << " (" << std::dec << freeCount << ")"
                                << " usedBytes=0x" << std::hex << usedBytes << " (" << std::dec << usedCount << ")"
                                << " total=" << totalBlocks
                                << " last=0x" << std::hex << lastAddr
                                << " lastSz=" << std::dec << lastSize
                                << " lastNext=0x" << std::hex << lastNext << std::dec << std::endl);
                    RUNTIME_LOG("[heap-walk] " << label << " top5Free:"
                                << " [0]=0x" << std::hex << top5[0].size << "@0x" << top5[0].addr
                                << " [1]=0x" << top5[1].size << "@0x" << top5[1].addr
                                << " [2]=0x" << top5[2].size << "@0x" << top5[2].addr
                                << " [3]=0x" << top5[3].size << "@0x" << top5[3].addr
                                << " [4]=0x" << top5[4].size << "@0x" << top5[4].addr << std::dec << std::endl);
                    if (bktBase >= 0x00100000u && bktBase < 0x02000000u)
                    {
                        std::ostringstream oss;
                        oss << "[heap-walk] " << label << " buckets:";
                        for (uint32_t bi = 0; bi < 12u; ++bi)
                        {
                            oss << " [" << bi << "]=0x" << std::hex << rd32(bktBase + (bi << 5) + 8u) << std::dec;
                        }
                        RUNTIME_LOG(oss.str() << std::endl);
                    }
                };
                dumpPool("main", 0x004DF3B0u);
                const uint32_t subPool = rd32(0x004DF3B0u + 0x24u);
                if (subPool != 0u) dumpPool("sub", subPool);
            }
        }
    }

    inline PS2Runtime::RecompiledFunction g_orig2f6918 = nullptr;
    inline void wrap2f6918(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        auto rd32 = [&](uint32_t a) -> uint32_t {
            uint8_t *p = nullptr; uint32_t av = 0;
            return (primal_sif_rpc::mapGuestRange(rdram, a, p, av) && av >= 4) ? *(uint32_t*)p : 0xDEADu;
        };
        const uint32_t before = rd32(0x00435960u);
        if (before != 0x0011D420u)
        {
            static int s_b = 0;
            if (s_b < 5)
            {
                ++s_b;
                RUNTIME_LOG("[435960-watch] 2f6918 ENTER before=0x" << std::hex << before << std::dec << std::endl);
            }
        }
        if (g_orig2f6918) g_orig2f6918(rdram, ctx, runtime);
        const uint32_t after = rd32(0x00435960u);
        if (before != 0x0011D420u || after != 0x0011D420u)
        {
            static int s_c = 0;
            if (s_c < 5)
            {
                ++s_c;
                RUNTIME_LOG("[435960-watch] 2f6918 before=0x" << std::hex << before << " after=0x" << after << std::dec << std::endl);
            }
        }
    }

    inline void (*g_orig32cd00b)(uint8_t *, R5900Context *, PS2Runtime *) = nullptr;
    inline void (*g_orig298200)(uint8_t *, R5900Context *, PS2Runtime *) = nullptr;

    inline void (*g_orig3170d0)(uint8_t *, R5900Context *, PS2Runtime *) = nullptr;
    inline void (*g_orig311708)(uint8_t *, R5900Context *, PS2Runtime *) = nullptr;

    inline void stub3118a8(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        SET_GPR_S32(ctx, 3, static_cast<int32_t>(READ32(ADD32(GPR_U32(ctx, 6), 8))));
        SET_GPR_S32(ctx, 2, static_cast<int32_t>(SLL32(GPR_U32(ctx, 8), 4)));
        SET_GPR_S32(ctx, 4, static_cast<int32_t>(ADD32(GPR_U32(ctx, 2), GPR_U32(ctx, 9))));
        SET_GPR_U64(ctx, 6, static_cast<uint64_t>(GPR_U64(ctx, 2)) + static_cast<uint64_t>(GPR_U64(ctx, 0)));
        SET_GPR_S32(ctx, 5, static_cast<int32_t>(ADD32(GPR_U32(ctx, 3), GPR_U32(ctx, 7))));
        SET_GPR_S32(ctx, 3, static_cast<int32_t>(READ32(ADD32(GPR_U32(ctx, 5), 4294967292u))));
        SET_GPR_S32(ctx, 2, 2);
        ctx->vu0_vf[2] = _mm_castsi128_ps(READ128(ADD32(GPR_U32(ctx, 4), 16)));
        if (GPR_U64(ctx, 3) != GPR_U64(ctx, 2))
        {
            ctx->pc = 0x003118ECu;
            return;
        }
        uint32_t bits = READ32(ADD32(GPR_U32(ctx, 5), 0));
        float f;
        std::memcpy(&f, &bits, sizeof(f));
        ctx->f[0] = f;
        __m128i maskAll = _mm_set_epi32(-1, -1, -1, -1);
        ctx->vu0_vf[1] = _mm_blendv_ps(ctx->vu0_vf[1], ctx->vu0_vf[2], _mm_castsi128_ps(maskAll));
        std::memcpy(&bits, &ctx->f[0], sizeof(bits));
        SET_GPR_U32(ctx, 3, bits);
        SET_GPR_U64(ctx, 2, GPR_U64(ctx, 3) << 32);
        ctx->vu0_vf[3] = _mm_castsi128_ps(GPR_VEC(ctx, 2));
        WRITE128(ADD32(GPR_U32(ctx, 29), 0), GPR_VEC(ctx, 2));
        __m128i maskX = _mm_set_epi32(0, 0, 0, -1);
        ctx->vu0_vf[1] = _mm_blendv_ps(ctx->vu0_vf[1], ctx->vu0_vf[3], _mm_castsi128_ps(maskX));
        ctx->vu0_vf[2] = _mm_blendv_ps(ctx->vu0_vf[2], ctx->vu0_vf[1], _mm_castsi128_ps(maskAll));
        ctx->pc = 0x00311A2Cu;
    }

    inline void stub31190c(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        SET_GPR_S32(ctx, 3, static_cast<int32_t>(READ32(ADD32(GPR_U32(ctx, 6), 8))));
        SET_GPR_S32(ctx, 2, static_cast<int32_t>(SLL32(GPR_U32(ctx, 8), 4)));
        SET_GPR_S32(ctx, 4, static_cast<int32_t>(ADD32(GPR_U32(ctx, 2), GPR_U32(ctx, 9))));
        SET_GPR_U64(ctx, 6, static_cast<uint64_t>(GPR_U64(ctx, 2)) + static_cast<uint64_t>(GPR_U64(ctx, 0)));
        SET_GPR_S32(ctx, 5, static_cast<int32_t>(ADD32(GPR_U32(ctx, 3), GPR_U32(ctx, 7))));
        SET_GPR_S32(ctx, 3, static_cast<int32_t>(READ32(ADD32(GPR_U32(ctx, 5), 4294967292u))));
        SET_GPR_S32(ctx, 2, 2);
        ctx->vu0_vf[2] = _mm_castsi128_ps(READ128(ADD32(GPR_U32(ctx, 4), 16)));
        if (GPR_U64(ctx, 3) != GPR_U64(ctx, 2))
        {
            ctx->pc = 0x00311954u;
            return;
        }
        uint32_t bits = READ32(ADD32(GPR_U32(ctx, 5), 0));
        float f;
        std::memcpy(&f, &bits, sizeof(f));
        ctx->f[0] = f;
        __m128i maskAll = _mm_set_epi32(-1, -1, -1, -1);
        ctx->vu0_vf[1] = _mm_blendv_ps(ctx->vu0_vf[1], ctx->vu0_vf[2], _mm_castsi128_ps(maskAll));
        std::memcpy(&bits, &ctx->f[0], sizeof(bits));
        SET_GPR_U32(ctx, 3, bits);
        SET_GPR_U64(ctx, 2, GPR_U64(ctx, 3) << 32);
        ctx->vu0_vf[3] = _mm_castsi128_ps(GPR_VEC(ctx, 2));
        WRITE128(ADD32(GPR_U32(ctx, 29), 0), GPR_VEC(ctx, 2));
        __m128i maskY = _mm_set_epi32(0, 0, -1, 0);
        ctx->vu0_vf[1] = _mm_blendv_ps(ctx->vu0_vf[1], ctx->vu0_vf[3], _mm_castsi128_ps(maskY));
        ctx->vu0_vf[2] = _mm_blendv_ps(ctx->vu0_vf[2], ctx->vu0_vf[1], _mm_castsi128_ps(maskAll));
        ctx->pc = 0x00311A2Cu;
    }

    inline void stub311a6c(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        SET_GPR_S32(ctx, 2, static_cast<int32_t>(READ32(ADD32(GPR_U32(ctx, 6), 8))));
        SET_GPR_S32(ctx, 4, static_cast<int32_t>(ADD32(GPR_U32(ctx, 9), GPR_U32(ctx, 8))));
        SET_GPR_S32(ctx, 2, static_cast<int32_t>(ADD32(GPR_U32(ctx, 7), GPR_U32(ctx, 2))));
        SET_GPR_S32(ctx, 3, static_cast<int8_t>(READ8(ADD32(GPR_U32(ctx, 2), 0))));
        WRITE8(ADD32(GPR_U32(ctx, 4), 256), static_cast<uint8_t>(GPR_U32(ctx, 3)));
        ctx->pc = 0x00311B08u;
    }

    inline void stub311a84(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        SET_GPR_S32(ctx, 2, static_cast<int32_t>(READ32(ADD32(GPR_U32(ctx, 6), 8))));
        SET_GPR_S32(ctx, 3, static_cast<int32_t>(SLL32(GPR_U32(ctx, 8), 1)));
        SET_GPR_S32(ctx, 3, static_cast<int32_t>(ADD32(GPR_U32(ctx, 9), GPR_U32(ctx, 3))));
        SET_GPR_S32(ctx, 2, static_cast<int32_t>(ADD32(GPR_U32(ctx, 7), GPR_U32(ctx, 2))));
        SET_GPR_S32(ctx, 4, static_cast<int16_t>(READ16(ADD32(GPR_U32(ctx, 2), 0))));
        WRITE16(ADD32(GPR_U32(ctx, 3), 240), static_cast<uint16_t>(GPR_U32(ctx, 4)));
        ctx->pc = 0x00311B08u;
    }

    inline void stub311aa0(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        SET_GPR_S32(ctx, 2, static_cast<int32_t>(READ32(ADD32(GPR_U32(ctx, 6), 8))));
        SET_GPR_S32(ctx, 3, static_cast<int32_t>(SLL32(GPR_U32(ctx, 8), 2)));
        SET_GPR_S32(ctx, 3, static_cast<int32_t>(ADD32(GPR_U32(ctx, 9), GPR_U32(ctx, 3))));
        SET_GPR_S32(ctx, 2, static_cast<int32_t>(ADD32(GPR_U32(ctx, 7), GPR_U32(ctx, 2))));
        SET_GPR_S32(ctx, 4, static_cast<int32_t>(READ32(ADD32(GPR_U32(ctx, 2), 0))));
        WRITE32(ADD32(GPR_U32(ctx, 3), 208), GPR_U32(ctx, 4));
        ctx->pc = 0x00311B08u;
    }

    inline void stub311abc(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        SET_GPR_S32(ctx, 2, static_cast<int32_t>(READ32(ADD32(GPR_U32(ctx, 6), 8))));
        SET_GPR_S32(ctx, 3, static_cast<int32_t>(SLL32(GPR_U32(ctx, 8), 3)));
        SET_GPR_S32(ctx, 3, static_cast<int32_t>(ADD32(GPR_U32(ctx, 9), GPR_U32(ctx, 3))));
        SET_GPR_S32(ctx, 2, static_cast<int32_t>(ADD32(GPR_U32(ctx, 7), GPR_U32(ctx, 2))));
        SET_GPR_U64(ctx, 4, READ64(ADD32(GPR_U32(ctx, 2), 0)));
        WRITE64(ADD32(GPR_U32(ctx, 3), 144), GPR_U64(ctx, 4));
        ctx->pc = 0x00311B08u;
    }

    inline void stub311ad8(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        SET_GPR_S32(ctx, 2, static_cast<int32_t>(READ32(ADD32(GPR_U32(ctx, 6), 8))));
        SET_GPR_S32(ctx, 3, static_cast<int32_t>(SLL32(GPR_U32(ctx, 8), 2)));
        SET_GPR_S32(ctx, 3, static_cast<int32_t>(ADD32(GPR_U32(ctx, 9), GPR_U32(ctx, 3))));
        SET_GPR_S32(ctx, 2, static_cast<int32_t>(ADD32(GPR_U32(ctx, 7), GPR_U32(ctx, 2))));
        uint32_t bits = READ32(ADD32(GPR_U32(ctx, 2), 0));
        float f;
        std::memcpy(&f, &bits, sizeof(f));
        ctx->f[0] = f;
        std::memcpy(&bits, &ctx->f[0], sizeof(bits));
        WRITE32(ADD32(GPR_U32(ctx, 3), 296), bits);
        ctx->pc = 0x00311B08u;
    }

    inline void stub311728(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        uint32_t sp = getRegU32(ctx, 29) - 0x50u;
        SET_GPR_S32(ctx, 29, static_cast<int32_t>(sp));
        WRITE128(sp + 0x30u, GPR_VEC(ctx, 16));
        WRITE128(sp + 0x40u, GPR_VEC(ctx, 31));
        SET_GPR_U64(ctx, 16, GPR_U64(ctx, 4));
        uint32_t v1 = READ32(getRegU32(ctx, 5));
        SET_GPR_S32(ctx, 3, static_cast<int32_t>(v1));
        SET_GPR_S32(ctx, 5, 2);
        uint32_t v0 = READ32(v1 + 0x2Cu);
        SET_GPR_S32(ctx, 2, static_cast<int32_t>(v0));
        SET_GPR_U32(ctx, 31, 0x0031174Cu);
        uint32_t a0 = READ32(v0 + 0x14u);
        SET_GPR_S32(ctx, 4, static_cast<int32_t>(a0));
        ctx->pc = 0x00282620u;
        if (!runtime->dispatchGuestBranch(rdram, ctx, 0x00282620u, 0x00311744u, 0x0031174Cu,
                                          PS2Runtime::GuestBranchKind::DirectCall, "JAL"))
        {
            return;
        }
        ctx->pc = 0x0031174Cu;
        if (g_orig311708)
            g_orig311708(rdram, ctx, runtime);
        for (int iter = 0; iter < 1000 && ctx->pc >= 0x00311728u && ctx->pc < 0x00311B18u; ++iter)
        {
            auto fn = runtime->lookupFunction(ctx->pc);
            if (!fn)
                break;
            fn(rdram, ctx, runtime);
        }
    }

    inline void stub3170e0(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        static const bool s_ret0 = [] {
            const char *e = std::getenv("PS2_STUB3170E0_RET0");
            return e != nullptr && e[0] == '1';
        }();
        if (s_ret0)
        {
            (void)rdram; (void)runtime;
            SET_GPR_S32(ctx, 2, 0);
            ctx->pc = getRegU32(ctx, 31);
            return;
        }
        uint32_t sp = getRegU32(ctx, 29) - 0x30u;
        SET_GPR_S32(ctx, 29, static_cast<int32_t>(sp));
        WRITE128(sp + 0x10u, GPR_VEC(ctx, 16));
        WRITE128(sp + 0x20u, GPR_VEC(ctx, 31));
        SET_GPR_U64(ctx, 16, GPR_U64(ctx, 4));
        uint32_t v1 = READ32(getRegU32(ctx, 5));
        SET_GPR_S32(ctx, 3, static_cast<int32_t>(v1));
        SET_GPR_S32(ctx, 5, 2);
        uint32_t v0 = READ32(v1 + 0x2Cu);
        SET_GPR_S32(ctx, 2, static_cast<int32_t>(v0));
        SET_GPR_U32(ctx, 31, 0x00317104u);
        uint32_t a0 = READ32(v0 + 0x14u);
        SET_GPR_S32(ctx, 4, static_cast<int32_t>(a0));
        ctx->pc = 0x00282620u;
        if (!runtime->dispatchGuestBranch(rdram, ctx, 0x00282620u, 0x003170FCu, 0x00317104u, PS2Runtime::GuestBranchKind::DirectCall, "JAL"))
        {
            return;
        }
        ctx->pc = 0x00317104u;
        if (g_orig3170d0)
        {
            g_orig3170d0(rdram, ctx, runtime);
        }
        for (int iter = 0; iter < 1000 && ctx->pc >= 0x003170E0u && ctx->pc < 0x003174FCu; ++iter)
        {
            auto fn = runtime->lookupFunction(ctx->pc);
            if (!fn)
            {
                break;
            }
            fn(rdram, ctx, runtime);
        }
    }

    inline void stub31740c(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        uint32_t v0 = SLL32(GPR_U32(ctx, 7), 2);
        v0 = ADD32(GPR_U32(ctx, 8), v0);
        SET_GPR_S32(ctx, 2, static_cast<int32_t>(v0));
        SET_GPR_S32(ctx, 11, static_cast<int32_t>(READ32(ADD32(v0, 208u))));
        ctx->pc = 0x00317478u;
        auto fn = runtime->lookupFunction(0x00317478u);
        if (fn)
            fn(rdram, ctx, runtime);
    }

    inline void stub2385f0(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        uint32_t sp = getRegU32(ctx, 29) - 0x10u;
        SET_GPR_S32(ctx, 29, static_cast<int32_t>(sp));
        uint32_t v1 = getRegU32(ctx, 4);
        SET_GPR_U64(ctx, 3, GPR_U64(ctx, 4));
        WRITE128(sp, GPR_VEC(ctx, 31));
        SET_GPR_S32(ctx, 4, static_cast<int32_t>(0x004DF8E0u));
        uint32_t a2 = READ32(v1 + 0x14u);
        uint32_t v0 = READ32(v1 + 0x10u);
        uint32_t a1 = READ32(a2);
        SET_GPR_S32(ctx, 6, static_cast<int32_t>(a2));
        SET_GPR_S32(ctx, 2, static_cast<int32_t>(v0));
        SET_GPR_U32(ctx, 31, 0x00238618u);
        SET_GPR_S32(ctx, 5, static_cast<int32_t>(ADD32(v0, a1)));
        ctx->pc = 0x0029F3F8u;
        if (!runtime->dispatchGuestBranch(rdram, ctx, 0x0029F3F8u, 0x00238610u, 0x00238618u,
                                          PS2Runtime::GuestBranchKind::DirectCall, "JAL"))
        {
            return;
        }
        SET_GPR_VEC(ctx, 31, READ128(sp));
        SET_GPR_S32(ctx, 29, static_cast<int32_t>(sp + 0x10u));
        ctx->pc = getRegU32(ctx, 31);
    }

    inline void stub2e5cb8(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        uint32_t sp = getRegU32(ctx, 29) - 0x10u;
        SET_GPR_S32(ctx, 29, static_cast<int32_t>(sp));
        SET_GPR_U64(ctx, 4, GPR_U64(ctx, 5));
        WRITE128(sp, GPR_VEC(ctx, 31));
        SET_GPR_U32(ctx, 31, 0x002E5CCCu);
        SET_GPR_U64(ctx, 5, GPR_U64(ctx, 6));
        ctx->pc = 0x002DF8C0u;
        if (!runtime->dispatchGuestBranch(rdram, ctx, 0x002DF8C0u, 0x002E5CC4u, 0x002E5CCCu,
                                          PS2Runtime::GuestBranchKind::DirectCall, "JAL"))
        {
            return;
        }
        SET_GPR_VEC(ctx, 31, READ128(sp));
        SET_GPR_S32(ctx, 29, static_cast<int32_t>(sp + 0x10u));
        ctx->pc = getRegU32(ctx, 31);
    }

    inline void skip3ec030(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        (void)runtime;
        static const bool s_verboseLogs = [] {
            const char *e = std::getenv("PS2_PRIMAL_VERBOSE_LOGS");
            return e != nullptr && e[0] == '1';
        }();
        const uint32_t gp = getRegU32(ctx, 28);
        const uint32_t gp5d90Addr = (gp + 0xFFFFA270u) & 0x01FFFFFFu;
        uint32_t gp5d90 = 0;
        std::memcpy(&gp5d90, rdram + gp5d90Addr, sizeof(gp5d90));
        // Caller at 0x32d094 does bgez $2: >=0 means decode finished. Return -1 by default
        // so normal FMV/decode progression runs without uploading raw undecoded IPU noise;
        // set PS2_IPU_SKIP_RET0=1 to test immediate return 0.
        static const bool s_ret0 = [] {
            const char *e = std::getenv("PS2_IPU_SKIP_RET0");
            return e != nullptr && e[0] == '1';
        }();
        const int32_t ret = s_ret0 ? 0 : -1;
        (void)gp5d90;
        static int s_calls = 0;
        if (s_verboseLogs || s_calls++ < 10)
            RUNTIME_LOG("[ipu-skip] 0x3ec030 -> " << ret << " gp5d90=0x" << std::hex << gp5d90
                        << " ra=0x" << getRegU32(ctx, 31) << std::dec << std::endl);
        SET_GPR_S32(ctx, 2, ret);
        ctx->pc = GPR_U32(ctx, 31);
    }

    void dumpClusterCounts();
    inline void wrap32cd00b(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        static const bool s_verboseLogs = [] {
            const char *e = std::getenv("PS2_PRIMAL_VERBOSE_LOGS");
            return e != nullptr && e[0] == '1';
        }();
        g_cnt32cd00.fetch_add(1, std::memory_order_relaxed);
        if (s_verboseLogs) { static uint64_t s_dump = 0; if (++s_dump % 1000u == 0u) dumpClusterCounts(); }
        auto rd5d8c = [&]() -> uint32_t {
            const uint32_t addr = ADD32(GPR_U32(ctx, 28), 0xFFFFA274u);
            uint8_t *p = nullptr; uint32_t av = 0;
            return (primal_sif_rpc::mapGuestRange(rdram, addr, p, av) && av >= 4) ? *(uint32_t*)p : 0xDEADu;
        };
        static const bool s_skipFmv = [] {
            const char *e = std::getenv("PS2_SKIP_FMV");
            return e != nullptr && e[0] == '1';
        }();
        const uint32_t before = rd5d8c();
        if (s_skipFmv && (before == 3u || before == 6u))
        {
            const uint32_t stateAddr = ADD32(GPR_U32(ctx, 28), 0xFFFFA274u);
            uint8_t *sp = nullptr;
            uint32_t sav = 0;
            if (primal_sif_rpc::mapGuestRange(rdram, stateAddr, sp, sav) && sav >= 4u)
            {
                const uint32_t nextState = 7u;
                std::memcpy(sp, &nextState, 4);
            }
        }
        if (g_orig32cd00b) g_orig32cd00b(rdram, ctx, runtime);
        if (s_verboseLogs)
        {
            static uint32_t s_last = 0xFFFFFFFFu;
            const uint32_t after = rd5d8c();
            if (after != s_last || before != after)
            {
                s_last = after;
                RUNTIME_LOG("[32cd00-state] before=" << before << " after=" << after << std::endl);
            }
        }
    }

    // #104 Missing switch-table cases (2..10) in FUN_002cf9e0 (table at 0x00477440)
    template <uint32_t Offset>
    inline void stub2cf9e0FloatCase(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t s0 = getRegU32(ctx, 16);
        const uint32_t s1 = getRegU32(ctx, 17);
        const uint32_t v0 = READ32(ADD32(s1, 8u));
        const uint32_t f0 = READ32(v0);
        WRITE32(ADD32(s1, 8u), ADD32(v0, 4u));
        WRITE32(ADD32(s0, Offset), f0);
        ctx->pc = 0x002CFB60u;
    }

    template <uint32_t TargetPc, uint32_t SourcePc, uint32_t RetPc>
    inline void stub2cf9e0CallCase(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        SET_GPR_U64(ctx, 4, GPR_U64(ctx, 16));
        SET_GPR_U64(ctx, 5, GPR_U64(ctx, 17));
        SET_GPR_U32(ctx, 31, RetPc);
        ctx->pc = TargetPc;
        if (runtime->dispatchGuestBranch(rdram, ctx, TargetPc, SourcePc, RetPc,
                                         PS2Runtime::GuestBranchKind::DirectCall, "JAL"))
        {
            ctx->pc = RetPc;
        }
    }

    inline void stub2cfad4(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t s0 = getRegU32(ctx, 16);
        const uint32_t s1 = getRegU32(ctx, 17);
        const uint32_t v0 = READ32(ADD32(s1, 8u));
        const uint32_t v1 = READ32(v0);
        WRITE32(ADD32(s1, 8u), ADD32(v0, 4u));
        WRITE32(ADD32(s0, 0x2D0u), (v1 != 0u) ? 1u : 0u);
        ctx->pc = 0x002CFB60u;
    }

    inline void stub2cfaf0(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t s1 = getRegU32(ctx, 17);
        SET_GPR_S32(ctx, 18, static_cast<int32_t>(0x4C444E45u)); // "ENDL"
        SET_GPR_S32(ctx, 3, static_cast<int32_t>(READ32(ADD32(s1, 8u))));
        ctx->pc = 0x002CFB00u;
    }

    // #109 Missing switch-table cases (7, 9, 10, 12) in FUN_002dbe58 (table at 0x00478240)
    inline void stub2dc038(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        SET_GPR_U64(ctx, 4, GPR_U64(ctx, 18)); // a0 = s2
        SET_GPR_U32(ctx, 31, 0x002DC040u);
        ctx->pc = 0x002D7618u;
        if (runtime->dispatchGuestBranch(rdram, ctx, 0x002D7618u, 0x002DC038u, 0x002DC040u,
                                         PS2Runtime::GuestBranchKind::DirectCall, "JAL"))
        {
            ctx->pc = 0x002DC040u;
        }
    }

    inline void stub2dc050(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t s1 = getRegU32(ctx, 17);
        const uint32_t s2 = getRegU32(ctx, 18);
        const uint32_t v0 = READ32(ADD32(s2, 8u));
        const uint32_t f0 = READ32(v0);
        WRITE32(ADD32(s2, 8u), ADD32(v0, 4u));
        WRITE32(ADD32(s1, 0x4Cu), f0);
        ctx->pc = 0x002DC144u;
    }

    inline void stub2dc068(uint8_t *, R5900Context *ctx, PS2Runtime *)
    {
        SET_GPR_S32(ctx, 19, static_cast<int32_t>(0x4C444E45u)); // s3 = "ENDL"
        ctx->pc = 0x002DC094u;
    }

    inline void stub2dc0cc(uint8_t *, R5900Context *ctx, PS2Runtime *)
    {
        SET_GPR_S32(ctx, 19, static_cast<int32_t>(0x4C444E45u)); // s3 = "ENDL"
        ctx->pc = 0x002DC0F4u;
    }

    // #110 Missing switch-table case 5 (0x2cb64c) in entry_002cb4b0 (table at 0x004771c0)
    inline void stub2cb64c(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t s0 = getRegU32(ctx, 16);
        const uint32_t s1 = getRegU32(ctx, 17);
        const uint32_t v0 = READ32(ADD32(s0, 8u));
        const uint32_t bits = READ32(v0);
        float f = 0.0f;
        std::memcpy(&f, &bits, sizeof(f));
        ctx->f[0] = f;
        const uint32_t nextV0 = ADD32(v0, 4u);
        SET_GPR_S32(ctx, 2, static_cast<int32_t>(nextV0));
        WRITE32(ADD32(s0, 8u), nextV0);
        WRITE32(ADD32(s1, 0x500u), bits);
        ctx->pc = 0x002CB67Cu;
    }

    // #110 Missing actor factory entries merged into destructor tails (JALR from 0x2bb188)
    template <uint32_t EntryAddr, uint32_t ObjSize, uint32_t CtorAddr>
    inline void primalActorFactoryStub(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        SET_GPR_S32(ctx, 29, static_cast<int32_t>(ADD32(GPR_U32(ctx, 29), 0xFFFFFFB0u)));
        const uint32_t sp = GPR_U32(ctx, 29);
        const uint32_t allocCtx = READ32(0x00488388u);
        SET_GPR_S32(ctx, 4, static_cast<int32_t>(allocCtx));
        WRITE128(ADD32(sp, 48u), GPR_VEC(ctx, 19)); // s3
        WRITE128(ADD32(sp, 32u), GPR_VEC(ctx, 18)); // s2
        SET_GPR_U64(ctx, 19, GPR_U64(ctx, 7));      // s3 = a3
        WRITE128(ADD32(sp, 16u), GPR_VEC(ctx, 17)); // s1
        SET_GPR_U64(ctx, 18, GPR_U64(ctx, 6));      // s2 = a2
        WRITE128(ADD32(sp, 64u), GPR_VEC(ctx, 31)); // ra
        SET_GPR_U64(ctx, 17, GPR_U64(ctx, 5));      // s1 = a1
        WRITE128(ADD32(sp, 0u), GPR_VEC(ctx, 16));  // s0

        if (allocCtx == 0u)
        {
            SET_GPR_U32(ctx, 31, EntryAddr + 0x38u);
            SET_GPR_S32(ctx, 4, static_cast<int32_t>(ObjSize));
            ctx->pc = 0x0028A2A0u;
            if (!runtime->dispatchGuestBranch(rdram, ctx, 0x0028A2A0u, EntryAddr + 0x30u, EntryAddr + 0x38u,
                                              PS2Runtime::GuestBranchKind::DirectCall, "JAL"))
            {
                return;
            }
            SET_GPR_U64(ctx, 16, GPR_U64(ctx, 2)); // s0 = v0
        }
        else
        {
            SET_GPR_S32(ctx, 5, static_cast<int32_t>(ObjSize));
            SET_GPR_U32(ctx, 31, EntryAddr + 0x4Cu);
            SET_GPR_S32(ctx, 6, 1);
            ctx->pc = 0x00281FC0u;
            if (!runtime->dispatchGuestBranch(rdram, ctx, 0x00281FC0u, EntryAddr + 0x44u, EntryAddr + 0x4Cu,
                                              PS2Runtime::GuestBranchKind::DirectCall, "JAL"))
            {
                return;
            }
            SET_GPR_U64(ctx, 16, GPR_U64(ctx, 2)); // s0 = v0
        }

        SET_GPR_U64(ctx, 4, GPR_U64(ctx, 16));
        SET_GPR_S32(ctx, 6, static_cast<int32_t>(ObjSize));
        SET_GPR_U32(ctx, 31, EntryAddr + 0x60u);
        SET_GPR_U64(ctx, 5, 0u);
        ctx->pc = 0x003FCBF0u;
        if (!runtime->dispatchGuestBranch(rdram, ctx, 0x003FCBF0u, EntryAddr + 0x58u, EntryAddr + 0x60u,
                                          PS2Runtime::GuestBranchKind::DirectCall, "JAL"))
        {
            return;
        }

        const uint32_t ownerPtr = READ32(0x00488388u);
        SET_GPR_S32(ctx, 3, static_cast<int32_t>(ownerPtr));
        SET_GPR_U64(ctx, 4, GPR_U64(ctx, 16));
        SET_GPR_U64(ctx, 5, GPR_U64(ctx, 17));
        SET_GPR_U32(ctx, 31, EntryAddr + 0x78u);
        WRITE32(GPR_U32(ctx, 16), ownerPtr);
        ctx->pc = CtorAddr;
        if (!runtime->dispatchGuestBranch(rdram, ctx, CtorAddr, EntryAddr + 0x70u, EntryAddr + 0x78u,
                                          PS2Runtime::GuestBranchKind::DirectCall, "JAL"))
        {
            return;
        }

        SET_GPR_U64(ctx, 3, GPR_U64(ctx, 2));
        const uint32_t curSp = GPR_U32(ctx, 29);
        SET_GPR_VEC(ctx, 31, READ128(ADD32(curSp, 64u)));
        WRITE32(ADD32(GPR_U32(ctx, 3), 40u), GPR_U32(ctx, 18));
        WRITE32(ADD32(GPR_U32(ctx, 3), 8u), GPR_U32(ctx, 19));
        SET_GPR_VEC(ctx, 19, READ128(ADD32(curSp, 48u)));
        SET_GPR_VEC(ctx, 18, READ128(ADD32(curSp, 32u)));
        SET_GPR_VEC(ctx, 17, READ128(ADD32(curSp, 16u)));
        SET_GPR_VEC(ctx, 16, READ128(ADD32(curSp, 0u)));
        const uint32_t retPc = GPR_U32(ctx, 31);
        SET_GPR_S32(ctx, 29, static_cast<int32_t>(ADD32(curSp, 80u)));
        ctx->pc = retPc;
    }

    inline PS2Runtime::RecompiledFunction g_orig379c88 = nullptr;
    inline PS2Runtime::RecompiledFunction g_orig379c8c = nullptr;
    inline void wrap379c88(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t savedSp = getRegU32(ctx, 29);
        const uint32_t callerRa = getRegU32(ctx, 31);
        if (g_orig379c88) g_orig379c88(rdram, ctx, runtime);
        if (ctx->pc == 0x00379C8Cu && g_orig379c8c)
        {
            g_orig379c8c(rdram, ctx, runtime);
        }
        if (ctx->pc == callerRa && getRegU32(ctx, 29) == savedSp - 0x10u)
        {
            SET_GPR_S32(ctx, 29, static_cast<int32_t>(savedSp));
        }
    }

    inline PS2Runtime::RecompiledFunction g_orig37d2a8 = nullptr;
    inline PS2Runtime::RecompiledFunction g_orig37d2ac = nullptr;
    inline void wrap37d2a8(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        if (g_orig37d2a8) g_orig37d2a8(rdram, ctx, runtime);
        if (ctx->pc == 0x0037D2ACu && g_orig37d2ac)
        {
            g_orig37d2ac(rdram, ctx, runtime);
        }
    }

    inline PS2Runtime::RecompiledFunction g_orig3385f0 = nullptr;
    inline void wrap3385f0(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t savedSp = getRegU32(ctx, 29);
        const uint32_t callerRa = getRegU32(ctx, 31);
        if (g_orig3385f0) g_orig3385f0(rdram, ctx, runtime);
        if (ctx->pc == callerRa && getRegU32(ctx, 29) == savedSp - 0xC0u)
        {
            SET_GPR_S32(ctx, 29, static_cast<int32_t>(savedSp));
        }
    }

    inline PS2Runtime::RecompiledFunction g_orig3a50d0 = nullptr;
    inline void wrap3a50d0(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        static uint32_t s_cnt = 0u;
        const uint32_t c = s_cnt++;
        const uint32_t a0 = getRegU32(ctx, 4);
        const uint32_t a1 = getRegU32(ctx, 5);
        const uint32_t a2 = getRegU32(ctx, 6);
        const uint32_t ra = getRegU32(ctx, 31);
        static const bool s_verbose3a50d0 = []() {
            const char *e = std::getenv("PS2_PRIMAL_VERBOSE_LOGS");
            return e != nullptr && e[0] == '1';
        }();
        const bool isFrontendAsset = (ra >= 0x00103490u && ra < 0x00103600u) ||
                                     (ra >= 0x003C6670u && ra < 0x003C6700u);
        if (s_verbose3a50d0 && (c < 20u || isFrontendAsset))
        {
            std::string str;
            uint8_t *p = nullptr; uint32_t av = 0;
            if (a1 && primal_sif_rpc::mapGuestRange(rdram, a1, p, av))
            {
                const uint32_t n = std::min<uint32_t>(av, 64u);
                for (uint32_t i = 0; i < n && p[i] != 0; ++i) str.push_back(static_cast<char>(p[i]));
            }
            RUNTIME_LOG("[3a50d0] #" << std::dec << c << " ra=0x" << std::hex << ra
                        << " a0=0x" << a0 << " str=0x" << a1 << " \"" << str
                        << "\" dstObjPtr=0x" << a2 << std::dec << std::endl);
        }
        if (g_orig3a50d0) g_orig3a50d0(rdram, ctx, runtime);
    }

    inline PS2Runtime::RecompiledFunction g_orig3a4648 = nullptr;
    inline void wrap3a4648(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t s5 = getRegU32(ctx, 4);
        if (g_orig3a4648) g_orig3a4648(rdram, ctx, runtime);
        const uint32_t v0 = getRegU32(ctx, 2);
        if (v0 == 0u)
        {
            static uint32_t s_zeroCnt = 0u;
            const uint32_t c = s_zeroCnt++;
            if (c < 5u)
            {
                auto rd32 = [&](uint32_t a) -> uint32_t {
                    uint8_t *p = nullptr; uint32_t av = 0;
                    return (primal_sif_rpc::mapGuestRange(rdram, a, p, av) && av >= 4) ? *(uint32_t*)p : 0xDEADu;
                };
                RUNTIME_LOG("[3a4648-zero] #" << std::dec << c
                            << " s5=0x" << std::hex << s5
                            << " +808=0x" << (s5 ? rd32(s5 + 0x808u) : 0u)
                            << " +840=0x" << (s5 ? rd32(s5 + 0x840u) : 0u)
                            << " +844=0x" << (s5 ? rd32(s5 + 0x844u) : 0u)
                            << " ra=0x" << getRegU32(ctx, 31) << std::dec << std::endl);
            }
        }
    }

    inline void wrap298200(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t idx = g_cnt298200.fetch_add(1, std::memory_order_relaxed);
        auto rd32 = [&](uint32_t a) -> uint32_t {
            uint8_t *p = nullptr; uint32_t av = 0;
            return (primal_sif_rpc::mapGuestRange(rdram, a, p, av) && av >= 4) ? *(uint32_t*)p : 0xDEADu;
        };
        const uint32_t f614 = rd32(0x00488614u);
        if (f614 != 0 || idx == 100 || idx == 200)
        {
            static int s_nzLog = 0;
            if (f614 == 0 || s_nzLog++ < 5 || idx == 100 || idx == 200)
            {
                const uint32_t tadr = rd32(0x004DF88Cu);
                RUNTIME_LOG("[298200-probe] #" << idx << " 488614=0x" << std::hex << f614
                            << " 4df88c=0x" << tadr
                            << " qw0=" << rd32(tadr) << "," << rd32(tadr + 4) << "," << rd32(tadr + 8) << "," << rd32(tadr + 12)
                            << " qw1=" << rd32(tadr + 16) << "," << rd32(tadr + 20) << "," << rd32(tadr + 24) << "," << rd32(tadr + 28)
                            << " qw2=" << rd32(tadr + 32) << "," << rd32(tadr + 36) << "," << rd32(tadr + 40) << "," << rd32(tadr + 44)
                            << " qw3=" << rd32(tadr + 48) << "," << rd32(tadr + 52) << "," << rd32(tadr + 56) << "," << rd32(tadr + 60)
                            << std::dec << " gifBefore=" << runtime->gs().getDebugHistory().size() << std::endl);
                if (idx == 200)
                {
                    runtime->gs().setDebugHistoryPaused(false);
                    const uint32_t strPtr = rd32(0x004883ACu);
                    uint8_t *spPtr = nullptr; uint32_t spAv = 0;
                    if (strPtr && primal_sif_rpc::mapGuestRange(rdram, strPtr, spPtr, spAv))
                    {
                        std::string s(reinterpret_cast<const char*>(spPtr), strnlen(reinterpret_cast<const char*>(spPtr), std::min<uint32_t>(spAv, 128u)));
                        RUNTIME_LOG("[298200-str] 4883ac=0x" << std::hex << strPtr << " \"" << s << "\"" << std::dec << std::endl);
                    }
                    for (uint32_t q = 0; q < 12; ++q)
                    {
                        const uint32_t a = 0x005762d0u + q * 16u;
                        RUNTIME_LOG("[298200-5762d0] +" << (q * 16u) << ": " << std::hex
                                    << rd32(a) << "," << rd32(a + 4) << "," << rd32(a + 8) << "," << rd32(a + 12) << std::dec << std::endl);
                    }
                    for (uint32_t q = 0; q < 8; ++q)
                    {
                        const uint32_t a = 0x00510440u + q * 16u;
                        RUNTIME_LOG("[298200-510440] +" << (q * 16u) << ": " << std::hex
                                    << rd32(a) << "," << rd32(a + 4) << "," << rd32(a + 8) << "," << rd32(a + 12) << std::dec << std::endl);
                    }
                    uint32_t cur = tadr;
                    for (int step = 0; step < 32 && cur != 0; ++step)
                    {
                        const uint32_t w0 = rd32(cur), w1 = rd32(cur + 4), w2 = rd32(cur + 8), w3 = rd32(cur + 12);
                        const uint32_t id = (w0 >> 28) & 0x7u;
                        const uint32_t qwc = w0 & 0xFFFFu;
                        RUNTIME_LOG("[298200-chain] #" << step << " @0x" << std::hex << cur
                                    << " id=" << std::dec << id << " qwc=" << qwc
                                    << " w1=0x" << std::hex << w1 << " w2=0x" << w2 << " w3=0x" << w3 << std::dec << std::endl);
                        if (id == 7u) break; // END
                        if (id == 1u) cur += (1u + qwc) * 16u; // CNT
                        else if (id == 2u) cur = w1; // NEXT
                        else if (id == 3u || id == 4u) cur += 16u; // REF/REFS
                        else if (id == 5u) cur += 16u; // CALL (just show top-level)
                        else break;
                    }
                }
            }
        }
        if (idx == 0)
        {
            runtime->gs().setDebugHistoryPaused(false);
        }
        if (g_orig298200) g_orig298200(rdram, ctx, runtime);
        {
            static uint64_t s_lastSeq = 0;
            static uint32_t s_totalXfer = 0;
            const auto histAll = runtime->gs().getDebugHistory();
            for (const auto &e : histAll)
            {
                if (e.seq > s_lastSeq)
                {
                    s_lastSeq = e.seq;
                    if (e.kind == GSDebugEventKind::Transfer)
                    {
                        if (s_totalXfer < 8)
                        {
                            RUNTIME_LOG("[298200-xfer] #" << s_totalXfer << " @idx=" << idx
                                        << " dbp=0x" << std::hex << e.bitbltbuf.dbp
                                        << " dpsm=" << std::dec << (int)e.bitbltbuf.dpsm
                                        << " px=" << e.transferPixels << std::endl);
                        }
                        ++s_totalXfer;
                    }
                }
            }
            {
                static const bool s_verboseFe = []() {
                    const char *e = std::getenv("PS2_PRIMAL_VERBOSE_LOGS");
                    return e != nullptr && e[0] == '1';
                }();
                static bool s_firstFeLogged = false;
                const uint32_t feObj = rd32(0x00488390u);
                const bool shouldLogFe = s_verboseFe &&
                                         ((feObj != 0u && !s_firstFeLogged) ||
                                          (idx >= 60u && (idx % 60u) == 0u) ||
                                          idx == 150u || idx == 200u);
                if (feObj != 0u) s_firstFeLogged = true;
                if (shouldLogFe)
                {
                    const uint32_t v1 = feObj ? rd32(feObj + 0x20u) : 0u;
                    const uint32_t v2 = feObj ? rd32(feObj + 0x68u) : 0u;
                    RUNTIME_LOG("[103b28-state] #" << std::dec << idx
                                << " 488390=0x" << std::hex << feObj
                                << " v1(+20)=0x" << v1
                                << " v1+8=0x" << (v1 ? rd32(v1 + 8u) : 0u)
                                << " v1+c=0x" << (v1 ? rd32(v1 + 0xCu) : 0u)
                                << " v2(+68)=0x" << v2
                                << " v2+8=0x" << (v2 ? rd32(v2 + 8u) : 0u)
                                << " v2+c=0x" << (v2 ? rd32(v2 + 0xCu) : 0u) << std::dec << std::endl);
                }
            }
            if (idx == 200 || (idx >= 60u && (idx % 60u) == 0u))
            {
                RUNTIME_LOG("[298200-xfer-total] #" << idx << " totalXfer=" << s_totalXfer << std::endl);
            }
        }
        if (idx == 200 || idx == 201)
        {
            const auto hist = runtime->gs().getDebugHistory();
            const auto snap = runtime->gs().getDebugSnapshot();
            int nTag = 0, nReg = 0, nDraw = 0, nXfer = 0, nPres = 0;
            for (const auto &e : hist)
            {
                if (e.kind == GSDebugEventKind::GifTag) ++nTag;
                else if (e.kind == GSDebugEventKind::Register) ++nReg;
                else if (e.kind == GSDebugEventKind::Draw) ++nDraw;
                else if (e.kind == GSDebugEventKind::Transfer) ++nXfer;
                else if (e.kind == GSDebugEventKind::Present) ++nPres;
            }
            RUNTIME_LOG("[298200-after] #" << idx << " gifAfter=" << hist.size()
                        << " tag=" << nTag << " reg=" << nReg << " draw=" << nDraw
                        << " xfer=" << nXfer << " pres=" << nPres
                        << " hostPres=" << snap.hasHostPresentationFrame
                        << " (" << snap.hostPresentationWidth << "x" << snap.hostPresentationHeight
                        << " dfbp=" << snap.hostPresentationDisplayFbp << " sfbp=" << snap.hostPresentationSourceFbp << ")"
                        << std::endl);
            std::vector<uint8_t> px;
            uint32_t pw = 0, ph = 0;
            if (runtime->gs().copyLatchedHostPresentationFrame(px, pw, ph))
            {
                uint32_t nz = 0;
                for (size_t i = 0; i + 3 < px.size(); i += 4)
                    if (px[i] | px[i + 1] | px[i + 2]) ++nz;
                RUNTIME_LOG("[298200-fb] #" << idx << " pw=" << pw << " ph=" << ph << " nz=" << nz << std::endl);
            }
            if (idx == 200)
            {
                const uint8_t *vram = runtime->memory().getGSVRAM();
                uint32_t nzAll = 0, nzTex = 0, nzClut = 0, nzFb = 0;
                if (vram)
                {
                    for (uint32_t i = 0; i < 4u * 1024u * 1024u; ++i) if (vram[i]) ++nzAll;
                    for (uint32_t i = 0x348100u; i < 0x348100u + 0x10000u && i < 4u * 1024u * 1024u; ++i) if (vram[i]) ++nzTex;
                    for (uint32_t i = 0x348000u; i < 0x348100u; ++i) if (vram[i]) ++nzClut;
                    for (uint32_t i = 0x230000u; i < 0x230000u + 640u * 448u * 4u && i < 4u * 1024u * 1024u; ++i) if (vram[i]) ++nzFb;
                }
                RUNTIME_LOG("[298200-vram] #200 nzAll=" << nzAll << " nzTex=" << nzTex << " nzClut=" << nzClut << " nzFb=" << nzFb << std::endl);
            }
            int shown = 0, regShown = 0;
            for (const auto &e : hist)
            {
                if (e.kind == GSDebugEventKind::Register && shown == 0 && regShown < 25)
                {
                    ++regShown;
                    RUNTIME_LOG("[298200-reg] #" << regShown << " reg=0x" << std::hex << (int)e.reg
                                << " val=0x" << e.regValue << std::dec << std::endl);
                }
                if (e.kind == GSDebugEventKind::Draw && shown < 2)
                {
                    ++shown;
                    RUNTIME_LOG("[298200-draw] #" << shown << " fbp=0x" << std::hex << e.frame.fbp
                                << " fbw=" << std::dec << (int)e.frame.fbw << " fpsm=" << (int)e.frame.psm
                                << " fbmsk=0x" << std::hex << e.frame.fbmsk
                                << " zbp=0x" << e.zbuf.zbp << " zpsm=" << std::dec << (int)e.zbuf.psm << " zmsk=" << e.zbuf.zmask
                                << " sc=(" << e.scissor.x0 << "," << e.scissor.y0 << ")-(" << e.scissor.x1 << "," << e.scissor.y1 << ")"
                                << " tex0=(tbp=0x" << std::hex << e.tex0.tbp0 << " cbp=0x" << e.tex0.cbp
                                << std::dec << " psm=" << (int)e.tex0.psm << " tw=" << (int)e.tex0.tw << " th=" << (int)e.tex0.th
                                << " tfx=" << (int)e.tex0.tfx << ")"
                                << " test=0x" << std::hex << e.test << " alpha=0x" << e.alpha
                                << " vtx=" << std::dec << e.vertexCount
                                << " x=[" << e.xMin << "," << e.xMax << "]"
                                << " y=[" << e.yMin << "," << e.yMax << "]"
                                << " a=[" << (int)e.aMin << "," << (int)e.aMax << "]" << std::endl);
                }
            }
            runtime->gs().setDebugHistoryPaused(true);
        }
    }

    inline void wrap104a00(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        g_cnt104a00.fetch_add(1, std::memory_order_relaxed);
        auto rd32 = [&](uint32_t a) -> uint32_t {
            uint8_t *p = nullptr; uint32_t av = 0;
            return (primal_sif_rpc::mapGuestRange(rdram, a, p, av) && av >= 4) ? *(uint32_t*)p : 0xDEADu;
        };
        const uint32_t before = rd32(0x00435960u);
        if (before != 0x0011D420u)
        {
            static int s_b = 0;
            if (s_b < 5)
            {
                ++s_b;
                RUNTIME_LOG("[435960-watch] 104a00 ENTER before=0x" << std::hex << before << std::dec << std::endl);
            }
        }
        SplitChainBridge<0x00104A00u, 0x00104B4Cu>::call(rdram, ctx, runtime);
        const uint32_t after = rd32(0x00435960u);
        if (before != 0x0011D420u || after != 0x0011D420u)
        {
            static int s_c = 0;
            if (s_c < 5)
            {
                ++s_c;
                RUNTIME_LOG("[435960-watch] 104a00 before=0x" << std::hex << before << " after=0x" << after << std::dec << std::endl);
            }
        }
    }

    inline void wrap329ff0(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        auto rd32 = [&](uint32_t a) -> uint32_t {
            uint8_t *p = nullptr; uint32_t av = 0;
            return (primal_sif_rpc::mapGuestRange(rdram, a, p, av) && av >= 4) ? *(uint32_t*)p : 0xDEADu;
        };
        const uint32_t before = rd32(0x00435960u);
        SplitChainBridge<0x00329FF0u, 0x0032AB78u>::call(rdram, ctx, runtime);
        const uint32_t after = rd32(0x00435960u);
        if (before != 0x0011D420u || after != 0x0011D420u)
        {
            static int s_c = 0;
            if (s_c < 5)
            {
                ++s_c;
                RUNTIME_LOG("[435960-watch] 329ff0 before=0x" << std::hex << before << " after=0x" << after << std::dec << std::endl);
            }
        }
    }

    inline PS2Runtime::RecompiledFunction g_orig103d40 = nullptr;
    inline PS2Runtime::RecompiledFunction g_orig104808 = nullptr;
    inline PS2Runtime::RecompiledFunction g_orig37e548 = nullptr;
    inline PS2Runtime::RecompiledFunction g_orig37e578 = nullptr;

    inline void wrap37e548(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        if (g_orig37e548) g_orig37e548(rdram, ctx, runtime);
        if (ctx->pc == 0x0037E578u && g_orig37e578)
        {
            g_orig37e578(rdram, ctx, runtime);
        }
    }

    inline PS2Runtime::RecompiledFunction g_orig2f92f0 = nullptr;
    inline void wrap2f92f0(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        static const bool s_verboseLogs = [] {
            const char *e = std::getenv("PS2_PRIMAL_VERBOSE_LOGS");
            return e != nullptr && e[0] == '1';
        }();
        if (g_seen103d40 && s_verboseLogs)
        {
            auto r32 = [&](uint32_t a) -> uint32_t {
                uint8_t *p = nullptr; uint32_t av = 0;
                return (primal_sif_rpc::mapGuestRange(rdram, a, p, av) && av >= 4) ? *(uint32_t*)p : 0xDEADu;
            };
            const uint32_t s4 = getRegU32(ctx, 20);
            const uint32_t s5 = getRegU32(ctx, 21);
            const uint32_t s5_8 = r32(s5 + 8u);
            const uint32_t s5_14 = r32(s5 + 0x14u);
            const uint32_t s5_18 = r32(s5 + 0x18u);
            const uint32_t s2_14 = (s5_18 != 0 && s5_18 != 0xDEADu) ? r32(s5_18 + 0x14u) : 0u;
            const uint32_t o0 = (s2_14 != 0 && s2_14 != 0xDEADu) ? r32(s2_14) : 0u;
            const uint32_t o0_fn = (o0 != 0 && o0 != 0xDEADu) ? r32(o0 + 8u) : 0u;
            const uint32_t s5_14_0 = (s5_14 != 0 && s5_14 != 0xDEADu) ? r32(s5_14) : 0u;
            const uint32_t fn1c = (s5_14_0 != 0 && s5_14_0 != 0xDEADu) ? r32(s5_14_0 + 0x1cu) : 0u;
            const uint32_t s7 = (s5_14_0 != 0 && s5_14_0 != 0xDEADu) ? r32(s5_14_0 + 0x20u) : 0u;
            const uint32_t s7_14 = (s7 != 0 && s7 != 0xDEADu) ? r32(s7 + 0x14u) : 0u;
            const uint32_t s7_o0 = (s7_14 != 0 && s7_14 != 0xDEADu) ? r32(s7_14) : 0u;
            const uint32_t s7_o0_fn = (s7_o0 != 0 && s7_o0 != 0xDEADu) ? r32(s7_o0 + 8u) : 0u;
            static uint32_t s_lastS5 = 0u;
            if (s5 != s_lastS5)
            {
                s_lastS5 = s5;
                const uint32_t gp5d8c = r32(ADD32(GPR_U32(ctx, 28), 0xFFFFA274u));
                const uint32_t trFlag = (s5_14_0 != 0 && s5_14_0 != 0xDEADu) ? (r32(s5_14_0 + 4u) >> 16) & 0xFFu : 0xDEADu;
                const uint32_t s5_10 = r32(s5 + 0x10u);
                const uint32_t act0 = (s5_10 != 0 && s5_10 != 0xDEADu) ? r32(s5_10) : 0u;
                const uint32_t act0_fn = (act0 != 0 && act0 != 0xDEADu) ? r32(act0 + 8u) : 0u;
                const uint32_t tr1 = (s5_14 != 0 && s5_14 != 0xDEADu) ? r32(s5_14 + 4u) : 0u;
                const uint32_t tr1_fn = (tr1 != 0 && tr1 != 0xDEADu) ? r32(tr1 + 0x1cu) : 0u;
                const uint32_t s5_c_e = r32(s5 + 0xCu);
                const uint32_t nTr = (s5_c_e >> 16) & 0xFFFFu;
                const uint32_t s5_c = s5_c_e & 0xFFFFu;
                const uint32_t sp1c = r32(ADD32(GPR_U32(ctx, 29), 0x1Cu));
                const uint32_t tr0_8 = (s5_14_0 != 0 && s5_14_0 != 0xDEADu) ? r32(s5_14_0 + 8u) : 0u;
                const uint32_t tr1_8 = (tr1 != 0 && tr1 != 0xDEADu) ? r32(tr1 + 8u) : 0u;
                const uint32_t v529e20 = r32(0x529e20u);
                const uint32_t s5_1c = r32(s5 + 0x1Cu);
                const uint32_t c_14 = (s5_1c >= 0x100000u && s5_1c < 0x2000000u) ? r32(s5_1c + 0x14u) : 0u;
                const uint32_t c_o0 = (c_14 >= 0x100000u && c_14 < 0x2000000u) ? r32(c_14) : 0u;
                const uint32_t c_fn = (c_o0 >= 0x100000u && c_o0 < 0x2000000u) ? r32(c_o0 + 8u) : 0u;
                RUNTIME_LOG("[2f92f0-state] s5=0x" << std::hex << s5
                            << " s5_c=0x" << s5_c << " nTr=" << std::dec << nTr
                            << " o0_fn=0x" << std::hex << o0_fn
                            << " c_fn=0x" << c_fn
                            << " v529e20=0x" << v529e20
                            << " sp1c=0x" << sp1c
                            << " gp5d8c=0x" << gp5d8c << " tr0_b6=0x" << trFlag
                            << " tr0_8=0x" << tr0_8 << " tr1=0x" << tr1
                            << " tr1_fn=0x" << tr1_fn << " tr1_8=0x" << tr1_8
                            << std::dec << std::endl);
            }
            RUNTIME_LOG("[2f92f0-dump] s5=0x" << std::hex << s5
                        << " s5+8=0x" << s5_8 << " s5_14_0=0x" << s5_14_0 << " fn1c=0x" << fn1c
                        << " s7=0x" << s7 << " s7_o0=0x" << s7_o0 << " s7_o0_fn=0x" << s7_o0_fn << std::dec << std::endl);
        }
        if (g_orig2f92f0) g_orig2f92f0(rdram, ctx, runtime);
    }

    inline PS2Runtime::RecompiledFunction g_orig2fa198 = nullptr;
    inline void wrap2fa198(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        static int s_enterLogs = 0;
        static int s_exitLogs = 0;
        if (g_seen103d40 && s_enterLogs < 5)
        {
            ++s_enterLogs;
            RUNTIME_LOG("[2fa198-probe] ENTER ra=0x" << std::hex << getRegU32(ctx, 31)
                        << " a0=0x" << getRegU32(ctx, 4) << std::dec << std::endl);
        }
        if (g_orig2fa198) g_orig2fa198(rdram, ctx, runtime);
        if (g_seen103d40 && s_exitLogs < 5)
        {
            ++s_exitLogs;
            RUNTIME_LOG("[2fa198-probe] EXIT v0=0x" << std::hex << getRegU32(ctx, 2) << std::dec << std::endl);
        }
    }

    template <uint32_t Addr>
    struct Eae8CalleeProbe
    {
        static inline PS2Runtime::RecompiledFunction s_orig = nullptr;
        static inline int s_logs = 0;

        static void call(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
        {
            const bool logIt = g_seen103d40 && s_logs < 30;
            if (logIt)
            {
                ++s_logs;
                RUNTIME_LOG("[eae8-callee] ENTER 0x" << std::hex << Addr
                            << " ra=0x" << getRegU32(ctx, 31)
                            << " a0=0x" << getRegU32(ctx, 4) << std::dec << std::endl);
            }
            if (s_orig) s_orig(rdram, ctx, runtime);
            if (logIt)
            {
                RUNTIME_LOG("[eae8-callee] EXIT 0x" << std::hex << Addr
                            << " v0=0x" << getRegU32(ctx, 2) << std::dec << std::endl);
            }
        }

        static void install(PS2Runtime &runtime)
        {
            s_orig = runtime.lookupFunction(Addr);
            if (s_orig) runtime.replaceFunction(Addr, &call);
        }
    };

    struct PrimalInflateAvailInBoost
    {
        inline static PS2Runtime::RecompiledFunction s_orig = nullptr;

        static void call(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
        {
            if (!s_orig)
                return;
            const uint32_t ra = getRegU32(ctx, 31);
            const uint32_t zstream = getRegU32(ctx, 4);
            const uint32_t p = zstream & PS2_RAM_MASK;
            const bool isPaletteLoop = (ra == 0x002E1F8Cu);
            const bool isPixelLoop = (ra == 0x002E1FCCu);
            if ((isPaletteLoop || isPixelLoop) && p + 24u <= PS2_RAM_SIZE)
            {
                const uint32_t origAvailIn = *reinterpret_cast<const uint32_t *>(rdram + p + 4u);
                if (origAvailIn > 0u && origAvailIn <= 65536u)
                {
                    *reinterpret_cast<uint32_t *>(rdram + p + 4u) = 0x00100000u;
                }
                auto runToReturn = [&]() {
                    s_orig(rdram, ctx, runtime);
                    uint32_t steps = 0;
                    while (ctx->pc != ra && ctx->pc >= 0x003CAA30u && ctx->pc < 0x003CD600u &&
                           !runtime->isStopRequested() && ++steps < 4096u)
                    {
                        auto contFn = (ctx->pc == 0x003CAA30u) ? s_orig : runtime->lookupFunction(ctx->pc);
                        if (!contFn)
                            break;
                        contFn(rdram, ctx, runtime);
                    }
                };
                runToReturn();
                if (isPaletteLoop)
                {
                    const int32_t ret = static_cast<int32_t>(getRegU32(ctx, 2));
                    const uint32_t availOut = *reinterpret_cast<const uint32_t *>(rdram + p + 20u);
                    if (availOut == 0u || ret != 0)
                    {
                        *reinterpret_cast<uint32_t *>(rdram + p + 20u) = 0u;
                        *reinterpret_cast<uint32_t *>(rdram + p + 4u) = 1u;
                    }
                }
                else if (isPixelLoop)
                {
                    int32_t ret = static_cast<int32_t>(getRegU32(ctx, 2));
                    const uint32_t availOut = *reinterpret_cast<const uint32_t *>(rdram + p + 20u);
                    if (ret == 0 && availOut == 0u && ctx->pc == ra)
                    {
                        *reinterpret_cast<uint32_t *>(rdram + p + 4u) = 0x00100000u;
                        runToReturn();
                        ret = static_cast<int32_t>(getRegU32(ctx, 2));
                    }
                    if (ret != 1)
                    {
                        SET_GPR_S32(ctx, 2, 1);
                    }
                    *reinterpret_cast<uint32_t *>(rdram + p + 4u) = 0u;
                }
                return;
            }
            s_orig(rdram, ctx, runtime);
        }

        static void install(PS2Runtime &runtime)
        {
            s_orig = runtime.lookupFunction(0x003CAA30u);
            if (s_orig)
            {
                runtime.registerFunction(0x003CAA30u, &call);
                for (uint32_t pc : {0x003CAA78u, 0x003CAB14u, 0x003CAB8Cu, 0x003CAD48u, 0x003CAD70u,
                                    0x003CAD94u, 0x003CAEA8u, 0x003CAEB0u, 0x003CAF40u})
                {
                    runtime.registerFunction(pc, s_orig);
                }
            }
            if (auto fn3cb0f0 = runtime.lookupFunction(0x003CB0F0u))
            {
                for (uint32_t pc = 0x003CB0F0u; pc < 0x003CBC9Cu; pc += 4u)
                {
                    runtime.registerFunction(pc, fn3cb0f0);
                }
            }
            if (auto fn2e1c98 = SplitChainBridge<0x002E1C98u, 0x002E2578u>::s_orig
                                    ? SplitChainBridge<0x002E1C98u, 0x002E2578u>::s_orig
                                    : runtime.lookupFunction(0x002E1C98u))
            {
                for (uint32_t pc : {0x002E1CF4u, 0x002E1D1Cu, 0x002E1D48u, 0x002E1D78u, 0x002E1D94u,
                                    0x002E1DA0u, 0x002E1DE4u, 0x002E1EECu, 0x002E1F04u, 0x002E1F18u,
                                    0x002E1F60u, 0x002E1F80u, 0x002E1F8Cu, 0x002E1FC0u, 0x002E1FCCu,
                                    0x002E1FE8u, 0x002E2060u, 0x002E20A0u, 0x002E2140u, 0x002E2150u,
                                    0x002E2210u, 0x002E2220u, 0x002E2244u, 0x002E2290u, 0x002E22A0u,
                                    0x002E22C4u, 0x002E22ECu, 0x002E2320u, 0x002E2350u, 0x002E2444u,
                                    0x002E2478u, 0x002E248Cu, 0x002E249Cu, 0x002E24A4u, 0x002E24F0u,
                                    0x002E253Cu, 0x002E2548u})
                {
                    runtime.registerFunction(pc, fn2e1c98);
                }
            }
            if (auto fn2e1180 = SplitChainBridge<0x002E1180u, 0x002E142Cu>::s_orig
                                    ? SplitChainBridge<0x002E1180u, 0x002E142Cu>::s_orig
                                    : runtime.lookupFunction(0x002E1180u))
            {
                for (uint32_t pc : {0x002E11C4u, 0x002E11DCu, 0x002E1238u, 0x002E1250u, 0x002E1288u,
                                    0x002E1298u, 0x002E12CCu, 0x002E12D8u, 0x002E1308u, 0x002E1374u,
                                    0x002E137Cu, 0x002E1388u, 0x002E139Cu, 0x002E13C0u, 0x002E13D4u,
                                    0x002E13E4u})
                {
                    runtime.registerFunction(pc, fn2e1180);
                }
            }
        }
    };

    struct PrimalBezierTessellationGuard
    {
        static inline PS2Runtime::RecompiledFunction s_orig2e83f0 = nullptr;
        static inline PS2Runtime::RecompiledFunction s_orig2e8240 = nullptr;
        static inline PS2Runtime::RecompiledFunction s_orig2e6948 = nullptr;
        static inline PS2Runtime::RecompiledFunction s_orig2e8178 = nullptr;
        static inline PS2Runtime::RecompiledFunction s_orig2e7d18 = nullptr;

        static void restoreVf0(R5900Context *ctx) noexcept
        {
            ctx->vu0_vf[0] = _mm_set_ps(1.0f, 0.0f, 0.0f, 0.0f);
        }

        static uint32_t readCurveCount(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime, uint32_t a0) noexcept
        {
            if (a0 == 0u) return 0u;
            const uint32_t phys = a0 & 0x1FFFFFFFu;
            if (phys >= 0x1000u && phys + 16u <= PS2_RAM_SIZE)
            {
                return *reinterpret_cast<const uint32_t *>(rdram + phys + 12u);
            }
            if (PS2Runtime::isSpecialAddress(a0))
            {
                return READ32(ADD32(a0, 12u));
            }
            return 0u;
        }

        static void hook2e83f0(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
        {
            restoreVf0(ctx);
            if (s_orig2e83f0) s_orig2e83f0(rdram, ctx, runtime);
            restoreVf0(ctx);
        }

        static void hook2e8240(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
        {
            restoreVf0(ctx);
            if (s_orig2e8240) s_orig2e8240(rdram, ctx, runtime);
            restoreVf0(ctx);
        }

        static void hook2e6948(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
        {
            restoreVf0(ctx);
            const uint32_t a0 = getRegU32(ctx, 4);
            const uint32_t a1 = getRegU32(ctx, 5);
            const uint32_t count = readCurveCount(rdram, ctx, runtime, a0);
            thread_local uint32_t s_lastA0 = 0u;
            thread_local uint32_t s_lastA1 = 0xFFFFFFFFu;
            thread_local uint32_t s_samePairHits = 0u;
            if (a0 == s_lastA0 && a1 == s_lastA1)
            {
                ++s_samePairHits;
            }
            else
            {
                s_lastA0 = a0;
                s_lastA1 = a1;
                s_samePairHits = 1u;
            }
            if (count >= 64u || s_samePairHits > 4u)
            {
                static int s_guardLog = 0;
                if (s_guardLog < 8)
                {
                    ++s_guardLog;
                    RUNTIME_LOG("[bezier-guard] skip split 0x2e6948 a0=0x" << std::hex << a0
                                << " a1=" << std::dec << a1 << " count=" << count
                                << " hits=" << s_samePairHits << std::endl);
                }
                s_samePairHits = 0u;
                SET_GPR_U32(ctx, 2, 0u);
                ctx->pc = getRegU32(ctx, 31);
                return;
            }
            if (s_orig2e6948) s_orig2e6948(rdram, ctx, runtime);
            restoreVf0(ctx);
        }

        static void hook2e8178(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
        {
            restoreVf0(ctx);
            const uint32_t a0 = getRegU32(ctx, 4);
            const uint32_t a1 = getRegU32(ctx, 5);
            const uint32_t count = readCurveCount(rdram, ctx, runtime, a0);
            thread_local uint32_t s_lastA0 = 0u;
            thread_local uint32_t s_lastA1 = 0xFFFFFFFFu;
            thread_local uint32_t s_samePairHits = 0u;
            if (a0 == s_lastA0 && a1 == s_lastA1)
            {
                ++s_samePairHits;
            }
            else
            {
                s_lastA0 = a0;
                s_lastA1 = a1;
                s_samePairHits = 1u;
            }
            if (count >= 64u || s_samePairHits > 4u)
            {
                static int s_guardLog = 0;
                if (s_guardLog < 8)
                {
                    ++s_guardLog;
                    RUNTIME_LOG("[bezier-guard] skip split 0x2e8178 a0=0x" << std::hex << a0
                                << " a1=" << std::dec << a1 << " count=" << count
                                << " hits=" << s_samePairHits << std::endl);
                }
                s_samePairHits = 0u;
                SET_GPR_U32(ctx, 2, 1u);
                ctx->pc = getRegU32(ctx, 31);
                return;
            }
            if (s_orig2e8178) s_orig2e8178(rdram, ctx, runtime);
            restoreVf0(ctx);
        }

        static void hook2e7d18(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
        {
            restoreVf0(ctx);
            const uint32_t a0 = getRegU32(ctx, 4);
            const uint32_t count = readCurveCount(rdram, ctx, runtime, a0);
            thread_local uint32_t s_lastA0 = 0u;
            thread_local uint32_t s_lastCount = 0u;
            thread_local uint32_t s_streak = 0u;
            if (a0 == s_lastA0 && count == s_lastCount)
            {
                ++s_streak;
            }
            else
            {
                s_lastA0 = a0;
                s_lastCount = count;
                s_streak = 1u;
            }
            if (s_streak > 64u)
            {
                static int s_guardLog = 0;
                if (s_guardLog < 8)
                {
                    ++s_guardLog;
                    RUNTIME_LOG("[bezier-guard] break loop 0x2e7d18 a0=0x" << std::hex << a0
                                << " count=" << std::dec << count << " streak=" << s_streak << std::endl);
                }
                s_streak = 0u;
                SET_GPR_U32(ctx, 2, 0u);
                ctx->pc = getRegU32(ctx, 31);
                return;
            }
            if (s_orig2e7d18) s_orig2e7d18(rdram, ctx, runtime);
            restoreVf0(ctx);
        }

        static void install(PS2Runtime &runtime)
        {
            s_orig2e83f0 = runtime.lookupFunction(0x002E83F0u);
            if (s_orig2e83f0) runtime.replaceFunction(0x002E83F0u, &hook2e83f0);
            s_orig2e8240 = runtime.lookupFunction(0x002E8240u);
            if (s_orig2e8240) runtime.replaceFunction(0x002E8240u, &hook2e8240);
            s_orig2e6948 = runtime.lookupFunction(0x002E6948u);
            if (s_orig2e6948) runtime.replaceFunction(0x002E6948u, &hook2e6948);
            s_orig2e8178 = runtime.lookupFunction(0x002E8178u);
            if (s_orig2e8178) runtime.replaceFunction(0x002E8178u, &hook2e8178);
            s_orig2e7d18 = runtime.lookupFunction(0x002E7D18u);
            if (s_orig2e7d18) runtime.replaceFunction(0x002E7D18u, &hook2e7d18);
        }
    };

    struct PrimalPackedVtablesAndHeapGuard
    {
        template <uint32_t EntryPc>
        static void stub3b2fa8(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
        {
            const uint32_t savedSp = getRegU32(ctx, 29);
            const uint32_t savedRa = getRegU32(ctx, 31);
            const __m128i savedS0 = GPR_VEC(ctx, 16);
            const __m128i savedS1 = GPR_VEC(ctx, 17);
            const uint32_t a0 = getRegU32(ctx, 4);
            const uint32_t a1 = getRegU32(ctx, 5);
            SET_GPR_S32(ctx, 29, static_cast<int32_t>(savedSp - 0x30u));
            WRITE128(savedSp - 0x30u, savedS0);
            WRITE128(savedSp - 0x20u, savedS1);
            WRITE128(savedSp - 0x10u, GPR_VEC(ctx, 31));
            SET_GPR_U64(ctx, 17, a0);
            SET_GPR_U64(ctx, 16, a1);
            WRITE32(ADD32(a0, 24u), 0x0044B948u);
            SET_GPR_S32(ctx, 5, 2);
            SET_GPR_U32(ctx, 31, EntryPc + 0x2Cu);
            ctx->pc = 0x00286BB8u;
            if (!runtime->dispatchGuestBranch(rdram, ctx, 0x00286BB8u, EntryPc + 0x24u, EntryPc + 0x2Cu,
                                              PS2Runtime::GuestBranchKind::DirectCall, "JAL"))
                return;
            if ((a1 & 1u) != 0u)
            {
                SET_GPR_U64(ctx, 4, a0);
                SET_GPR_U32(ctx, 31, EntryPc + 0x40u);
                ctx->pc = 0x0028A4A8u;
                if (!runtime->dispatchGuestBranch(rdram, ctx, 0x0028A4A8u, EntryPc + 0x38u, EntryPc + 0x40u,
                                                  PS2Runtime::GuestBranchKind::DirectCall, "JAL"))
                    return;
            }
            SET_GPR_VEC(ctx, 16, savedS0);
            SET_GPR_VEC(ctx, 17, savedS1);
            SET_GPR_VEC(ctx, 31, READ128(savedSp - 0x10u));
            SET_GPR_S32(ctx, 29, static_cast<int32_t>(savedSp));
            ctx->pc = savedRa;
        }

        static void stub3b3058(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
        {
            const uint32_t savedSp = getRegU32(ctx, 29);
            const uint32_t savedRa = getRegU32(ctx, 31);
            SET_GPR_S32(ctx, 29, static_cast<int32_t>(savedSp - 0x10u));
            WRITE128(savedSp - 0x10u, GPR_VEC(ctx, 31));
            SET_GPR_U64(ctx, 4, GPR_U64(ctx, 5));
            SET_GPR_U64(ctx, 5, GPR_U64(ctx, 6));
            SET_GPR_U32(ctx, 31, 0x003B306Cu);
            ctx->pc = 0x003B2958u;
            if (!runtime->dispatchGuestBranch(rdram, ctx, 0x003B2958u, 0x003B3064u, 0x003B306Cu,
                                              PS2Runtime::GuestBranchKind::DirectCall, "JAL"))
                return;
            SET_GPR_VEC(ctx, 31, READ128(savedSp - 0x10u));
            SET_GPR_S32(ctx, 29, static_cast<int32_t>(savedSp));
            ctx->pc = savedRa;
        }

        static void stub3b3078(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
        {
            const uint32_t savedSp = getRegU32(ctx, 29);
            const uint32_t savedRa = getRegU32(ctx, 31);
            const uint32_t a1 = getRegU32(ctx, 5);
            SET_GPR_S32(ctx, 29, static_cast<int32_t>(savedSp - 0x10u));
            WRITE128(savedSp - 0x10u, GPR_VEC(ctx, 31));
            SET_GPR_U64(ctx, 4, GPR_U64(ctx, 5));
            if (a1 != 0u)
            {
                SET_GPR_S32(ctx, 5, 3);
                SET_GPR_U32(ctx, 31, 0x003B3090u);
                ctx->pc = 0x003B2748u;
                if (!runtime->dispatchGuestBranch(rdram, ctx, 0x003B2748u, 0x003B3088u, 0x003B3090u,
                                                  PS2Runtime::GuestBranchKind::DirectCall, "JAL"))
                    return;
            }
            SET_GPR_VEC(ctx, 31, READ128(savedSp - 0x10u));
            SET_GPR_S32(ctx, 29, static_cast<int32_t>(savedSp));
            ctx->pc = savedRa;
        }

        static void stub2e5cd8(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
        {
            const uint32_t savedSp = getRegU32(ctx, 29);
            const uint32_t savedRa = getRegU32(ctx, 31);
            const uint32_t a1 = getRegU32(ctx, 5);
            SET_GPR_S32(ctx, 29, static_cast<int32_t>(savedSp - 0x10u));
            WRITE128(savedSp - 0x10u, GPR_VEC(ctx, 31));
            SET_GPR_U64(ctx, 4, GPR_U64(ctx, 5));
            if (a1 != 0u)
            {
                SET_GPR_S32(ctx, 5, 3);
                SET_GPR_U32(ctx, 31, 0x002E5CF4u);
                ctx->pc = 0x002E01B0u;
                if (!runtime->dispatchGuestBranch(rdram, ctx, 0x002E01B0u, 0x002E5CECu, 0x002E5CF4u,
                                                  PS2Runtime::GuestBranchKind::DirectCall, "JAL"))
                    return;
            }
            SET_GPR_VEC(ctx, 31, READ128(savedSp - 0x10u));
            SET_GPR_S32(ctx, 29, static_cast<int32_t>(savedSp));
            ctx->pc = savedRa;
        }

        static void stub3b30a0(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
        {
            const uint32_t savedSp = getRegU32(ctx, 29);
            const uint32_t savedRa = getRegU32(ctx, 31);
            SET_GPR_S32(ctx, 29, static_cast<int32_t>(savedSp - 0x10u));
            WRITE128(savedSp - 0x10u, GPR_VEC(ctx, 31));
            SET_GPR_U64(ctx, 4, GPR_U64(ctx, 5));
            SET_GPR_U64(ctx, 5, GPR_U64(ctx, 6));
            SET_GPR_U32(ctx, 31, 0x003B30B4u);
            ctx->pc = 0x003B2530u;
            if (!runtime->dispatchGuestBranch(rdram, ctx, 0x003B2530u, 0x003B30ACu, 0x003B30B4u,
                                              PS2Runtime::GuestBranchKind::DirectCall, "JAL"))
                return;
            SET_GPR_VEC(ctx, 31, READ128(savedSp - 0x10u));
            SET_GPR_S32(ctx, 29, static_cast<int32_t>(savedSp));
            ctx->pc = savedRa;
        }

        static void stub3b30c0(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
        {
            const uint32_t savedSp = getRegU32(ctx, 29);
            const uint32_t savedRa = getRegU32(ctx, 31);
            const uint32_t a1 = getRegU32(ctx, 5);
            SET_GPR_S32(ctx, 29, static_cast<int32_t>(savedSp - 0x10u));
            WRITE128(savedSp - 0x10u, GPR_VEC(ctx, 31));
            SET_GPR_U64(ctx, 4, GPR_U64(ctx, 5));
            if (a1 != 0u)
            {
                SET_GPR_S32(ctx, 5, 3);
                SET_GPR_U32(ctx, 31, 0x003B30D8u);
                ctx->pc = 0x003B2480u;
                if (!runtime->dispatchGuestBranch(rdram, ctx, 0x003B2480u, 0x003B30D0u, 0x003B30D8u,
                                                  PS2Runtime::GuestBranchKind::DirectCall, "JAL"))
                    return;
            }
            SET_GPR_VEC(ctx, 31, READ128(savedSp - 0x10u));
            SET_GPR_S32(ctx, 29, static_cast<int32_t>(savedSp));
            ctx->pc = savedRa;
        }

        static void stub10bd38(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
        {
            const uint32_t a0 = getRegU32(ctx, 4);
            SET_GPR_S32(ctx, 2, static_cast<int32_t>(READ32(a0)));
            ctx->pc = 0x0010BD3Cu;
            if (auto fn10bd3c = runtime->lookupFunction(0x0010BD3Cu))
            {
                fn10bd3c(rdram, ctx, runtime);
            }
            else
            {
                ctx->pc = getRegU32(ctx, 31);
            }
        }

        static void updateHeapStats28b908(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime,
                                        uint32_t poolAddr, uint32_t forceFlag, int depth = 0)
        {
            if (poolAddr < 0x00100000u || poolAddr >= 0x02000000u || depth > 8)
            {
                return;
            }
            const uint32_t subPool = READ32(ADD32(poolAddr, 36u));
            if (subPool != 0u && subPool != poolAddr)
            {
                updateHeapStats28b908(rdram, ctx, runtime, subPool, forceFlag, depth + 1);
            }
            const uint32_t curFrame = FAST_READ32(0x00488444u);
            const uint32_t lastFrame = READ32(ADD32(poolAddr, 52u));
            if (curFrame == lastFrame && forceFlag == 0u)
            {
                return;
            }
            WRITE32(ADD32(poolAddr, 52u), curFrame);
            // Skip 0x28b95c..0x28b9a4 (dead 5-nop retail debug assert walk over free-list buckets)
            uint32_t a1 = READ32(ADD32(poolAddr, 12u));
            uint32_t t1 = 0u; // +0x3C (60)
            uint32_t a2 = 0u; // +0x48 (72)
            uint32_t a3 = 0u; // +0x40 (64)
            uint32_t t0 = 0u; // +0x44 (68)
            uint32_t guard = 0u;
            while (a1 >= 0x00100000u && a1 < 0x02000000u && guard++ < 65536u)
            {
                const int32_t v1 = static_cast<int32_t>(READ32(ADD32(a1, 16u)));
                const int32_t v0 = (v1 > 0) ? v1 : -static_cast<int32_t>(static_cast<uint32_t>(v1) & 0x07FFFFFFu);
                if (v0 > 0)
                {
                    t1 = ADD32(t1, static_cast<uint32_t>(v0));
                    a2 = ADD32(a2, 1u);
                }
                else
                {
                    a3 = SUB32(a3, static_cast<uint32_t>(v0));
                    t0 = ADD32(t0, 1u);
                }
                const uint32_t next = READ32(ADD32(a1, 4u));
                if (next == 0u || next == a1)
                {
                    break;
                }
                a1 = next;
            }
            WRITE32(ADD32(poolAddr, 72u), a2);
            WRITE32(ADD32(poolAddr, 60u), t1);
            WRITE32(ADD32(poolAddr, 64u), a3);
            WRITE32(ADD32(poolAddr, 68u), t0);
        }

        static void override28b908(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
        {
            updateHeapStats28b908(rdram, ctx, runtime, getRegU32(ctx, 4), getRegU32(ctx, 5), 0);
            ctx->pc = getRegU32(ctx, 31);
        }

        static inline PS2Runtime::RecompiledFunction s_orig3eb210 = nullptr;
        static inline PS2Runtime::RecompiledFunction s_orig3a6120 = nullptr;
        static inline PS2Runtime::RecompiledFunction s_orig3a77d8 = nullptr;

        static void wrap3a77d8(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
        {
            static int s_badLogs = 0;
            const uint32_t a0 = getRegU32(ctx, 4);
            if (a0 < 0x00100000u && s_badLogs < 8)
            {
                ++s_badLogs;
                RUNTIME_LOG("[3a77d8-BAD] #" << s_badLogs << " ra=0x" << std::hex << getRegU32(ctx, 31)
                            << " a0=0x" << a0 << std::dec << std::endl);
            }
            if (s_orig3a77d8) s_orig3a77d8(rdram, ctx, runtime);
        }

        static void wrap3eb210(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
        {
            static int s_logs = 0;
            const bool logIt = (s_logs < 8);
            if (logIt)
            {
                ++s_logs;
                const uint32_t a0 = getRegU32(ctx, 4);
                uint32_t s4 = 0u, n = 0u;
                (void)primal_sif_rpc::readGuestU32(rdram, ADD32(a0, 64u), s4);
                if (s4 != 0u) (void)primal_sif_rpc::readGuestU32(rdram, ADD32(s4, 72u), n);
                RUNTIME_LOG("[3eb210-probe] #" << s_logs << " ra=0x" << std::hex << getRegU32(ctx, 31)
                            << " a0=0x" << a0 << " a1=0x" << getRegU32(ctx, 5)
                            << " a2=0x" << getRegU32(ctx, 6) << " a3=0x" << getRegU32(ctx, 7)
                            << " s4=0x" << s4 << " *(s4+0x48)=0x" << n << std::dec << std::endl);
            }
            if (s_orig3eb210) s_orig3eb210(rdram, ctx, runtime);
            if (logIt)
            {
                RUNTIME_LOG("[3eb210-probe] #" << s_logs << " ret=0x" << std::hex << getRegU32(ctx, 2) << std::dec << std::endl);
            }
        }

        static void wrap3a6120(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
        {
            static int s_badLogs = 0;
            const uint32_t a0 = getRegU32(ctx, 4);
            if (a0 < 0x00100000u && s_badLogs < 8)
            {
                ++s_badLogs;
                RUNTIME_LOG("[3a6120-BAD] #" << s_badLogs << " ra=0x" << std::hex << getRegU32(ctx, 31)
                            << " a0=0x" << a0 << std::dec << std::endl);
            }
            if (s_orig3a6120) s_orig3a6120(rdram, ctx, runtime);
        }

        template <uint32_t Addr>
        static inline PS2Runtime::RecompiledFunction s_origWatch47 = nullptr;

        template <uint32_t Addr>
        static void wrapWatch47(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
        {
            uint32_t b1 = 0u, a1 = 0u, b2 = 0u, a2 = 0u;
            (void)primal_sif_rpc::readGuestU32(rdram, 0x004729D0u, b1);
            (void)primal_sif_rpc::readGuestU32(rdram, 0x004DF3B0u, b2);
            if (s_origWatch47<Addr>) s_origWatch47<Addr>(rdram, ctx, runtime);
            (void)primal_sif_rpc::readGuestU32(rdram, 0x004729D0u, a1);
            (void)primal_sif_rpc::readGuestU32(rdram, 0x004DF3B0u, a2);
            if ((b1 != 0u && a1 == 0u) || (b2 != 0u && a2 == 0u))
            {
                RUNTIME_LOG("[4729d0-WIPE] func=0x" << std::hex << Addr
                            << " b1=0x" << b1 << " a1=0x" << a1
                            << " b2=0x" << b2 << " a2=0x" << a2
                            << " ra=0x" << getRegU32(ctx, 31)
                            << " a0=0x" << getRegU32(ctx, 4)
                            << " a1r=0x" << getRegU32(ctx, 5)
                            << " a2r=0x" << getRegU32(ctx, 6) << std::dec << std::endl);
            }
        }

        static void install(PS2Runtime &runtime)
        {
            runtime.registerFunction(0x003B2FA8u, &stub3b2fa8<0x003B2FA8u>);
            runtime.registerFunction(0x003B3000u, &stub3b2fa8<0x003B3000u>);
            runtime.registerFunction(0x003B3058u, &stub3b3058);
            runtime.registerFunction(0x003B3078u, &stub3b3078);
            runtime.registerFunction(0x003B30A0u, &stub3b30a0);
            runtime.registerFunction(0x003B30C0u, &stub3b30c0);
            runtime.registerFunction(0x0010BD38u, &stub10bd38);
            runtime.registerFunction(0x002E5C60u, &stub3b2fa8<0x002E5C60u>);
            runtime.registerFunction(0x002E5CD8u, &stub2e5cd8);
            runtime.registerFunction(0x0028B908u, &override28b908);
            if (auto fn3a66f0 = runtime.lookupFunction(0x003A66F0u))
            {
                for (uint32_t pc = 0x003A66F4u; pc < 0x003A6DF0u; pc += 4u)
                {
                    runtime.registerFunction(pc, fn3a66f0);
                }
            }
            // #92 Monolithic heap allocator interior slot repairs (0x28a2a0..0x28ba50)
            if (auto fn28a558 = runtime.lookupFunction(0x0028A558u))
            {
                for (uint32_t pc = 0x0028A55Cu; pc < 0x0028A6FCu; pc += 4u)
                    runtime.registerFunction(pc, fn28a558);
            }
            if (auto fn28a700 = runtime.lookupFunction(0x0028A700u))
            {
                for (uint32_t pc = 0x0028A704u; pc < 0x0028A798u; pc += 4u)
                    runtime.registerFunction(pc, fn28a700);
            }
            if (auto fn28aba0 = runtime.lookupFunction(0x0028ABA0u))
            {
                for (uint32_t pc = 0x0028ABA4u; pc < 0x0028AC44u; pc += 4u)
                    runtime.registerFunction(pc, fn28aba0);
            }
            if (auto fn28ae20 = runtime.lookupFunction(0x0028AE20u))
            {
                for (uint32_t pc = 0x0028AE24u; pc < 0x0028AFE0u; pc += 4u)
                    runtime.registerFunction(pc, fn28ae20);
            }
            if (auto fn = runtime.lookupFunction(0x0028A3A8u)) runtime.registerFunction(0x0028A3F0u, fn);
            if (auto fn = runtime.lookupFunction(0x0028A840u)) runtime.registerFunction(0x0028A8C4u, fn);
            if (auto fn = runtime.lookupFunction(0x0028ACB8u)) runtime.registerFunction(0x0028ACC8u, fn);
            if (auto fn = runtime.lookupFunction(0x0028B190u))
            {
                runtime.registerFunction(0x0028B1D0u, fn);
                runtime.registerFunction(0x0028B258u, fn);
                runtime.registerFunction(0x0028B298u, fn);
            }
            if (auto fn = runtime.lookupFunction(0x0028B368u)) runtime.registerFunction(0x0028B3E0u, fn);
            if (auto fn = runtime.lookupFunction(0x0028B438u)) runtime.registerFunction(0x0028B4A8u, fn);
            if (auto fn = runtime.lookupFunction(0x0028B550u)) runtime.registerFunction(0x0028B560u, fn);
            if (auto fn = runtime.lookupFunction(0x0028B818u)) runtime.registerFunction(0x0028B83Cu, fn);
            if (auto fn = runtime.lookupFunction(0x0028B850u)) runtime.registerFunction(0x0028B874u, fn);
            if (auto f = runtime.lookupFunction(0x0032B8B0u)) { s_origWatch47<0x0032B8B0u> = f; runtime.replaceFunction(0x0032B8B0u, &wrapWatch47<0x0032B8B0u>); }
            if (auto f = runtime.lookupFunction(0x0032C7A0u)) { s_origWatch47<0x0032C7A0u> = f; runtime.replaceFunction(0x0032C7A0u, &wrapWatch47<0x0032C7A0u>); }
            if (auto f = runtime.lookupFunction(0x003EB180u)) { s_origWatch47<0x003EB180u> = f; runtime.replaceFunction(0x003EB180u, &wrapWatch47<0x003EB180u>); }
            if (auto f = runtime.lookupFunction(0x003EC140u)) { s_origWatch47<0x003EC140u> = f; runtime.replaceFunction(0x003EC140u, &wrapWatch47<0x003EC140u>); }
            if (auto f = runtime.lookupFunction(0x003C4808u)) { s_origWatch47<0x003C4808u> = f; runtime.replaceFunction(0x003C4808u, &wrapWatch47<0x003C4808u>); }
            if (auto f = runtime.lookupFunction(0x0032B054u)) { s_origWatch47<0x0032B054u> = f; runtime.replaceFunction(0x0032B054u, &wrapWatch47<0x0032B054u>); }
            if (auto fn28afe0 = SplitChainBridge<0x0028AFE0u, 0x0028B18Cu>::s_orig)
            {
                for (uint32_t pc = 0x0028AFE4u; pc < 0x0028B18Cu; pc += 4u)
                {
                    runtime.registerFunction(pc, fn28afe0);
                }
            }
            if (auto fn28a9d8 = SplitChainBridge<0x0028A9D8u, 0x0028AB9Cu>::s_orig)
            {
                for (uint32_t pc = 0x0028A9DCu; pc < 0x0028AB9Cu; pc += 4u)
                {
                    runtime.registerFunction(pc, fn28a9d8);
                }
            }
            if (auto fn3eb210 = runtime.lookupFunction(0x003EB210u))
            {
                s_orig3eb210 = fn3eb210;
                runtime.replaceFunction(0x003EB210u, &wrap3eb210);
                for (uint32_t pc = 0x003EB214u; pc < 0x003EB508u; pc += 4u)
                {
                    runtime.registerFunction(pc, fn3eb210);
                }
            }
            s_orig3a6120 = runtime.lookupFunction(0x003A6120u);
            if (s_orig3a6120) runtime.replaceFunction(0x003A6120u, &wrap3a6120);
            s_orig3a77d8 = runtime.lookupFunction(0x003A77D8u);
            if (s_orig3a77d8) runtime.replaceFunction(0x003A77D8u, &wrap3a77d8);
            SplitChainBridge<0x0032BA90u, 0x0032BEECu>::install(runtime);
            RUNTIME_LOG("[game_overrides] packed vtable methods (0x3b2fa8..0x3b30c0, 0x10bd38) + heap guard (0x28b908/0x28afe0/0x28a9d8/0x3eb210) installed" << std::endl);
        }
    };

    inline void wrap103d40(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        static int s_callIdx = 0;
        const int idx = s_callIdx++;
        if (idx == 0) g_seen103d40 = true;
        if (idx < 10)
        {
            RUNTIME_LOG("[scene-probe] ENTER #" << idx << " 0x103d40 ra=0x" << std::hex << getRegU32(ctx, 31)
                        << " a0=0x" << getRegU32(ctx, 4) << std::dec << std::endl);
        }
        if (g_orig103d40) g_orig103d40(rdram, ctx, runtime);
        if (idx < 10)
        {
            RUNTIME_LOG("[scene-probe] EXIT #" << idx << " 0x103d40 v0=0x" << std::hex << getRegU32(ctx, 2) << std::dec << std::endl);
        }
    }

    inline PS2Runtime::RecompiledFunction g_orig104198 = nullptr;
    inline void wrap104198(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        static int s_callIdx = 0;
        const int idx = s_callIdx++;
        if (idx < 5)
        {
            RUNTIME_LOG("[scene-probe] ENTER #" << idx << " 0x104198 ra=0x" << std::hex << getRegU32(ctx, 31)
                        << " a0=0x" << getRegU32(ctx, 4) << std::dec << std::endl);
        }
        {
            using clock = std::chrono::steady_clock;
            static auto s_fpsLast = clock::now();
            static uint64_t s_fpsCalls = 0;
            ++s_fpsCalls;
            const auto now = clock::now();
            const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - s_fpsLast).count();
            if (ms >= 1000)
            {
                s_fpsLast = now;
                RUNTIME_LOG("[104198-fps] calls=" << s_fpsCalls << " in " << ms << "ms" << std::endl);
                s_fpsCalls = 0;
            }
        }
        if (g_orig104198) g_orig104198(rdram, ctx, runtime);
    }

    template <uint32_t Addr>
    struct HeartbeatProbe
    {
        static inline PS2Runtime::RecompiledFunction s_orig = nullptr;

        static void call(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
        {
            using clock = std::chrono::steady_clock;
            static auto s_last = clock::now();
            static uint64_t s_calls = 0;
            static bool s_first = true;
            if (s_first)
            {
                s_first = false;
                uint32_t sp20 = 0;
                (void)primal_sif_rpc::readGuestU32(rdram, getRegU32(ctx, 29) + 0x20u, sp20);
                RUNTIME_LOG("[hb-0x" << std::hex << Addr << "] FIRST ra=0x" << getRegU32(ctx, 31)
                            << " sp+20=0x" << sp20 << std::dec << std::endl);
            }
            ++s_calls;
            const auto now = clock::now();
            const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - s_last).count();
            if (ms >= 1000)
            {
                s_last = now;
                RUNTIME_LOG("[hb-0x" << std::hex << Addr << "] calls=" << std::dec << s_calls
                            << " in " << ms << "ms ra=0x" << std::hex << getRegU32(ctx, 31) << std::dec << std::endl);
                s_calls = 0;
            }
            if (s_orig) s_orig(rdram, ctx, runtime);
        }

        static void install(PS2Runtime &runtime)
        {
            s_orig = runtime.lookupFunction(Addr);
            if (s_orig) runtime.replaceFunction(Addr, &call);
        }
    };

    // Log scene chunk jobs queued by FUN_0032a9e0: name at job+0x38, state at job+0x34.
    inline PS2Runtime::RecompiledFunction g_orig32a9e0 = nullptr;
    inline int g_ioThreadId = 0;
    inline void ret1stub(uint8_t *, R5900Context *ctx, PS2Runtime *) { SET_GPR_U64(ctx, 2, 1); }
    inline PS2Runtime::RecompiledFunction g_orig2f73a4b = nullptr;
    inline PS2Runtime::RecompiledFunction g_orig2f73a4 = nullptr;
    inline void wrap2f73a4(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t s0 = getRegU32(ctx, 16);
        uint32_t vt = 0, f10 = 0;
        (void)primal_sif_rpc::readGuestU32(rdram, s0 + 0x1Cu, vt);
        (void)primal_sif_rpc::readGuestU32(rdram, vt + 0x10u, f10);
        static int n = 0;
        if (n < 8)
        {
            ++n;
            RUNTIME_LOG("[loop2f73a4] #" << n << " s0=0x" << std::hex << s0
                        << " vt=0x" << vt << " vtbl+0x10=0x" << f10 << std::dec << std::endl);
        }
        if (g_orig2f73a4) g_orig2f73a4(rdram, ctx, runtime);
    }

    inline PS2Runtime::RecompiledFunction g_orig2fa478 = nullptr;
    inline void wrap2fa478(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t entryPc = ctx->pc;
        const uint32_t s1 = getRegU32(ctx, 17);
        const uint32_t s2 = getRegU32(ctx, 18);
        const uint32_t s3 = getRegU32(ctx, 19);
        const uint32_t s5 = getRegU32(ctx, 21);
        uint32_t s0Ptr = 0, predFn = 0, flags = 0;
        const bool willRun = (entryPc == 0x002FA478u && (s1 - 1u) != s3);
        if (willRun)
        {
            (void)primal_sif_rpc::readGuestU32(rdram, s2, s0Ptr);
            (void)primal_sif_rpc::readGuestU32(rdram, s0Ptr + 0x1Cu, predFn);
            (void)primal_sif_rpc::readGuestU32(rdram, s0Ptr + 0x08u, flags);
        }
        if (g_orig2fa478) g_orig2fa478(rdram, ctx, runtime);
        if (willRun)
        {
            const uint32_t c298 = g_cnt298200.load(std::memory_order_relaxed);
            static int s_postLog = 0;
            static uint32_t s_lastPred = 0, s_lastS5 = 0;
            const uint32_t v1 = getRegU32(ctx, 3);
            const uint32_t inv = (flags >> 1) & 1u;
            const bool interesting = (c298 >= 80u && s_postLog < 30) || (s5 != s_lastS5) || (predFn != s_lastPred && s_postLog < 60);
            if (interesting && (c298 >= 60u || s5 != s_lastS5))
            {
                if (c298 >= 80u) ++s_postLog;
                s_lastS5 = s5;
                s_lastPred = predFn;
                RUNTIME_LOG("[smd-trans] c298=" << std::dec << c298
                            << " s5=0x" << std::hex << s5
                            << " s0=0x" << s0Ptr
                            << " predFn=0x" << predFn
                            << " inv=" << std::dec << inv
                            << " v1=" << v1
                            << " nextPc=0x" << std::hex << ctx->pc << std::dec << std::endl);
            }
        }
    }

    inline void stub32a1f0(uint8_t *rdram, R5900Context *ctx, PS2Runtime *)
    {
        const uint32_t s1 = getRegU32(ctx, 17);
        const uint32_t v1 = getRegU32(ctx, 3);
        (void)primal_sif_rpc::writeGuestU32(rdram, s1 + 0x30u, v1);
        ctx->pc = 0x0032A944u;
    }

    inline void stub32a248(uint8_t *rdram, R5900Context *ctx, PS2Runtime *)
    {
        const uint32_t s1 = getRegU32(ctx, 17);
        const uint32_t v0 = getRegU32(ctx, 2);
        (void)primal_sif_rpc::writeGuestU32(rdram, s1 + 0x30u, v0);
        ctx->pc = 0x0032A944u;
    }
    inline PS2Runtime::RecompiledFunction g_orig282640 = nullptr;
    inline void wrap282640(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t a0 = getRegU32(ctx, 4), a1 = getRegU32(ctx, 5), v1 = getRegU32(ctx, 3);
        uint32_t val = 0; (void)primal_sif_rpc::readGuestU32(rdram, a0, val);
        static int n = 0; if (n < 8) { ++n; RUNTIME_LOG("[loop282640] #" << n << " ra=0x" << std::hex << getRegU32(ctx, 31) << " a0=0x" << a0 << " a1=0x" << a1 << " v1=0x" << v1 << " *(a0)=0x" << val << std::dec << std::endl); }
        { static const bool ub = [] { const char *e = std::getenv("PS2_UNBLOCK_LOOP"); return e != nullptr && e[0] == '1'; }(); if (ub && a0 == 0u) SET_GPR_U64(ctx, 4, 0x004F7110u); }
        if (g_orig282640) g_orig282640(rdram, ctx, runtime);
    }
    inline void wrap32a9e0(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t job = getRegU32(ctx, 4);
        auto rd32 = [&](uint32_t a, uint32_t &v) -> bool {
            return primal_sif_rpc::readGuestU32(rdram, a, v);
        };
        uint32_t stBefore = 0, stAfter = 0;
        rd32(job + 0x34u, stBefore);
        if (g_orig32a9e0) g_orig32a9e0(rdram, ctx, runtime);
        { static const bool ft = [] { const char *e = std::getenv("PS2_FORCE_IO_THREAD"); return e != nullptr && e[0] == '1'; }(); static bool done = false; if (ft && !done) { done = true; EeScheduler &ee = runtime->eeScheduler(); EeThreadCreateParams p; p.entry = 0x0032CF20u; p.stack = 0x01FF0000u; p.stackSize = 0x8000u; p.gp = getRegU32(ctx, 28); p.priority = 5; int id = ee.createThread(p); g_ioThreadId = id; int sr = (id > 0) ? ee.startThread(id, 1u, *ctx, false) : -1; RUNTIME_LOG("[forcethread] create id=" << id << " start=" << sr << " entry=0x32cf20" << std::endl); } }
        rd32(job + 0x34u, stAfter);
        char name[33] = {};
        for (int i = 0; i < 32; ++i)
        {
            uint32_t w = 0;
            if (!rd32(job + 0x38u + i * 4u, w)) break;
            name[i * 4] = w & 0xFF; name[i * 4 + 1] = (w >> 8) & 0xFF;
            name[i * 4 + 2] = (w >> 16) & 0xFF; name[i * 4 + 3] = (w >> 24) & 0xFF;
            if (name[i * 4] == 0) break;
        }
        static int s_n = 0;
        if (s_n < 40)
        {
            ++s_n;
            RUNTIME_LOG("[job32a9e0] #" << s_n << " job=0x" << std::hex << job << " name=\"" << name
                        << "\" st " << stBefore << "->" << stAfter << " dest=0x" << [&] { uint32_t d = 0; rd32(job + 0x94u, d); return d; }()
                        << std::dec << std::endl);
        }
    }

    // Log every TOCS name->LBA lookup: FUN_003a3c40(toc=0x4f6880, name, out).
    inline PS2Runtime::RecompiledFunction g_orig3a3c40 = nullptr;
    inline void wrap3a3c40(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    { const uint32_t a0raw = getRegU32(ctx, 4); const uint32_t a2in = getRegU32(ctx, 6);
        const uint32_t nameAddr = getRegU32(ctx, 5);
        char name[33] = {};
        for (int i = 0; i < 32; ++i)
        {
            uint32_t w = 0;
            if (!primal_sif_rpc::readGuestU32(rdram, nameAddr + i * 4u, w)) break;
            name[i * 4] = w & 0xFF; name[i * 4 + 1] = (w >> 8) & 0xFF;
            name[i * 4 + 2] = (w >> 16) & 0xFF; name[i * 4 + 3] = (w >> 24) & 0xFF;
            if (name[i * 4] == 0) break;
        }
        if (g_orig3a3c40) g_orig3a3c40(rdram, ctx, runtime);
        uint32_t v0 = getRegU32(ctx, 2);
        uint32_t out0 = 0, out1 = 0;
        uint32_t outAddr = a2in;
        primal_sif_rpc::readGuestU32(rdram, outAddr, out0);
        primal_sif_rpc::readGuestU32(rdram, outAddr + 4, out1);
        static int s_n = 0;
        if (s_n < 60)
        {
            ++s_n;
            RUNTIME_LOG("[tocs] #" << s_n << " a0=0x" << std::hex << a0raw << " a1=0x" << nameAddr << " name=\"" << name << "\" ret=0x" << std::hex << v0
                        << " out=0x" << out0 << ",0x" << out1 << std::dec << std::endl);
        }
    }

    // Log FUN_0032aa48 (load-job poll) view of the job: +0x30 status, +0x34 state, +0x38 name.
    inline PS2Runtime::RecompiledFunction g_orig32aa48 = nullptr;
    inline void wrap32aa48(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t job = getRegU32(ctx, 4);
        auto rd32 = [&](uint32_t a, uint32_t &v) -> bool { return primal_sif_rpc::readGuestU32(rdram, a, v); };
        uint32_t s30 = 0, s34 = 0;
        rd32(job + 0x30u, s30); rd32(job + 0x34u, s34);
        char name[33] = {};
        for (int i = 0; i < 8; ++i)
        {
            uint32_t w = 0;
            if (!rd32(job + 0x38u + i * 4u, w)) break;
            name[i * 4] = w & 0xFF; name[i * 4 + 1] = (w >> 8) & 0xFF;
            name[i * 4 + 2] = (w >> 16) & 0xFF; name[i * 4 + 3] = (w >> 24) & 0xFF;
            if (name[i * 4] == 0) break;
        }
        if (g_orig32aa48) g_orig32aa48(rdram, ctx, runtime);
        if (s30 == 0x18u)
        {
            static int s_dumpN = 0;
            if (s_dumpN < 4)
            {
                ++s_dumpN;
                std::ostringstream oss;
                oss << "[jobdump" << s_dumpN << "] job=0x" << std::hex << job << " :";
                for (uint32_t off = 0; off < 0xc0u; off += 4)
                {
                    uint32_t w = 0;
                    if (primal_sif_rpc::readGuestU32(rdram, job + off, w)) oss << " +0x" << std::hex << off << "=0x" << w;
                }
                RUNTIME_LOG(oss.str() << std::dec << std::endl);
            }
        }
        uint32_t ret = getRegU32(ctx, 2);
        if (ret == 1u)
        {
            static int s_dd = 0;
            if (s_dd < 3)
            {
                ++s_dd;
                uint32_t dest = 0;
                (void)rd32(job + 0x94u, dest);
                std::ostringstream oss;
                oss << "[scenedump" << s_dd << "] job=0x" << std::hex << job << " dest=0x" << dest << " :";
                for (uint32_t off = 0; off < 0xc0u; off += 4)
                {
                    uint32_t w = 0;
                    if (primal_sif_rpc::readGuestU32(rdram, job + off, w)) oss << " +0x" << std::hex << off << "=0x" << w;
                }
                uint32_t item = 0;
                (void)rd32(job + 0xb4u, item);
                if (item != 0)
                {
                    oss << " | item=0x" << item << " :";
                    for (uint32_t off = 0; off < 0x60u; off += 4)
                    {
                        uint32_t w = 0;
                        if (primal_sif_rpc::readGuestU32(rdram, item + off, w)) oss << " +0x" << std::hex << off << "=0x" << w;
                    }
                }
                for (uint32_t foff : {0x24u, 0x98u, 0xb8u})
                {
                    uint32_t p = 0;
                    (void)rd32(job + foff, p);
                    if (p != 0)
                    {
                        oss << " | +0x" << std::hex << foff << "->0x" << p << " :";
                        for (uint32_t off = 0; off < 0x40u; off += 4)
                        {
                            uint32_t w = 0;
                            if (primal_sif_rpc::readGuestU32(rdram, p + off, w)) oss << " +0x" << std::hex << off << "=0x" << w;
                        }
                    }
                }
                RUNTIME_LOG(oss.str() << std::dec << std::endl);
            }
        }
        static int s_n = 0;
        if (s_n < 50)
        {
            ++s_n;
            RUNTIME_LOG("[poll32aa48] #" << s_n << " job=0x" << std::hex << job << " +30=0x" << s30
                        << " +34=0x" << s34 << " name=\"" << name << "\" ret=0x" << ret << std::dec << std::endl);
        }
    }

    // Log FUN_0032a1f0 (load-job state machine) active case = param_1[0xc] (job+0x30).
    inline PS2Runtime::RecompiledFunction g_orig32a1f0 = nullptr;
    inline void wrap32a1f0(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t job = getRegU32(ctx, 4);
        uint32_t cur = 0;
        primal_sif_rpc::readGuestU32(rdram, job + 0x30u, cur);
        if (g_orig32a1f0) g_orig32a1f0(rdram, ctx, runtime);
        uint32_t nxt = 0;
        primal_sif_rpc::readGuestU32(rdram, job + 0x30u, nxt);
        static int s_n = 0;
        if (s_n < 60)
        {
            ++s_n;
            RUNTIME_LOG("[jobsm] #" << s_n << " job=0x" << std::hex << job << " case 0x" << cur
                        << " -> 0x" << nxt << std::dec << std::endl);
        }
    }

    // Log the real job drivers 0x32a148/0x32a248 (watchpoint writer pcs for job+0x30).
    inline PS2Runtime::RecompiledFunction g_orig32a148 = nullptr;
    inline PS2Runtime::RecompiledFunction g_orig32a248 = nullptr;
    inline void logJobDriver(const char *tag, uint8_t *rdram, R5900Context *ctx, PS2Runtime::RecompiledFunction orig, PS2Runtime *runtime)
    {
        const uint32_t job = getRegU32(ctx, 4);
        uint32_t before = 0;
        primal_sif_rpc::readGuestU32(rdram, job + 0x30u, before);
        if (orig) orig(rdram, ctx, runtime);
        uint32_t after = 0;
        primal_sif_rpc::readGuestU32(rdram, job + 0x30u, after);
        static int s_n = 0;
        if (s_n < 60)
        {
            ++s_n;
            RUNTIME_LOG("[" << tag << "] #" << s_n << " job=0x" << std::hex << job
                        << " +30 0x" << before << "->0x" << after << " ra=0x" << getRegU32(ctx, 31) << std::dec << std::endl);
        }
    }
    inline void wrap32a148(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    { logJobDriver("drv32a148", rdram, ctx, g_orig32a148, runtime); }
    inline void wrap32a248(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    { logJobDriver("drv32a248", rdram, ctx, g_orig32a248, runtime); }

    // Chokepoint logger for ALL cdvd commands: FUN_003e62f8(client, func, flags, args...).
    // func = $a1 (reg 5); the path arg for func 0xd is $a3 (reg 7).
    inline PS2Runtime::RecompiledFunction g_orig3e62f8 = nullptr;
    inline void wrap3e62f8(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t func = getRegU32(ctx, 5);
        const uint32_t arg3 = getRegU32(ctx, 7);
        char path[65] = {};
        if (func == 0xdu && arg3 != 0u)
        {
            for (int i = 0; i < 64; ++i)
            {
                uint32_t w = 0;
                if (!primal_sif_rpc::readGuestU32(rdram, arg3 + i * 4u, w)) break;
                path[i * 4] = w & 0xFF; path[i * 4 + 1] = (w >> 8) & 0xFF;
                path[i * 4 + 2] = (w >> 16) & 0xFF; path[i * 4 + 3] = (w >> 24) & 0xFF;
                if (path[i * 4] == 0) break;
            }
        }
        if (g_orig3e62f8) g_orig3e62f8(rdram, ctx, runtime);
        static int s_n = 0;
        if (s_n < 80)
        {
            ++s_n;
            RUNTIME_LOG("[cdvd] #" << s_n << " func=0x" << std::hex << func
                        << (func == 0xdu ? " path=\"" + std::string(path) + "\"" : std::string())
                        << " ret=0x" << getRegU32(ctx, 2) << std::dec << std::endl);
        }
    }

// Cluster sweep: heartbeat-probe every function in 0x32a000-0x32f000 (loader cluster).
struct ClusterProbe {
    static inline PS2Runtime::RecompiledFunction s_orig = nullptr;
    static inline std::unordered_map<uint32_t, uint64_t> s_counts;
    static void call(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime, uint32_t addr) {
        s_counts[addr]++;
        if (s_orig) s_orig(rdram, ctx, runtime);
    }
};
template <uint32_t Addr>
struct ClusterEntry {
    static inline PS2Runtime::RecompiledFunction s_orig = nullptr;
    static void call(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime) {
        ClusterProbe::s_counts[Addr]++;
        if (s_orig) s_orig(rdram, ctx, runtime);
    }
    static void install(PS2Runtime &runtime) {
        s_orig = runtime.lookupFunction(Addr);
        if (s_orig) runtime.replaceFunction(Addr, &call);
    }
};
inline ClusterEntry<0x32A080u> g_ce32a080;
inline ClusterEntry<0x32A0D8u> g_ce32a0d8;
inline ClusterEntry<0x32A134u> g_ce32a134;
inline ClusterEntry<0x32A13Cu> g_ce32a13c;
inline ClusterEntry<0x32A144u> g_ce32a144;
inline ClusterEntry<0x32A148u> g_ce32a148;
inline ClusterEntry<0x32A158u> g_ce32a158;
inline ClusterEntry<0x32A218u> g_ce32a218;
inline ClusterEntry<0x32A220u> g_ce32a220;
inline ClusterEntry<0x32A24Cu> g_ce32a24c;
inline ClusterEntry<0x32A348u> g_ce32a348;
inline ClusterEntry<0x32A3BCu> g_ce32a3bc;
inline ClusterEntry<0x32A3C8u> g_ce32a3c8;
inline ClusterEntry<0x32A41Cu> g_ce32a41c;
inline ClusterEntry<0x32A48Cu> g_ce32a48c;
inline ClusterEntry<0x32A4E8u> g_ce32a4e8;
inline ClusterEntry<0x32A50Cu> g_ce32a50c;
inline ClusterEntry<0x32A510u> g_ce32a510;
inline ClusterEntry<0x32A518u> g_ce32a518;
inline ClusterEntry<0x32A524u> g_ce32a524;
inline ClusterEntry<0x32A85Cu> g_ce32a85c;
inline ClusterEntry<0x32A86Cu> g_ce32a86c;
inline ClusterEntry<0x32A890u> g_ce32a890;
inline ClusterEntry<0x32A894u> g_ce32a894;
inline ClusterEntry<0x32A8A0u> g_ce32a8a0;
inline ClusterEntry<0x32A904u> g_ce32a904;
inline ClusterEntry<0x32A938u> g_ce32a938;
inline ClusterEntry<0x32A93Cu> g_ce32a93c;
inline ClusterEntry<0x32A944u> g_ce32a944;
inline ClusterEntry<0x32A948u> g_ce32a948;
inline ClusterEntry<0x32A978u> g_ce32a978;
inline ClusterEntry<0x32A9C0u> g_ce32a9c0;
inline ClusterEntry<0x32A9C4u> g_ce32a9c4;
inline ClusterEntry<0x32A9E0u> g_ce32a9e0;
inline ClusterEntry<0x32AA28u> g_ce32aa28;
inline ClusterEntry<0x32AA2Cu> g_ce32aa2c;
inline ClusterEntry<0x32AA48u> g_ce32aa48;
inline ClusterEntry<0x32AA5Cu> g_ce32aa5c;
inline ClusterEntry<0x32AA7Cu> g_ce32aa7c;
inline ClusterEntry<0x32AA98u> g_ce32aa98;
inline ClusterEntry<0x32AAC8u> g_ce32aac8;
inline ClusterEntry<0x32AB0Cu> g_ce32ab0c;
inline ClusterEntry<0x32AB28u> g_ce32ab28;
inline ClusterEntry<0x32AB40u> g_ce32ab40;
inline ClusterEntry<0x32AB5Cu> g_ce32ab5c;
inline ClusterEntry<0x32AB64u> g_ce32ab64;
inline ClusterEntry<0x32AB68u> g_ce32ab68;
inline ClusterEntry<0x32AB78u> g_ce32ab78;
inline ClusterEntry<0x32AB98u> g_ce32ab98;
inline ClusterEntry<0x32ABB8u> g_ce32abb8;
inline ClusterEntry<0x32ABD0u> g_ce32abd0;
inline ClusterEntry<0x32ABE0u> g_ce32abe0;
inline ClusterEntry<0x32AC64u> g_ce32ac64;
inline ClusterEntry<0x32AC98u> g_ce32ac98;
inline ClusterEntry<0x32AC9Cu> g_ce32ac9c;
inline ClusterEntry<0x32ACA8u> g_ce32aca8;
inline ClusterEntry<0x32AD2Cu> g_ce32ad2c;
inline ClusterEntry<0x32AD44u> g_ce32ad44;
inline ClusterEntry<0x32AD48u> g_ce32ad48;
inline ClusterEntry<0x32AD60u> g_ce32ad60;
inline ClusterEntry<0x32ADB0u> g_ce32adb0;
inline ClusterEntry<0x32ADF0u> g_ce32adf0;
inline ClusterEntry<0x32AE10u> g_ce32ae10;
inline ClusterEntry<0x32AE30u> g_ce32ae30;
inline ClusterEntry<0x32AE58u> g_ce32ae58;
inline ClusterEntry<0x32AE60u> g_ce32ae60;
inline ClusterEntry<0x32AEA8u> g_ce32aea8;
inline ClusterEntry<0x32AF00u> g_ce32af00;
inline ClusterEntry<0x32B008u> g_ce32b008;
inline ClusterEntry<0x32B0ECu> g_ce32b0ec;
inline ClusterEntry<0x32B140u> g_ce32b140;
inline ClusterEntry<0x32B150u> g_ce32b150;
inline ClusterEntry<0x32B168u> g_ce32b168;
inline ClusterEntry<0x32B1A4u> g_ce32b1a4;
inline ClusterEntry<0x32B1B4u> g_ce32b1b4;
inline ClusterEntry<0x32B1C0u> g_ce32b1c0;
inline ClusterEntry<0x32B1DCu> g_ce32b1dc;
inline ClusterEntry<0x32B1E4u> g_ce32b1e4;
inline ClusterEntry<0x32B204u> g_ce32b204;
inline ClusterEntry<0x32B21Cu> g_ce32b21c;
inline ClusterEntry<0x32B234u> g_ce32b234;
inline ClusterEntry<0x32B244u> g_ce32b244;
inline ClusterEntry<0x32B260u> g_ce32b260;
inline ClusterEntry<0x32B284u> g_ce32b284;
inline ClusterEntry<0x32B2A8u> g_ce32b2a8;
inline ClusterEntry<0x32B2C4u> g_ce32b2c4;
inline ClusterEntry<0x32B2D8u> g_ce32b2d8;
inline ClusterEntry<0x32B330u> g_ce32b330;
inline ClusterEntry<0x32B348u> g_ce32b348;
inline ClusterEntry<0x32B738u> g_ce32b738;
inline ClusterEntry<0x32B770u> g_ce32b770;
inline ClusterEntry<0x32B798u> g_ce32b798;
inline ClusterEntry<0x32B8F4u> g_ce32b8f4;
inline ClusterEntry<0x32B8F8u> g_ce32b8f8;
inline ClusterEntry<0x32B910u> g_ce32b910;
inline ClusterEntry<0x32B958u> g_ce32b958;
inline ClusterEntry<0x32B980u> g_ce32b980;
inline ClusterEntry<0x32B9F4u> g_ce32b9f4;
inline ClusterEntry<0x32BA20u> g_ce32ba20;
inline ClusterEntry<0x32BA90u> g_ce32ba90;
inline ClusterEntry<0x32BAD8u> g_ce32bad8;
inline ClusterEntry<0x32BB0Cu> g_ce32bb0c;
inline ClusterEntry<0x32BBD0u> g_ce32bbd0;
inline ClusterEntry<0x32BBDCu> g_ce32bbdc;
inline ClusterEntry<0x32BC04u> g_ce32bc04;
inline ClusterEntry<0x32BC90u> g_ce32bc90;
inline ClusterEntry<0x32BC9Cu> g_ce32bc9c;
inline ClusterEntry<0x32BD1Cu> g_ce32bd1c;
inline ClusterEntry<0x32BD24u> g_ce32bd24;
inline ClusterEntry<0x32BD28u> g_ce32bd28;
inline ClusterEntry<0x32BD8Cu> g_ce32bd8c;
inline ClusterEntry<0x32BDA0u> g_ce32bda0;
inline ClusterEntry<0x32BDA4u> g_ce32bda4;
inline ClusterEntry<0x32BDA8u> g_ce32bda8;
inline ClusterEntry<0x32BE38u> g_ce32be38;
inline ClusterEntry<0x32BEACu> g_ce32beac;
inline ClusterEntry<0x32BEB0u> g_ce32beb0;
inline ClusterEntry<0x32BEF0u> g_ce32bef0;
inline ClusterEntry<0x32BF60u> g_ce32bf60;
inline ClusterEntry<0x32BF9Cu> g_ce32bf9c;
inline ClusterEntry<0x32BFA8u> g_ce32bfa8;
inline ClusterEntry<0x32BFC4u> g_ce32bfc4;
inline ClusterEntry<0x32C000u> g_ce32c000;
inline ClusterEntry<0x32C004u> g_ce32c004;
inline ClusterEntry<0x32C03Cu> g_ce32c03c;
inline ClusterEntry<0x32C060u> g_ce32c060;
inline ClusterEntry<0x32C07Cu> g_ce32c07c;
inline ClusterEntry<0x32C0D4u> g_ce32c0d4;
inline ClusterEntry<0x32C0F8u> g_ce32c0f8;
inline ClusterEntry<0x32C158u> g_ce32c158;
inline ClusterEntry<0x32C1B8u> g_ce32c1b8;
inline ClusterEntry<0x32C210u> g_ce32c210;
inline ClusterEntry<0x32C238u> g_ce32c238;
inline ClusterEntry<0x32C290u> g_ce32c290;
inline ClusterEntry<0x32C2FCu> g_ce32c2fc;
inline ClusterEntry<0x32C330u> g_ce32c330;
inline ClusterEntry<0x32C380u> g_ce32c380;
inline ClusterEntry<0x32C3ACu> g_ce32c3ac;
inline ClusterEntry<0x32C418u> g_ce32c418;
inline ClusterEntry<0x32C468u> g_ce32c468;
inline ClusterEntry<0x32C484u> g_ce32c484;
inline ClusterEntry<0x32C4D4u> g_ce32c4d4;
inline ClusterEntry<0x32C4D8u> g_ce32c4d8;
inline ClusterEntry<0x32C4F0u> g_ce32c4f0;
inline ClusterEntry<0x32C5A0u> g_ce32c5a0;
inline ClusterEntry<0x32C5A4u> g_ce32c5a4;
inline ClusterEntry<0x32C5D0u> g_ce32c5d0;
inline ClusterEntry<0x32C5F8u> g_ce32c5f8;
inline ClusterEntry<0x32C618u> g_ce32c618;
inline ClusterEntry<0x32C670u> g_ce32c670;
inline ClusterEntry<0x32C698u> g_ce32c698;
inline ClusterEntry<0x32C6B8u> g_ce32c6b8;
inline ClusterEntry<0x32C6FCu> g_ce32c6fc;
inline ClusterEntry<0x32C700u> g_ce32c700;
inline ClusterEntry<0x32C718u> g_ce32c718;
inline ClusterEntry<0x32C798u> g_ce32c798;
inline ClusterEntry<0x32C7A0u> g_ce32c7a0;
inline ClusterEntry<0x32C858u> g_ce32c858;
inline ClusterEntry<0x32C8A0u> g_ce32c8a0;
inline ClusterEntry<0x32C8D4u> g_ce32c8d4;
inline ClusterEntry<0x32C8ECu> g_ce32c8ec;
inline ClusterEntry<0x32C95Cu> g_ce32c95c;
inline ClusterEntry<0x32C980u> g_ce32c980;
inline ClusterEntry<0x32C984u> g_ce32c984;
inline ClusterEntry<0x32C9A0u> g_ce32c9a0;
inline ClusterEntry<0x32CA48u> g_ce32ca48;
inline ClusterEntry<0x32CA70u> g_ce32ca70;
inline ClusterEntry<0x32CAE4u> g_ce32cae4;
inline ClusterEntry<0x32CB04u> g_ce32cb04;
inline ClusterEntry<0x32CB1Cu> g_ce32cb1c;
inline ClusterEntry<0x32CB40u> g_ce32cb40;
inline ClusterEntry<0x32CC28u> g_ce32cc28;
inline ClusterEntry<0x32CC40u> g_ce32cc40;
inline ClusterEntry<0x32CC5Cu> g_ce32cc5c;
inline ClusterEntry<0x32CCACu> g_ce32ccac;
inline ClusterEntry<0x32CCC4u> g_ce32ccc4;
inline ClusterEntry<0x32CCC8u> g_ce32ccc8;
inline ClusterEntry<0x32CD00u> g_ce32cd00;
inline ClusterEntry<0x32CD34u> g_ce32cd34;
inline ClusterEntry<0x32CD58u> g_ce32cd58;
inline ClusterEntry<0x32CD80u> g_ce32cd80;
inline ClusterEntry<0x32CD98u> g_ce32cd98;
inline ClusterEntry<0x32CDA4u> g_ce32cda4;
inline ClusterEntry<0x32CDB4u> g_ce32cdb4;
inline ClusterEntry<0x32CDF4u> g_ce32cdf4;
inline ClusterEntry<0x32CE04u> g_ce32ce04;
inline ClusterEntry<0x32CE24u> g_ce32ce24;
inline ClusterEntry<0x32CE34u> g_ce32ce34;
inline ClusterEntry<0x32CE74u> g_ce32ce74;
inline ClusterEntry<0x32CE88u> g_ce32ce88;
inline ClusterEntry<0x32CEA8u> g_ce32cea8;
inline ClusterEntry<0x32CECCu> g_ce32cecc;
inline ClusterEntry<0x32CEF4u> g_ce32cef4;
inline ClusterEntry<0x32CF20u> g_ce32cf20;
inline ClusterEntry<0x32CF68u> g_ce32cf68;
inline ClusterEntry<0x32CF8Cu> g_ce32cf8c;
inline ClusterEntry<0x32CF98u> g_ce32cf98;
inline ClusterEntry<0x32D010u> g_ce32d010;
inline ClusterEntry<0x32D068u> g_ce32d068;
inline ClusterEntry<0x32D0A0u> g_ce32d0a0;
inline ClusterEntry<0x32D0DCu> g_ce32d0dc;
inline ClusterEntry<0x32D0E0u> g_ce32d0e0;
inline ClusterEntry<0x32D100u> g_ce32d100;
inline ClusterEntry<0x32D17Cu> g_ce32d17c;
inline ClusterEntry<0x32D180u> g_ce32d180;
inline ClusterEntry<0x32D1E8u> g_ce32d1e8;
inline ClusterEntry<0x32D1ECu> g_ce32d1ec;
inline ClusterEntry<0x32D234u> g_ce32d234;
inline ClusterEntry<0x32D254u> g_ce32d254;
inline ClusterEntry<0x32D258u> g_ce32d258;
inline ClusterEntry<0x32D25Cu> g_ce32d25c;
inline ClusterEntry<0x32D270u> g_ce32d270;
inline ClusterEntry<0x32DAB8u> g_ce32dab8;
inline ClusterEntry<0x32DAC0u> g_ce32dac0;
inline ClusterEntry<0x32DB1Cu> g_ce32db1c;
inline ClusterEntry<0x32DB5Cu> g_ce32db5c;
inline ClusterEntry<0x32DB60u> g_ce32db60;
inline ClusterEntry<0x32DB70u> g_ce32db70;
inline ClusterEntry<0x32DB78u> g_ce32db78;
inline ClusterEntry<0x32DBD0u> g_ce32dbd0;
inline ClusterEntry<0x32DBF0u> g_ce32dbf0;
inline ClusterEntry<0x32DC30u> g_ce32dc30;
inline ClusterEntry<0x32DC50u> g_ce32dc50;
inline ClusterEntry<0x32DCD8u> g_ce32dcd8;
inline ClusterEntry<0x32DD08u> g_ce32dd08;
inline ClusterEntry<0x32DDA0u> g_ce32dda0;
inline ClusterEntry<0x32DDCCu> g_ce32ddcc;
inline ClusterEntry<0x32DE14u> g_ce32de14;
inline ClusterEntry<0x32DE24u> g_ce32de24;
inline ClusterEntry<0x32DE48u> g_ce32de48;
inline ClusterEntry<0x32DE68u> g_ce32de68;
inline ClusterEntry<0x32DE8Cu> g_ce32de8c;
inline ClusterEntry<0x32DEA0u> g_ce32dea0;
inline ClusterEntry<0x32DEC0u> g_ce32dec0;
inline ClusterEntry<0x32DEF0u> g_ce32def0;
inline ClusterEntry<0x32DF48u> g_ce32df48;
inline ClusterEntry<0x32DF7Cu> g_ce32df7c;
inline ClusterEntry<0x32DFCCu> g_ce32dfcc;
inline ClusterEntry<0x32DFF0u> g_ce32dff0;
inline ClusterEntry<0x32E060u> g_ce32e060;
inline ClusterEntry<0x32E080u> g_ce32e080;
inline ClusterEntry<0x32E088u> g_ce32e088;
inline ClusterEntry<0x32E0C0u> g_ce32e0c0;
inline ClusterEntry<0x32E0DCu> g_ce32e0dc;
inline ClusterEntry<0x32E0E0u> g_ce32e0e0;
inline ClusterEntry<0x32E0F0u> g_ce32e0f0;
inline ClusterEntry<0x32E178u> g_ce32e178;
inline ClusterEntry<0x32E1D8u> g_ce32e1d8;
inline ClusterEntry<0x32E210u> g_ce32e210;
inline ClusterEntry<0x32E274u> g_ce32e274;
inline ClusterEntry<0x32E2C0u> g_ce32e2c0;
inline ClusterEntry<0x32E334u> g_ce32e334;
inline ClusterEntry<0x32E35Cu> g_ce32e35c;
inline ClusterEntry<0x32E378u> g_ce32e378;
inline ClusterEntry<0x32E3CCu> g_ce32e3cc;
inline ClusterEntry<0x32E454u> g_ce32e454;
inline ClusterEntry<0x32E47Cu> g_ce32e47c;
inline ClusterEntry<0x32E4C8u> g_ce32e4c8;
inline ClusterEntry<0x32E554u> g_ce32e554;
inline ClusterEntry<0x32E5B8u> g_ce32e5b8;
inline ClusterEntry<0x32E5CCu> g_ce32e5cc;
inline ClusterEntry<0x32E618u> g_ce32e618;
inline ClusterEntry<0x32E638u> g_ce32e638;
inline ClusterEntry<0x32E63Cu> g_ce32e63c;
inline ClusterEntry<0x32E778u> g_ce32e778;
inline ClusterEntry<0x32E798u> g_ce32e798;
inline ClusterEntry<0x32E7D0u> g_ce32e7d0;
inline ClusterEntry<0x32E7F0u> g_ce32e7f0;
inline ClusterEntry<0x32E7FCu> g_ce32e7fc;
inline ClusterEntry<0x32E804u> g_ce32e804;
inline ClusterEntry<0x32E824u> g_ce32e824;
inline ClusterEntry<0x32E874u> g_ce32e874;
inline ClusterEntry<0x32E878u> g_ce32e878;
inline ClusterEntry<0x32E87Cu> g_ce32e87c;
inline ClusterEntry<0x32E8A8u> g_ce32e8a8;
inline ClusterEntry<0x32E8C0u> g_ce32e8c0;
inline ClusterEntry<0x32E92Cu> g_ce32e92c;
inline ClusterEntry<0x32E964u> g_ce32e964;
inline ClusterEntry<0x32E988u> g_ce32e988;
inline ClusterEntry<0x32E9BCu> g_ce32e9bc;
inline ClusterEntry<0x32EA20u> g_ce32ea20;
inline ClusterEntry<0x32EA3Cu> g_ce32ea3c;
inline ClusterEntry<0x32EA60u> g_ce32ea60;
inline ClusterEntry<0x32EA9Cu> g_ce32ea9c;
inline ClusterEntry<0x32EAC8u> g_ce32eac8;
inline ClusterEntry<0x32EACCu> g_ce32eacc;
inline ClusterEntry<0x32EAE8u> g_ce32eae8;
inline ClusterEntry<0x32F3F0u> g_ce32f3f0;
inline ClusterEntry<0x32F44Cu> g_ce32f44c;
inline ClusterEntry<0x32F488u> g_ce32f488;
inline ClusterEntry<0x32F4E0u> g_ce32f4e0;
inline ClusterEntry<0x32F55Cu> g_ce32f55c;
inline ClusterEntry<0x32F56Cu> g_ce32f56c;
inline ClusterEntry<0x32F588u> g_ce32f588;
inline ClusterEntry<0x32F5CCu> g_ce32f5cc;
inline ClusterEntry<0x32F5DCu> g_ce32f5dc;
inline ClusterEntry<0x32F604u> g_ce32f604;
inline ClusterEntry<0x32F638u> g_ce32f638;
inline ClusterEntry<0x32F640u> g_ce32f640;
inline ClusterEntry<0x32F650u> g_ce32f650;
inline ClusterEntry<0x32F654u> g_ce32f654;
inline ClusterEntry<0x32F668u> g_ce32f668;
inline ClusterEntry<0x32F6F0u> g_ce32f6f0;
inline ClusterEntry<0x32F704u> g_ce32f704;
inline ClusterEntry<0x32F70Cu> g_ce32f70c;
inline ClusterEntry<0x32F720u> g_ce32f720;
inline ClusterEntry<0x32F770u> g_ce32f770;
inline ClusterEntry<0x32F778u> g_ce32f778;
inline ClusterEntry<0x32F7B0u> g_ce32f7b0;
inline ClusterEntry<0x32F7D4u> g_ce32f7d4;
inline ClusterEntry<0x32F7F8u> g_ce32f7f8;
inline ClusterEntry<0x32F820u> g_ce32f820;
inline ClusterEntry<0x32F83Cu> g_ce32f83c;
inline ClusterEntry<0x32F844u> g_ce32f844;
inline ClusterEntry<0x32F84Cu> g_ce32f84c;
inline ClusterEntry<0x32F850u> g_ce32f850;
inline ClusterEntry<0x32F868u> g_ce32f868;
inline ClusterEntry<0x32F88Cu> g_ce32f88c;
inline ClusterEntry<0x32F8A0u> g_ce32f8a0;
inline ClusterEntry<0x32F8B0u> g_ce32f8b0;
inline ClusterEntry<0x32F8B4u> g_ce32f8b4;
inline ClusterEntry<0x32F8C8u> g_ce32f8c8;
inline ClusterEntry<0x32F8E8u> g_ce32f8e8;
inline ClusterEntry<0x32F928u> g_ce32f928;
inline ClusterEntry<0x32F960u> g_ce32f960;
inline ClusterEntry<0x32F9D8u> g_ce32f9d8;
inline ClusterEntry<0x32FA20u> g_ce32fa20;
inline ClusterEntry<0x32FA68u> g_ce32fa68;
inline ClusterEntry<0x32FA90u> g_ce32fa90;
inline ClusterEntry<0x32FAA0u> g_ce32faa0;
inline ClusterEntry<0x32FB28u> g_ce32fb28;
inline ClusterEntry<0x32FB58u> g_ce32fb58;
inline ClusterEntry<0x32FB80u> g_ce32fb80;
inline ClusterEntry<0x32FBA8u> g_ce32fba8;
inline ClusterEntry<0x32FBBCu> g_ce32fbbc;
inline ClusterEntry<0x32FBD8u> g_ce32fbd8;
inline ClusterEntry<0x32FC4Cu> g_ce32fc4c;
inline ClusterEntry<0x32FC60u> g_ce32fc60;
inline ClusterEntry<0x32FCBCu> g_ce32fcbc;
inline ClusterEntry<0x32FCC0u> g_ce32fcc0;
inline ClusterEntry<0x32FCC4u> g_ce32fcc4;
inline ClusterEntry<0x32FCE8u> g_ce32fce8;
inline ClusterEntry<0x32FE50u> g_ce32fe50;
inline ClusterEntry<0x32FEA4u> g_ce32fea4;
inline ClusterEntry<0x32FED8u> g_ce32fed8;
inline ClusterEntry<0x32FF00u> g_ce32ff00;
inline ClusterEntry<0x32FF28u> g_ce32ff28;
inline ClusterEntry<0x32FF80u> g_ce32ff80;
inline ClusterEntry<0x32FFA4u> g_ce32ffa4;
inline ClusterEntry<0x32FFB8u> g_ce32ffb8;
inline ClusterEntry<0x32FFD8u> g_ce32ffd8;
inline ClusterEntry<0x32FFF8u> g_ce32fff8;
inline void installClusterSweep(PS2Runtime &runtime) {
    g_ce32a080.install(runtime);
    g_ce32a0d8.install(runtime);
    g_ce32a134.install(runtime);
    g_ce32a13c.install(runtime);
    g_ce32a144.install(runtime);
    g_ce32a148.install(runtime);
    g_ce32a158.install(runtime);
    g_ce32a218.install(runtime);
    g_ce32a220.install(runtime);
    g_ce32a24c.install(runtime);
    g_ce32a348.install(runtime);
    g_ce32a3bc.install(runtime);
    g_ce32a3c8.install(runtime);
    g_ce32a41c.install(runtime);
    g_ce32a48c.install(runtime);
    g_ce32a4e8.install(runtime);
    g_ce32a50c.install(runtime);
    g_ce32a510.install(runtime);
    g_ce32a518.install(runtime);
    g_ce32a524.install(runtime);
    g_ce32a85c.install(runtime);
    g_ce32a86c.install(runtime);
    g_ce32a890.install(runtime);
    g_ce32a894.install(runtime);
    g_ce32a8a0.install(runtime);
    g_ce32a904.install(runtime);
    g_ce32a938.install(runtime);
    g_ce32a93c.install(runtime);
    g_ce32a944.install(runtime);
    g_ce32a948.install(runtime);
    g_ce32a978.install(runtime);
    g_ce32a9c0.install(runtime);
    g_ce32a9c4.install(runtime);
    g_ce32a9e0.install(runtime);
    g_ce32aa28.install(runtime);
    g_ce32aa2c.install(runtime);
    g_ce32aa48.install(runtime);
    g_ce32aa5c.install(runtime);
    g_ce32aa7c.install(runtime);
    g_ce32aa98.install(runtime);
    g_ce32aac8.install(runtime);
    g_ce32ab0c.install(runtime);
    g_ce32ab28.install(runtime);
    g_ce32ab40.install(runtime);
    g_ce32ab5c.install(runtime);
    g_ce32ab64.install(runtime);
    g_ce32ab68.install(runtime);
    g_ce32ab78.install(runtime);
    g_ce32ab98.install(runtime);
    g_ce32abb8.install(runtime);
    g_ce32abd0.install(runtime);
    g_ce32abe0.install(runtime);
    g_ce32ac64.install(runtime);
    g_ce32ac98.install(runtime);
    g_ce32ac9c.install(runtime);
    g_ce32aca8.install(runtime);
    g_ce32ad2c.install(runtime);
    g_ce32ad44.install(runtime);
    g_ce32ad48.install(runtime);
    g_ce32ad60.install(runtime);
    g_ce32adb0.install(runtime);
    g_ce32adf0.install(runtime);
    g_ce32ae10.install(runtime);
    g_ce32ae30.install(runtime);
    g_ce32ae58.install(runtime);
    g_ce32ae60.install(runtime);
    g_ce32aea8.install(runtime);
    g_ce32af00.install(runtime);
    g_ce32b008.install(runtime);
    g_ce32b0ec.install(runtime);
    g_ce32b140.install(runtime);
    g_ce32b150.install(runtime);
    g_ce32b168.install(runtime);
    g_ce32b1a4.install(runtime);
    g_ce32b1b4.install(runtime);
    g_ce32b1c0.install(runtime);
    g_ce32b1dc.install(runtime);
    g_ce32b1e4.install(runtime);
    g_ce32b204.install(runtime);
    g_ce32b21c.install(runtime);
    g_ce32b234.install(runtime);
    g_ce32b244.install(runtime);
    g_ce32b260.install(runtime);
    g_ce32b284.install(runtime);
    g_ce32b2a8.install(runtime);
    g_ce32b2c4.install(runtime);
    g_ce32b2d8.install(runtime);
    g_ce32b330.install(runtime);
    g_ce32b348.install(runtime);
    g_ce32b738.install(runtime);
    g_ce32b770.install(runtime);
    g_ce32b798.install(runtime);
    g_ce32b8f4.install(runtime);
    g_ce32b8f8.install(runtime);
    g_ce32b910.install(runtime);
    g_ce32b958.install(runtime);
    g_ce32b980.install(runtime);
    g_ce32b9f4.install(runtime);
    g_ce32ba20.install(runtime);
    g_ce32ba90.install(runtime);
    g_ce32bad8.install(runtime);
    g_ce32bb0c.install(runtime);
    g_ce32bbd0.install(runtime);
    g_ce32bbdc.install(runtime);
    g_ce32bc04.install(runtime);
    g_ce32bc90.install(runtime);
    g_ce32bc9c.install(runtime);
    g_ce32bd1c.install(runtime);
    g_ce32bd24.install(runtime);
    g_ce32bd28.install(runtime);
    g_ce32bd8c.install(runtime);
    g_ce32bda0.install(runtime);
    g_ce32bda4.install(runtime);
    g_ce32bda8.install(runtime);
    g_ce32be38.install(runtime);
    g_ce32beac.install(runtime);
    g_ce32beb0.install(runtime);
    g_ce32bef0.install(runtime);
    g_ce32bf60.install(runtime);
    g_ce32bf9c.install(runtime);
    g_ce32bfa8.install(runtime);
    g_ce32bfc4.install(runtime);
    g_ce32c000.install(runtime);
    g_ce32c004.install(runtime);
    g_ce32c03c.install(runtime);
    g_ce32c060.install(runtime);
    g_ce32c07c.install(runtime);
    g_ce32c0d4.install(runtime);
    g_ce32c0f8.install(runtime);
    g_ce32c158.install(runtime);
    g_ce32c1b8.install(runtime);
    g_ce32c210.install(runtime);
    g_ce32c238.install(runtime);
    g_ce32c290.install(runtime);
    g_ce32c2fc.install(runtime);
    g_ce32c330.install(runtime);
    g_ce32c380.install(runtime);
    g_ce32c3ac.install(runtime);
    g_ce32c418.install(runtime);
    g_ce32c468.install(runtime);
    g_ce32c484.install(runtime);
    g_ce32c4d4.install(runtime);
    g_ce32c4d8.install(runtime);
    g_ce32c4f0.install(runtime);
    g_ce32c5a0.install(runtime);
    g_ce32c5a4.install(runtime);
    g_ce32c5d0.install(runtime);
    g_ce32c5f8.install(runtime);
    g_ce32c618.install(runtime);
    g_ce32c670.install(runtime);
    g_ce32c698.install(runtime);
    g_ce32c6b8.install(runtime);
    g_ce32c6fc.install(runtime);
    g_ce32c700.install(runtime);
    g_ce32c718.install(runtime);
    g_ce32c798.install(runtime);
    g_ce32c7a0.install(runtime);
    g_ce32c858.install(runtime);
    g_ce32c8a0.install(runtime);
    g_ce32c8d4.install(runtime);
    g_ce32c8ec.install(runtime);
    g_ce32c95c.install(runtime);
    g_ce32c980.install(runtime);
    g_ce32c984.install(runtime);
    g_ce32c9a0.install(runtime);
    g_ce32ca48.install(runtime);
    g_ce32ca70.install(runtime);
    g_ce32cae4.install(runtime);
    g_ce32cb04.install(runtime);
    g_ce32cb1c.install(runtime);
    g_ce32cb40.install(runtime);
    g_ce32cc28.install(runtime);
    g_ce32cc40.install(runtime);
    g_ce32cc5c.install(runtime);
    g_ce32ccac.install(runtime);
    g_ce32ccc4.install(runtime);
    g_ce32ccc8.install(runtime);
    g_ce32cd00.install(runtime);
    g_ce32cd34.install(runtime);
    g_ce32cd58.install(runtime);
    g_ce32cd80.install(runtime);
    g_ce32cd98.install(runtime);
    g_ce32cda4.install(runtime);
    g_ce32cdb4.install(runtime);
    g_ce32cdf4.install(runtime);
    g_ce32ce04.install(runtime);
    g_ce32ce24.install(runtime);
    g_ce32ce34.install(runtime);
    g_ce32ce74.install(runtime);
    g_ce32ce88.install(runtime);
    g_ce32cea8.install(runtime);
    g_ce32cecc.install(runtime);
    g_ce32cef4.install(runtime);
    g_ce32cf20.install(runtime);
    g_ce32cf68.install(runtime);
    g_ce32cf8c.install(runtime);
    g_ce32cf98.install(runtime);
    g_ce32d010.install(runtime);
    g_ce32d068.install(runtime);
    g_ce32d0a0.install(runtime);
    g_ce32d0dc.install(runtime);
    g_ce32d0e0.install(runtime);
    g_ce32d100.install(runtime);
    g_ce32d17c.install(runtime);
    g_ce32d180.install(runtime);
    g_ce32d1e8.install(runtime);
    g_ce32d1ec.install(runtime);
    g_ce32d234.install(runtime);
    g_ce32d254.install(runtime);
    g_ce32d258.install(runtime);
    g_ce32d25c.install(runtime);
    g_ce32d270.install(runtime);
    g_ce32dab8.install(runtime);
    g_ce32dac0.install(runtime);
    g_ce32db1c.install(runtime);
    g_ce32db5c.install(runtime);
    g_ce32db60.install(runtime);
    g_ce32db70.install(runtime);
    g_ce32db78.install(runtime);
    g_ce32dbd0.install(runtime);
    g_ce32dbf0.install(runtime);
    g_ce32dc30.install(runtime);
    g_ce32dc50.install(runtime);
    g_ce32dcd8.install(runtime);
    g_ce32dd08.install(runtime);
    g_ce32dda0.install(runtime);
    g_ce32ddcc.install(runtime);
    g_ce32de14.install(runtime);
    g_ce32de24.install(runtime);
    g_ce32de48.install(runtime);
    g_ce32de68.install(runtime);
    g_ce32de8c.install(runtime);
    g_ce32dea0.install(runtime);
    g_ce32dec0.install(runtime);
    g_ce32def0.install(runtime);
    g_ce32df48.install(runtime);
    g_ce32df7c.install(runtime);
    g_ce32dfcc.install(runtime);
    g_ce32dff0.install(runtime);
    g_ce32e060.install(runtime);
    g_ce32e080.install(runtime);
    g_ce32e088.install(runtime);
    g_ce32e0c0.install(runtime);
    g_ce32e0dc.install(runtime);
    g_ce32e0e0.install(runtime);
    g_ce32e0f0.install(runtime);
    g_ce32e178.install(runtime);
    g_ce32e1d8.install(runtime);
    g_ce32e210.install(runtime);
    g_ce32e274.install(runtime);
    g_ce32e2c0.install(runtime);
    g_ce32e334.install(runtime);
    g_ce32e35c.install(runtime);
    g_ce32e378.install(runtime);
    g_ce32e3cc.install(runtime);
    g_ce32e454.install(runtime);
    g_ce32e47c.install(runtime);
    g_ce32e4c8.install(runtime);
    g_ce32e554.install(runtime);
    g_ce32e5b8.install(runtime);
    g_ce32e5cc.install(runtime);
    g_ce32e618.install(runtime);
    g_ce32e638.install(runtime);
    g_ce32e63c.install(runtime);
    g_ce32e778.install(runtime);
    g_ce32e798.install(runtime);
    g_ce32e7d0.install(runtime);
    g_ce32e7f0.install(runtime);
    g_ce32e7fc.install(runtime);
    g_ce32e804.install(runtime);
    g_ce32e824.install(runtime);
    g_ce32e874.install(runtime);
    g_ce32e878.install(runtime);
    g_ce32e87c.install(runtime);
    g_ce32e8a8.install(runtime);
    g_ce32e8c0.install(runtime);
    g_ce32e92c.install(runtime);
    g_ce32e964.install(runtime);
    g_ce32e988.install(runtime);
    g_ce32e9bc.install(runtime);
    g_ce32ea20.install(runtime);
    g_ce32ea3c.install(runtime);
    g_ce32ea60.install(runtime);
    g_ce32ea9c.install(runtime);
    g_ce32eac8.install(runtime);
    g_ce32eacc.install(runtime);
    g_ce32eae8.install(runtime);
    g_ce32f3f0.install(runtime);
    g_ce32f44c.install(runtime);
    g_ce32f488.install(runtime);
    g_ce32f4e0.install(runtime);
    g_ce32f55c.install(runtime);
    g_ce32f56c.install(runtime);
    g_ce32f588.install(runtime);
    g_ce32f5cc.install(runtime);
    g_ce32f5dc.install(runtime);
    g_ce32f604.install(runtime);
    g_ce32f638.install(runtime);
    g_ce32f640.install(runtime);
    g_ce32f650.install(runtime);
    g_ce32f654.install(runtime);
    g_ce32f668.install(runtime);
    g_ce32f6f0.install(runtime);
    g_ce32f704.install(runtime);
    g_ce32f70c.install(runtime);
    g_ce32f720.install(runtime);
    g_ce32f770.install(runtime);
    g_ce32f778.install(runtime);
    g_ce32f7b0.install(runtime);
    g_ce32f7d4.install(runtime);
    g_ce32f7f8.install(runtime);
    g_ce32f820.install(runtime);
    g_ce32f83c.install(runtime);
    g_ce32f844.install(runtime);
    g_ce32f84c.install(runtime);
    g_ce32f850.install(runtime);
    g_ce32f868.install(runtime);
    g_ce32f88c.install(runtime);
    g_ce32f8a0.install(runtime);
    g_ce32f8b0.install(runtime);
    g_ce32f8b4.install(runtime);
    g_ce32f8c8.install(runtime);
    g_ce32f8e8.install(runtime);
    g_ce32f928.install(runtime);
    g_ce32f960.install(runtime);
    g_ce32f9d8.install(runtime);
    g_ce32fa20.install(runtime);
    g_ce32fa68.install(runtime);
    g_ce32fa90.install(runtime);
    g_ce32faa0.install(runtime);
    g_ce32fb28.install(runtime);
    g_ce32fb58.install(runtime);
    g_ce32fb80.install(runtime);
    g_ce32fba8.install(runtime);
    g_ce32fbbc.install(runtime);
    g_ce32fbd8.install(runtime);
    g_ce32fc4c.install(runtime);
    g_ce32fc60.install(runtime);
    g_ce32fcbc.install(runtime);
    g_ce32fcc0.install(runtime);
    g_ce32fcc4.install(runtime);
    g_ce32fce8.install(runtime);
    g_ce32fe50.install(runtime);
    g_ce32fea4.install(runtime);
    g_ce32fed8.install(runtime);
    g_ce32ff00.install(runtime);
    g_ce32ff28.install(runtime);
    g_ce32ff80.install(runtime);
    g_ce32ffa4.install(runtime);
    g_ce32ffb8.install(runtime);
    g_ce32ffd8.install(runtime);
    g_ce32fff8.install(runtime);
    RUNTIME_LOG("[cluster] sweep installed for " << 352 << " fns in 0x32a000-0x32f000" << std::endl);
}
inline void dumpClusterCounts() {
    RUNTIME_LOG("[cluster] hot fns:" << std::endl);
    for (auto &kv : ClusterProbe::s_counts) if (kv.second > 0) RUNTIME_LOG("  0x" << std::hex << kv.first << " calls=" << std::dec << kv.second << std::endl);
}

    // Hot-cluster job-field loggers (round 91): log a0 and job fields at entry.
    inline PS2Runtime::RecompiledFunction g_origH32a8a0 = nullptr;
    inline void wrapH32a8a0(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t job = getRegU32(ctx, 4);
        uint32_t s30 = 0, s34 = 0, s38 = 0;
        primal_sif_rpc::readGuestU32(rdram, job + 0x30u, s30);
        primal_sif_rpc::readGuestU32(rdram, job + 0x34u, s34);
        primal_sif_rpc::readGuestU32(rdram, job + 0x38u, s38);
        static int s_n32a8a0 = 0;
        if (s_n32a8a0 < 25)
        {
            ++s_n32a8a0;
            RUNTIME_LOG("[hot0x32a8a0] #" << s_n32a8a0 << " job=0x" << std::hex << job << " +30=0x" << s30 << " +34=0x" << s34 << " +38=0x" << s38 << " ra=0x" << getRegU32(ctx, 31) << std::dec << std::endl);
        }
        if (g_origH32a8a0) g_origH32a8a0(rdram, ctx, runtime);
    }
    inline PS2Runtime::RecompiledFunction g_origH32a9e0 = nullptr;
    inline void wrapH32a9e0(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t job = getRegU32(ctx, 4);
        uint32_t s30 = 0, s34 = 0, s38 = 0;
        primal_sif_rpc::readGuestU32(rdram, job + 0x30u, s30);
        primal_sif_rpc::readGuestU32(rdram, job + 0x34u, s34);
        primal_sif_rpc::readGuestU32(rdram, job + 0x38u, s38);
        static int s_n32a9e0 = 0;
        if (s_n32a9e0 < 25)
        {
            ++s_n32a9e0;
            RUNTIME_LOG("[hot0x32a9e0] #" << s_n32a9e0 << " job=0x" << std::hex << job << " +30=0x" << s30 << " +34=0x" << s34 << " +38=0x" << s38 << " ra=0x" << getRegU32(ctx, 31) << std::dec << std::endl);
        }
        if (g_origH32a9e0) g_origH32a9e0(rdram, ctx, runtime);
    }
    inline PS2Runtime::RecompiledFunction g_origH32abe0 = nullptr;
    // Round 108: guest CRC matching FUN_0032adf0 (poly 0x04C11DB7, init/xorout 0xFFFFFFFF, MSB-first).
    inline uint32_t primalGuestCrc(const uint8_t *p, uint32_t n)
    {
        uint32_t v1 = 0xFFFFFFFFu;
        for (uint32_t i = 0; i < n; ++i)
        {
            uint32_t v0 = (((uint32_t)p[i] << 24) ^ v1) & 0xFF000000u;
            for (int k = 0; k < 8; ++k)
            {
                uint32_t a0 = (v0 << 1);
                if (v0 & 0x80000000u) a0 ^= 0x04C11DB7u;
                v0 = a0;
            }
            v1 = ((v1 << 8) ^ v0);
        }
        return ~v1;
    }

    inline void wrapH32abe0(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t job = getRegU32(ctx, 4);
        const uint32_t a1in = getRegU32(ctx, 5);
        const uint32_t a2in = getRegU32(ctx, 6);
        const uint32_t a3in = getRegU32(ctx, 7);
        uint32_t s30 = 0, s34 = 0, s38 = 0;
        primal_sif_rpc::readGuestU32(rdram, job + 0x30u, s30);
        primal_sif_rpc::readGuestU32(rdram, job + 0x34u, s34);
        primal_sif_rpc::readGuestU32(rdram, job + 0x38u, s38);
        static int s_n32abe0 = 0;
        if (s_n32abe0 < 25)
        {
            ++s_n32abe0;
            RUNTIME_LOG("[hot0x32abe0] #" << s_n32abe0 << " job=0x" << std::hex << job << " +30=0x" << s30 << " +34=0x" << s34 << " +38=0x" << s38 << " ra=0x" << getRegU32(ctx, 31) << std::dec << std::endl);
        }
        if (g_origH32abe0) g_origH32abe0(rdram, ctx, runtime);
        if (job == 0x489fa0u && a1in == 1u) { static const bool sf = [] { const char *e = std::getenv("PS2_FORCE_JOB_DONE"); return e != nullptr && e[0] == '1'; }(); if (sf) { static int sfc = 0; (void)primal_sif_rpc::writeGuestU32(rdram, job + 0x10u, 0u); if (sfc < 20) { ++sfc; RUNTIME_LOG("[forcejob] #" << sfc << " cleared 489fa0+0x10" << std::endl); } } }
        { static const bool sv = [] { const char *e = std::getenv("PS2_SERVE_SCENE"); return e != nullptr && e[0] == '1'; }(); if (sv && job == 0x489fa0u && a1in == 1u) { const uint32_t buf = a2in; const uint32_t reqsize = a3in; static uint32_t LBA = 10061u, SZ = 0x21a4u; { const char *el = std::getenv("PS2_SERVE_LBA"); if (el) LBA = (uint32_t)strtoul(el, nullptr, 0); const char *es = std::getenv("PS2_SERVE_SIZE"); if (es) SZ = (uint32_t)strtoul(es, nullptr, 0); } uint32_t n = reqsize < SZ ? reqsize : SZ; std::ifstream &img = ps2_game_overrides::primal_private_iop_rpc::streamCdImage(); uint8_t *host = nullptr; uint32_t avail = 0; if (img.is_open() && buf != 0 && primal_sif_rpc::mapGuestRange(rdram, buf + 0x10u, host, avail) && n <= avail) { img.clear(); img.seekg((std::streamoff)LBA * 2048, std::ios::beg); img.read((char *)host, n); uint32_t got = (uint32_t)img.gcount(); if (got > 0) { primal_sif_rpc::writeGuestU32(rdram, buf + 8u, got); primal_sif_rpc::writeGuestU32(rdram, buf + 4u, primalGuestCrc(host, got)); primal_sif_rpc::writeGuestU32(rdram, job + 0x10u, 0u); static int sc = 0; if (sc < 10) { ++sc; RUNTIME_LOG("[servescene] #" << sc << " buf=0x" << std::hex << buf << " served " << std::dec << got << "B lba=" << LBA << " crc=0x" << std::hex << primalGuestCrc(host, got) << std::dec << std::endl); } } } } }
    }
    inline PS2Runtime::RecompiledFunction g_origH32aca8 = nullptr;
    inline void wrapH32aca8(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t job = getRegU32(ctx, 4);
        uint32_t s30 = 0, s34 = 0, s38 = 0;
        primal_sif_rpc::readGuestU32(rdram, job + 0x30u, s30);
        primal_sif_rpc::readGuestU32(rdram, job + 0x34u, s34);
        primal_sif_rpc::readGuestU32(rdram, job + 0x38u, s38);
        static int s_n32aca8 = 0;
        if (s_n32aca8 < 25)
        {
            ++s_n32aca8;
            RUNTIME_LOG("[hot0x32aca8] #" << s_n32aca8 << " job=0x" << std::hex << job << " +30=0x" << s30 << " +34=0x" << s34 << " +38=0x" << s38 << " ra=0x" << getRegU32(ctx, 31) << std::dec << std::endl);
        }
        if (g_origH32aca8) g_origH32aca8(rdram, ctx, runtime);
    }
    inline PS2Runtime::RecompiledFunction g_origH32ab98 = nullptr;
    inline void wrapH32ab98(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t job = getRegU32(ctx, 4);
        uint32_t s30 = 0, s34 = 0, s38 = 0;
        primal_sif_rpc::readGuestU32(rdram, job + 0x30u, s30);
        primal_sif_rpc::readGuestU32(rdram, job + 0x34u, s34);
        primal_sif_rpc::readGuestU32(rdram, job + 0x38u, s38);
        static int s_n32ab98 = 0;
        if (s_n32ab98 < 25)
        {
            ++s_n32ab98;
            RUNTIME_LOG("[hot0x32ab98] #" << s_n32ab98 << " job=0x" << std::hex << job << " +30=0x" << s30 << " +34=0x" << s34 << " +38=0x" << s38 << " ra=0x" << getRegU32(ctx, 31) << std::dec << std::endl);
        }
        if (g_origH32ab98) g_origH32ab98(rdram, ctx, runtime);
    }
    inline PS2Runtime::RecompiledFunction g_origH32abb8 = nullptr;
    inline void wrapH32abb8(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t job = getRegU32(ctx, 4);
        uint32_t s30 = 0, s34 = 0, s38 = 0;
        primal_sif_rpc::readGuestU32(rdram, job + 0x30u, s30);
        primal_sif_rpc::readGuestU32(rdram, job + 0x34u, s34);
        primal_sif_rpc::readGuestU32(rdram, job + 0x38u, s38);
        static int s_n32abb8 = 0;
        if (s_n32abb8 < 25)
        {
            ++s_n32abb8;
            RUNTIME_LOG("[hot0x32abb8] #" << s_n32abb8 << " job=0x" << std::hex << job << " +30=0x" << s30 << " +34=0x" << s34 << " +38=0x" << s38 << " ra=0x" << getRegU32(ctx, 31) << std::dec << std::endl);
        }
        if (g_origH32abb8) g_origH32abb8(rdram, ctx, runtime);
    }
    inline PS2Runtime::RecompiledFunction g_origH32abd0 = nullptr;
    inline void wrapH32abd0(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t job = getRegU32(ctx, 4);
        uint32_t s30 = 0, s34 = 0, s38 = 0;
        primal_sif_rpc::readGuestU32(rdram, job + 0x30u, s30);
        primal_sif_rpc::readGuestU32(rdram, job + 0x34u, s34);
        primal_sif_rpc::readGuestU32(rdram, job + 0x38u, s38);
        static int s_n32abd0 = 0;
        if (s_n32abd0 < 25)
        {
            ++s_n32abd0;
            RUNTIME_LOG("[hot0x32abd0] #" << s_n32abd0 << " job=0x" << std::hex << job << " +30=0x" << s30 << " +34=0x" << s34 << " +38=0x" << s38 << " ra=0x" << getRegU32(ctx, 31) << std::dec << std::endl);
        }
        if (g_origH32abd0) g_origH32abd0(rdram, ctx, runtime);
    }
    inline void installHotClusterLoggers(PS2Runtime &runtime)
    {
        g_origH32a8a0 = runtime.lookupFunction(0x32A8A0u);
        if (g_origH32a8a0) runtime.replaceFunction(0x32A8A0u, &wrapH32a8a0);
        g_origH32a9e0 = runtime.lookupFunction(0x32A9E0u);
        if (g_origH32a9e0) runtime.replaceFunction(0x32A9E0u, &wrapH32a9e0);
        g_origH32abe0 = runtime.lookupFunction(0x32ABE0u);
        if (g_origH32abe0) runtime.replaceFunction(0x32ABE0u, &wrapH32abe0);
        g_origH32aca8 = runtime.lookupFunction(0x32ACA8u);
        if (g_origH32aca8) runtime.replaceFunction(0x32ACA8u, &wrapH32aca8);
        g_origH32ab98 = runtime.lookupFunction(0x32AB98u);
        if (g_origH32ab98) runtime.replaceFunction(0x32AB98u, &wrapH32ab98);
        g_origH32abb8 = runtime.lookupFunction(0x32ABB8u);
        if (g_origH32abb8) runtime.replaceFunction(0x32ABB8u, &wrapH32abb8);
        g_origH32abd0 = runtime.lookupFunction(0x32ABD0u);
        if (g_origH32abd0) runtime.replaceFunction(0x32ABD0u, &wrapH32abd0);
        RUNTIME_LOG("[hot] cluster loggers installed" << std::endl);
    }

    // Round 92: wrap FUN_0032a978 (chunk load issuer) with arg logging.
    inline PS2Runtime::RecompiledFunction g_orig32a978 = nullptr;
    inline void wrap32a978(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t job = getRegU32(ctx, 4);
        const uint32_t nameAddr = getRegU32(ctx, 5);
        const uint32_t buf = getRegU32(ctx, 6);
        const uint32_t size = getRegU32(ctx, 7);
        char name[33] = {};
        for (int i = 0; i < 32; ++i)
        {
            uint32_t w = 0;
            if (!primal_sif_rpc::readGuestU32(rdram, nameAddr + i * 4u, w)) break;
            name[i * 4] = w & 0xFF; name[i * 4 + 1] = (w >> 8) & 0xFF;
            name[i * 4 + 2] = (w >> 16) & 0xFF; name[i * 4 + 3] = (w >> 24) & 0xFF;
            if (name[i * 4] == 0) break;
        }
        if (g_orig32a978) g_orig32a978(rdram, ctx, runtime);
        { static const bool ft = [] { const char *e = std::getenv("PS2_FORCE_IO_THREAD"); return e != nullptr && e[0] == '1'; }(); static bool done = false; if (ft && !done && nameAddr != 0) { done = true; EeScheduler &ee = runtime->eeScheduler(); EeThreadCreateParams p; p.entry = 0x0032CF20u; p.stack = 0x01FF0000u; p.stackSize = 0x8000u; p.gp = getRegU32(ctx, 28); p.priority = 5; int id = ee.createThread(p); g_ioThreadId = id; int sr = (id > 0) ? ee.startThread(id, 1u, *ctx, false) : -1; RUNTIME_LOG("[forcethread] create id=" << id << " start=" << sr << " entry=0x32cf20" << std::endl); } }
        static int s_n = 0;
        if (s_n < 40)
        {
            ++s_n;
            RUNTIME_LOG("[load32a978] #" << s_n << " job=0x" << std::hex << job << " name=\"" << name
                        << "\" buf=0x" << buf << " size=0x" << size << " ret=0x" << getRegU32(ctx, 2) << std::dec << std::endl);
        }
    }

    // Round 94: wrap FUN_0032c238 (asset read issuer candidate) with arg logging.
    inline PS2Runtime::RecompiledFunction g_orig2830a0 = nullptr;
    inline void wrap2830a0(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t a0 = getRegU32(ctx, 4), a1 = getRegU32(ctx, 5), a2 = getRegU32(ctx, 6);
        const uint32_t ra = getRegU32(ctx, 31), sp = getRegU32(ctx, 29);
        uint32_t root = 0u;
        (void)primal_sif_rpc::readGuestU32(rdram, a1, root);
        // Walk leftmost chain (offset +0x10) until NIL sentinel 0x004DF350 to catch null/cycle before hanging in 0x283148.
        uint32_t cur = root;
        uint32_t steps = 0u;
        bool bad = (root == 0u);
        uint32_t badLeft = 0u, badRight = 0u;
        while (!bad && cur != 0x004DF350u && steps < 4096u)
        {
            uint32_t left = 0u, right = 0u;
            if (!primal_sif_rpc::readGuestU32(rdram, cur + 0x10u, left) || left == 0u)
            {
                (void)primal_sif_rpc::readGuestU32(rdram, cur + 0x14u, right);
                badLeft = left; badRight = right;
                bad = true;
                break;
            }
            if (left == 0x004DF350u) break;
            cur = left;
            ++steps;
        }
        if (steps >= 4096u) bad = true;
        if (bad)
        {
            static int s_badTreeLogs = 0;
            if (s_badTreeLogs < 8)
            {
                ++s_badTreeLogs;
                const uint64_t tickNow = runtime ? runtime->eeScheduler().currentVSyncTick() : 0ull;
                RUNTIME_LOG("[watch-2830a0] #" << std::dec << s_badTreeLogs
                            << " tick=" << tickNow
                            << " ra=0x" << std::hex << ra
                            << " sp=0x" << sp
                            << " a0=0x" << a0
                            << " a1(tree)=0x" << a1
                            << " a2(dir)=0x" << a2
                            << " root=0x" << root
                            << " badNode=0x" << cur
                            << " left=0x" << badLeft
                            << " right=0x" << badRight
                            << " steps=" << std::dec << steps << std::endl);
            }
            // Guard against infinite spin in FUN_002830d8 (0x283148): initialize iterator to NIL sentinel 0x004DF350.
            (void)primal_sif_rpc::writeGuestU32(rdram, a0 + 0x00u, a1);
            (void)primal_sif_rpc::writeGuestU32(rdram, a0 + 0x04u, a2);
            (void)primal_sif_rpc::writeGuestU32(rdram, a0 + 0x08u, 0x004DF350u);
            if (a1 != 0u) (void)primal_sif_rpc::writeGuestU32(rdram, a1 + 0x0Cu, a0);
            SET_GPR_U64(ctx, 2, a0);
            ctx->pc = ra;
            return;
        }
        if (g_orig2830a0) g_orig2830a0(rdram, ctx, runtime);
    }

    inline PS2Runtime::RecompiledFunction g_orig30f9f8 = nullptr;
    inline void wrap30f9f8(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        if (g_orig30f9f8) g_orig30f9f8(rdram, ctx, runtime);
        // Generalize the SMD FMV-background self-loop fix (State 18, State 25, etc.):
        // Whenever an SMD transition has inv=1 (expects FMV playing) AND dest_idx == cur_idx
        // (self-looping back to the same state when gp5d8c==0), report active (v0=1) so the
        // skipped FMV does not infinitely starve subsequent transitions into the Title Screen.
        if (getRegU32(ctx, 2) == 0u)
        {
            const uint32_t s5 = getRegU32(ctx, 21);
            const uint32_t s0 = getRegU32(ctx, 16);
            uint32_t flags = 0u;
            uint32_t s5Word = 0u, s0Word = 0u;
            if (s5 >= 0x100000u && s0 >= 0x100000u &&
                primal_sif_rpc::readGuestU32(rdram, s0 + 0x08u, flags) &&
                ((flags >> 1) & 1u) != 0u &&
                primal_sif_rpc::readGuestU32(rdram, s5 + 0x10u, s5Word) &&
                primal_sif_rpc::readGuestU32(rdram, s0 + 0x04u, s0Word))
            {
                const uint16_t curIdx = static_cast<uint16_t>(s5Word & 0xFFFFu);
                const int16_t dstIdx = static_cast<int16_t>(s0Word & 0xFFFFu);
                if (dstIdx == static_cast<int16_t>(curIdx))
                {
                    SET_GPR_U64(ctx, 2, 1u);
                }
            }
        }
    }

    inline PS2Runtime::RecompiledFunction g_orig3ebe18 = nullptr;
    inline void wrap3ebe18(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t workBuf = getRegU32(ctx, 5);
        const uint32_t workSize = getRegU32(ctx, 6);
        if (workBuf == 0u)
        {
            RUNTIME_LOG("[guard-3ebe18] blocked null sceMpegCreate work_buf=0x0 size=0x"
                        << std::hex << workSize << " ra=0x" << getRegU32(ctx, 31) << std::dec << std::endl);
            SET_GPR_U64(ctx, 2, 0u);
            ctx->pc = getRegU32(ctx, 31);
            return;
        }
        if (g_orig3ebe18) g_orig3ebe18(rdram, ctx, runtime);
    }

    inline PS2Runtime::RecompiledFunction g_orig32c238 = nullptr;
    inline void wrap32c238(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t a0 = getRegU32(ctx, 4), a1 = getRegU32(ctx, 5), a2 = getRegU32(ctx, 6), a3 = getRegU32(ctx, 7);
        const uint32_t ra = getRegU32(ctx, 31), sp = getRegU32(ctx, 29);
        uint32_t poolBefore = 0u, poolAfter = 0u;
        (void)primal_sif_rpc::readGuestU32(rdram, 0x004DF3B0u, poolBefore);
        if (g_orig32c238) g_orig32c238(rdram, ctx, runtime);
        (void)primal_sif_rpc::readGuestU32(rdram, 0x004DF3B0u, poolAfter);
        static int s_n = 0;
        if (s_n < 40)
        {
            ++s_n;
            RUNTIME_LOG("[req32c238] #" << s_n << " ra=0x" << std::hex << ra << " sp=0x" << sp
                        << " a0=0x" << a0 << " a1=0x" << a1 << " a2=0x" << a2 << " a3=0x" << a3
                        << " ret=0x" << getRegU32(ctx, 2)
                        << " 4df3b0=0x" << poolBefore << "->0x" << poolAfter << std::dec << std::endl);
        }
    }
    // Round 95: trace the 0x489fa0 ring-job issue path through the 0x3CAxxx SIF chain.
    inline PS2Runtime::RecompiledFunction g_orig3caa08 = nullptr;
    inline void wrap3caa08(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t a0 = getRegU32(ctx, 4), a1 = getRegU32(ctx, 5), a2 = getRegU32(ctx, 6), a3 = getRegU32(ctx, 7);
        if (g_orig3caa08) g_orig3caa08(rdram, ctx, runtime);
        static int s_n = 0;
        if (s_n < 40)
        {
            ++s_n;
            RUNTIME_LOG("[w3caa08] #" << s_n << " a0=0x" << std::hex << a0 << " a1=0x" << a1 << " a2=0x" << a2 << " a3=0x" << a3 << " ret=0x" << getRegU32(ctx, 2) << std::dec << std::endl);
        }
    }

    inline PS2Runtime::RecompiledFunction g_orig3ca848 = nullptr;
    inline PS2Runtime::RecompiledFunction g_origJalrTarget = nullptr;
    inline uint32_t g_jalrTargetAddr = 0;
    inline void wrapJalrTarget(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t a0 = getRegU32(ctx, 4), a1 = getRegU32(ctx, 5);
        if (g_origJalrTarget) g_origJalrTarget(rdram, ctx, runtime);
        static int s_n = 0;
        if (s_n < 40)
        {
            ++s_n;
            RUNTIME_LOG("[jalr->0x" << std::hex << g_jalrTargetAddr << "] #" << s_n << " a0=0x" << a0 << " a1=0x" << a1 << " ret=0x" << getRegU32(ctx, 2) << std::dec << std::endl);
        }
        static int s_dump = 0;
        if (s_dump < 6 && a1 != 0)
        {
            ++s_dump;
            std::ostringstream oss;
            oss << "[itemdump" << s_dump << "] a1=0x" << std::hex << a1 << " :";
            for (uint32_t off = 0; off < 0x30u; off += 4)
            {
                uint32_t w = 0;
                if (primal_sif_rpc::readGuestU32(rdram, a1 + off, w)) oss << " +0x" << std::hex << off << "=0x" << w;
            }
            RUNTIME_LOG(oss.str() << std::dec << std::endl);
        }
    }
    inline void wrap3ca848(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t a0 = getRegU32(ctx, 4);
        uint32_t f24 = 0, f2c = 0, f30 = 0;
        (void)primal_sif_rpc::readGuestU32(rdram, a0 + 0x24u, f24);
        (void)primal_sif_rpc::readGuestU32(rdram, a0 + 0x2Cu, f2c);
        (void)primal_sif_rpc::readGuestU32(rdram, a0 + 0x30u, f30);
        if (f2c != 0 && g_jalrTargetAddr == 0 && runtime != nullptr)
        {
            PS2Runtime::RecompiledFunction orig = runtime->lookupFunction(f2c);
            if (orig != nullptr)
            {
                g_origJalrTarget = orig;
                g_jalrTargetAddr = f2c;
                runtime->replaceFunction(f2c, &wrapJalrTarget);
            }
        }
        if (g_orig3ca848) g_orig3ca848(rdram, ctx, runtime);
        static int s_n = 0;
        if (s_n < 40)
        {
            ++s_n;
            RUNTIME_LOG("[w3ca848] #" << s_n << " a0=0x" << std::hex << a0 << " +24=0x" << f24 << " +2c=0x" << f2c << " +30=0x" << f30 << " ret=0x" << getRegU32(ctx, 2) << std::dec << std::endl);
        }
    }

    inline PS2Runtime::RecompiledFunction g_orig3ccec0 = nullptr;
    inline void wrap3ccec0(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t a1 = getRegU32(ctx, 5);
        uint32_t vt2c = 0, arg30 = 0;
        (void)primal_sif_rpc::readGuestU32(rdram, a1 + 0x2Cu, vt2c);
        (void)primal_sif_rpc::readGuestU32(rdram, a1 + 0x30u, arg30);
        if (g_orig3ccec0) g_orig3ccec0(rdram, ctx, runtime);
        static int s_n = 0;
        if (s_n < 40)
        {
            ++s_n;
            RUNTIME_LOG("[w3ccec0] #" << s_n << " a1=0x" << std::hex << a1 << " vt+2c=0x" << vt2c << " arg+30=0x" << arg30 << std::dec << std::endl);
        }
    }

    // Round 97: log FUN_0028a798 (queue signal) args.
    inline PS2Runtime::RecompiledFunction g_orig28a798 = nullptr;
    inline void wrap28a798(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t a0 = getRegU32(ctx, 4), a1 = getRegU32(ctx, 5);
        if (g_orig28a798) g_orig28a798(rdram, ctx, runtime);
        static int s_n = 0;
        if (s_n < 30)
        {
            ++s_n;
            RUNTIME_LOG("[sig28a798] #" << s_n << " a0=0x" << std::hex << a0 << " a1=0x" << a1 << " ret=0x" << getRegU32(ctx, 2) << std::dec << std::endl);
        }
    }

    // Round 114: wrap entry_0032cf20 (caller of consumer 0x32b168) — unique name, no existing wrap.
    inline PS2Runtime::RecompiledFunction g_orig32cf20u = nullptr;
    inline void wrap32cf20u(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t a0 = getRegU32(ctx, 4), a1 = getRegU32(ctx, 5), a2 = getRegU32(ctx, 6), a3 = getRegU32(ctx, 7);
        SET_GPR_U64(ctx, 18, 1);
        { const uint32_t gp = getRegU32(ctx, 28); const uint32_t ga = gp + 0xFFFFB1F8u; uint32_t gv = 0; (void)primal_sif_rpc::readGuestU32(rdram, ga, gv); static int sg = 0; if (sg < 6) { ++sg; RUNTIME_LOG("[cf20gp] #" << sg << " gp=0x" << std::hex << gp << " spinaddr=0x" << ga << " val=0x" << gv << std::dec << std::endl); } (void)primal_sif_rpc::writeGuestU32(rdram, ga, 0u); }
        if (g_orig32cf20u) g_orig32cf20u(rdram, ctx, runtime);
        static int s_n = 0;
        if (s_n < 30) { ++s_n; RUNTIME_LOG("[32cf20u] #" << s_n << " a0=0x" << std::hex << a0 << " a1=0x" << a1 << " a2=0x" << a2 << " a3=0x" << a3 << " ret=0x" << getRegU32(ctx, 2) << std::dec << std::endl); }
    }

    // Round 103: wrap FUN_0032b168 (queue consumer / read issuer caller).
    inline PS2Runtime::RecompiledFunction g_orig32b168 = nullptr;
    inline void wrap32b168(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t a0 = getRegU32(ctx, 4), a1 = getRegU32(ctx, 5), a2 = getRegU32(ctx, 6);
        const uint32_t gp = getRegU32(ctx, 28);
        { static const bool fi = [] { const char *e = std::getenv("PS2_FORCE_ISSUE"); return e != nullptr && e[0] == '1'; }(); static int fn = 0; if (fi && fn < 10) { ++fn; RUNTIME_LOG("[32b168] gp=0x" << std::hex << gp << " gate=0x" << (gp + 0xFFFFF3B4u) << std::dec << std::endl); } if (fi) (void)primal_sif_rpc::writeGuestU32(rdram, gp + 0xFFFFF3B4u, 1u); }
        if (g_orig32b168) g_orig32b168(rdram, ctx, runtime);
        static int s_n = 0;
        if (s_n < 40) { ++s_n; RUNTIME_LOG("[32b168] #" << s_n << " a0=0x" << std::hex << a0 << " a1=0x" << a1 << " a2=0x" << a2 << " ret=0x" << getRegU32(ctx, 2) << std::dec << std::endl); }
    }

    // Round 102: wrap entry_0032b798 (TOCS resolver caller / scene load path) to capture entry args + hash.
    inline PS2Runtime::RecompiledFunction g_orig32b798 = nullptr;
    inline void wrap32b798(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t a0 = getRegU32(ctx, 4), a1 = getRegU32(ctx, 5), a2 = getRegU32(ctx, 6), a3 = getRegU32(ctx, 7);
        if (g_orig32b798) g_orig32b798(rdram, ctx, runtime);
        static int s_n = 0;
        if (s_n < 40) { ++s_n; RUNTIME_LOG("[32b798] #" << s_n << " a0=0x" << std::hex << a0 << " a1=0x" << a1 << " a2=0x" << a2 << " a3=0x" << a3 << " ret=0x" << getRegU32(ctx, 2) << std::dec << std::endl); }
    }

    // Round 98: wrap FUN_003a3940 (stream-ready gate): log client and client+0x3C; PS2_STREAM_FORCE_READY=1 forces it to 1.
    inline PS2Runtime::RecompiledFunction g_orig3a3940 = nullptr;
    inline void wrap3a3940(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t a0 = getRegU32(ctx, 4);
        uint32_t client = 0, ready = 0;
        (void)primal_sif_rpc::readGuestU32(rdram, a0 + 0x800u, client);
        if (client) (void)primal_sif_rpc::readGuestU32(rdram, client + 0x3Cu, ready);
        if (g_orig3a3940) g_orig3a3940(rdram, ctx, runtime);
        uint32_t ret = getRegU32(ctx, 2);
        static int s_n = 0;
        if (s_n < 30) { ++s_n; RUNTIME_LOG("[gate3a3940] #" << s_n << " a0=0x" << std::hex << a0 << " client=0x" << client << " +3c=0x" << ready << " ret=0x" << ret << std::dec << std::endl); }
        {
            static const bool sf = [] { const char *e = std::getenv("PS2_STREAM_FORCE_READY"); return e != nullptr && e[0] == '1'; }();
            if (sf && client != 0 && ret == 0) { (void)primal_sif_rpc::writeGuestU32(rdram, client + 0x3Cu, 1u); static int s_f = 0; if (s_f < 10) { ++s_f; RUNTIME_LOG("[forceready] #" << s_f << " client=0x" << std::hex << client << std::endl); } }
        }
    }

    // Round 95: log the pump decision fields in FUN_0032aca8 (job+0x10 vs entry v0).
    inline PS2Runtime::RecompiledFunction g_orig32aca8 = nullptr;
    inline void wrap32aca8(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        const uint32_t job = getRegU32(ctx, 4);
        const uint32_t v0in = getRegU32(ctx, 2);
        uint32_t j10 = 0; uint32_t bufp = 0; (void)primal_sif_rpc::readGuestU32(rdram, job + 4u, bufp);
        (void)primal_sif_rpc::readGuestU32(rdram, job + 0x10u, j10);
        if (g_orig32aca8) g_orig32aca8(rdram, ctx, runtime);
        static int s_n = 0;
        if (s_n < 40)
        {
            ++s_n;
            RUNTIME_LOG("[pump32aca8] #" << s_n << " job=0x" << std::hex << job << " +10=0x" << j10 << " v0in=0x" << v0in << " buf=0x" << bufp << " ret=0x" << getRegU32(ctx, 2) << std::dec << std::endl);
        }
        // Round 98 experiment: PS2_FORCE_JOB_DONE=1 clears job+0x10 on the 0x489fa0 scene
        // node so the NEXT pump takes the finalize path (writes sg09 magic to buf[0]).
        {
            static const bool s_force = [] { const char *e = std::getenv("PS2_FORCE_JOB_DONE"); return e != nullptr && e[0] == '1'; }();
            if (s_force && job == 0x489fa0u)
            {
                static int s_f = 0;
                (void)primal_sif_rpc::writeGuestU32(rdram, job + 0x10u, 0u); if (g_ioThreadId > 0) (void)runtime->eeScheduler().wakeupThread(g_ioThreadId, false);
                if (s_f < 20) { ++s_f; RUNTIME_LOG("[forcejobdone] #" << s_f << " cleared job+0x10" << std::endl); }
            }
        }
        static int s_dump = 0;
        if (s_dump < 4)
        {
            ++s_dump;
            std::ostringstream oss;
            oss << "[pumpdump" << s_dump << "] job=0x" << std::hex << job << " :";
            for (uint32_t off = 0; off < 0xc0u; off += 4)
            {
                uint32_t w = 0;
                if (primal_sif_rpc::readGuestU32(rdram, job + off, w)) oss << " +0x" << std::hex << off << "=0x" << w;
            }
            uint32_t buf = 0;
            if (primal_sif_rpc::readGuestU32(rdram, job + 4u, buf) && buf != 0)
            {
                oss << " | buf=0x" << buf << " :";
                for (uint32_t off = 0; off < 0x20u; off += 4)
                {
                    uint32_t w = 0;
                    if (primal_sif_rpc::readGuestU32(rdram, buf + off, w)) oss << " +0x" << std::hex << off << "=0x" << w;
                }
            }
            RUNTIME_LOG(oss.str() << std::dec << std::endl);
        }
    }

    inline void wrap104808(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        static bool s_logged = false;
        if (!s_logged)
        {
            s_logged = true;
            RUNTIME_LOG("[scene-probe] ENTER 0x104808 ra=0x" << std::hex << getRegU32(ctx, 31)
                        << " a0=0x" << getRegU32(ctx, 4) << std::dec << std::endl);
        }
        if (g_orig104808) g_orig104808(rdram, ctx, runtime);
    }

    // Complete override for 0x001036C8..0x00103A18 (entry_001036c8 + entry_00103938 + epilogue of entry_001039ec)
    // Fixes split-TU return at 0x1039E8/0x1039EC ($sp -0x80 leak) and internal jump-table dispatch at 0x1038E8.
    inline void func1036c8Override(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        switch (ctx->pc) {
            case 0x10370cu: goto label_10370c;
            case 0x103714u: goto label_103714;
            case 0x103758u: goto label_103758;
            case 0x103770u: goto label_103770;
            case 0x1037a8u: goto label_1037a8;
            case 0x103804u: goto label_103804;
            case 0x103854u: goto label_103854;
            case 0x103920u: goto label_103920;
            case 0x103938u: goto label_103938;
            case 0x103950u: goto label_103950;
            case 0x10395cu: goto label_10395c;
            case 0x103968u: goto label_103968;
            case 0x103984u: goto label_103984;
            case 0x1039a0u: goto label_1039a0;
            case 0x1039e8u: goto label_1039e8;
            case 0x1039ecu: goto label_1039ec;
            default: break;
        }

        ctx->pc = 0x1036c8u;
        SET_GPR_S32(ctx, 29, (int32_t)ADD32(GPR_U32(ctx, 29), 4294967168));
        ctx->pc = 0x1036ccu;
        WRITE128(ADD32(GPR_U32(ctx, 29), 48), GPR_VEC(ctx, 19));
        ctx->pc = 0x1036d0u;
        SET_GPR_U64(ctx, 19, (uint64_t)GPR_U64(ctx, 4) + (uint64_t)GPR_U64(ctx, 0));
        ctx->pc = 0x1036d4u;
        WRITE128(ADD32(GPR_U32(ctx, 29), 80), GPR_VEC(ctx, 21));
        ctx->pc = 0x1036d8u;
        SET_GPR_S32(ctx, 4, (int32_t)((uint32_t)79 << 16));
        ctx->pc = 0x1036dcu;
        WRITE128(ADD32(GPR_U32(ctx, 29), 96), GPR_VEC(ctx, 22));
        ctx->pc = 0x1036e0u;
        WRITE128(ADD32(GPR_U32(ctx, 29), 64), GPR_VEC(ctx, 20));
        ctx->pc = 0x1036e4u;
        SET_GPR_U64(ctx, 21, (uint64_t)GPR_U64(ctx, 4) + (uint64_t)GPR_U64(ctx, 0));
        ctx->pc = 0x1036e8u;
        WRITE128(ADD32(GPR_U32(ctx, 29), 32), GPR_VEC(ctx, 18));
        ctx->pc = 0x1036ecu;
        SET_GPR_U64(ctx, 20, (uint64_t)GPR_U64(ctx, 5) + (uint64_t)GPR_U64(ctx, 0));
        ctx->pc = 0x1036f0u;
        WRITE128(ADD32(GPR_U32(ctx, 29), 112), GPR_VEC(ctx, 31));
        ctx->pc = 0x1036f4u;
        SET_GPR_U64(ctx, 18, (uint64_t)GPR_U64(ctx, 6) + (uint64_t)GPR_U64(ctx, 0));
        ctx->pc = 0x1036f8u;
        WRITE128(ADD32(GPR_U32(ctx, 29), 16), GPR_VEC(ctx, 17));
        ctx->pc = 0x1036fcu;
        SET_GPR_U64(ctx, 22, (uint64_t)GPR_U64(ctx, 7) + (uint64_t)GPR_U64(ctx, 0));
        ctx->pc = 0x103700u;
        WRITE128(ADD32(GPR_U32(ctx, 29), 0), GPR_VEC(ctx, 16));
        ctx->pc = 0x103704u;
        SET_GPR_U32(ctx, 31, 0x10370Cu);
        ctx->pc = 0x103708u;
        ctx->in_delay_slot = true;
        ctx->branch_pc = 0x103704u;
        SET_GPR_S32(ctx, 4, (int32_t)ADD32(GPR_U32(ctx, 4), 7920));
        ctx->in_delay_slot = false;
        ctx->pc = 0x2F5FD8u;
        if (!runtime->dispatchGuestBranch(rdram, ctx, 0x2F5FD8u, 0x103704u, 0x10370Cu, PS2Runtime::GuestBranchKind::DirectCall, "JAL")) {
            return;
        }
        ctx->pc = 0x10370Cu;
    label_10370c:
        ctx->pc = 0x10370Cu;
        SET_GPR_U32(ctx, 31, 0x103714u);
        ctx->pc = 0x103710u;
        ctx->in_delay_slot = true;
        ctx->branch_pc = 0x10370Cu;
        SET_GPR_U64(ctx, 4, (uint64_t)GPR_U64(ctx, 0) + (uint64_t)GPR_U64(ctx, 0));
        ctx->in_delay_slot = false;
        ctx->pc = 0x2F5E88u;
        if (!runtime->dispatchGuestBranch(rdram, ctx, 0x2F5E88u, 0x10370Cu, 0x103714u, PS2Runtime::GuestBranchKind::DirectCall, "JAL")) {
            return;
        }
        ctx->pc = 0x103714u;
    label_103714:
        ctx->pc = 0x103714u;
        SET_GPR_S32(ctx, 3, (int32_t)((uint32_t)73 << 16));
        ctx->pc = 0x103718u;
        SET_GPR_S32(ctx, 3, (int32_t)FAST_READ32(0x488390u));
        ctx->pc = 0x10371cu;
        SET_GPR_S32(ctx, 2, (int32_t)READ32(ADD32(GPR_U32(ctx, 3), 100)));
        ctx->pc = 0x103720u;
        {
            const bool branch_taken_0x103720 = (GPR_U64(ctx, 2) == GPR_U64(ctx, 0));
            ctx->pc = 0x103724u;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x103720u;
            SET_GPR_S32(ctx, 17, (int32_t)READ32(ADD32(GPR_U32(ctx, 28), 4294935172)));
            ctx->in_delay_slot = false;
            if (branch_taken_0x103720) {
                ctx->pc = 0x1037A8u;
                goto label_1037a8;
            }
        }
        ctx->pc = 0x103728u;
        SET_GPR_S32(ctx, 2, (int32_t)ADD32(GPR_U32(ctx, 0), 5));
        ctx->pc = 0x10372Cu;
        {
            const bool branch_taken_0x10372c = (GPR_U64(ctx, 17) != GPR_U64(ctx, 2));
            ctx->pc = 0x103730u;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x10372Cu;
            SET_GPR_S32(ctx, 2, (int32_t)ADD32(GPR_U32(ctx, 0), 6));
            ctx->in_delay_slot = false;
            if (branch_taken_0x10372c) {
                ctx->pc = 0x103780u;
                goto label_103780;
            }
        }
        ctx->pc = 0x103734u;
        SET_GPR_S32(ctx, 2, (int32_t)READ32(ADD32(GPR_U32(ctx, 3), 32)));
        ctx->pc = 0x103738u;
        SET_GPR_S32(ctx, 16, (int32_t)((uint32_t)72 << 16));
        ctx->pc = 0x10373cu;
        WRITE32(ADD32(GPR_U32(ctx, 3), 100), GPR_U32(ctx, 0));
        ctx->pc = 0x103740u;
        SET_GPR_S32(ctx, 16, (int32_t)ADD32(GPR_U32(ctx, 16), 21896));
        ctx->pc = 0x103744u;
        SET_GPR_S32(ctx, 6, (int32_t)((uint32_t)67 << 16));
        ctx->pc = 0x103748u;
        SET_GPR_U64(ctx, 5, (uint64_t)GPR_U64(ctx, 16) + (uint64_t)GPR_U64(ctx, 0));
        ctx->pc = 0x10374cu;
        SET_GPR_S32(ctx, 4, (int32_t)READ32(ADD32(GPR_U32(ctx, 2), 8)));
        ctx->pc = 0x103750u;
        SET_GPR_U32(ctx, 31, 0x103758u);
        ctx->pc = 0x103754u;
        ctx->in_delay_slot = true;
        ctx->branch_pc = 0x103750u;
        SET_GPR_S32(ctx, 6, (int32_t)ADD32(GPR_U32(ctx, 6), 4294966264));
        ctx->in_delay_slot = false;
        ctx->pc = 0x2E59E0u;
        if (!runtime->dispatchGuestBranch(rdram, ctx, 0x2E59E0u, 0x103750u, 0x103758u, PS2Runtime::GuestBranchKind::DirectCall, "JAL")) {
            return;
        }
        ctx->pc = 0x103758u;
    label_103758:
        ctx->pc = 0x103758u;
        SET_GPR_S32(ctx, 3, (int32_t)((uint32_t)73 << 16));
        ctx->pc = 0x10375cu;
        SET_GPR_S32(ctx, 3, (int32_t)FAST_READ32(0x488390u));
        ctx->pc = 0x103760u;
        SET_GPR_U64(ctx, 5, (uint64_t)GPR_U64(ctx, 16) + (uint64_t)GPR_U64(ctx, 0));
        ctx->pc = 0x103764u;
        SET_GPR_S32(ctx, 2, (int32_t)READ32(ADD32(GPR_U32(ctx, 3), 32)));
        ctx->pc = 0x103768u;
        SET_GPR_U32(ctx, 31, 0x103770u);
        ctx->pc = 0x10376Cu;
        ctx->in_delay_slot = true;
        ctx->branch_pc = 0x103768u;
        SET_GPR_S32(ctx, 4, (int32_t)READ32(ADD32(GPR_U32(ctx, 2), 8)));
        ctx->in_delay_slot = false;
        ctx->pc = 0x2E5A68u;
        if (!runtime->dispatchGuestBranch(rdram, ctx, 0x2E5A68u, 0x103768u, 0x103770u, PS2Runtime::GuestBranchKind::DirectCall, "JAL")) {
            return;
        }
        ctx->pc = 0x103770u;
    label_103770:
        ctx->pc = 0x103770u;
        SET_GPR_S32(ctx, 2, (int32_t)((uint32_t)73 << 16));
        ctx->pc = 0x103774u;
        SET_GPR_S32(ctx, 2, (int32_t)FAST_READ32(0x488390u));
        ctx->pc = 0x103778u;
        {
            const bool branch_taken_0x103778 = (GPR_U64(ctx, 0) == GPR_U64(ctx, 0));
            ctx->pc = 0x10377Cu;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x103778u;
            WRITE32(ADD32(GPR_U32(ctx, 2), 12), GPR_U32(ctx, 17));
            ctx->in_delay_slot = false;
            if (branch_taken_0x103778) {
                ctx->pc = 0x1037A8u;
                goto label_1037a8;
            }
        }
        ctx->pc = 0x103780u;
    label_103780:
        ctx->pc = 0x103780u;
        {
            const bool branch_taken_0x103780 = (GPR_U64(ctx, 17) != GPR_U64(ctx, 2));
            ctx->pc = 0x103784u;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x103780u;
            SET_GPR_S32(ctx, 2, (int32_t)READ32(ADD32(GPR_U32(ctx, 28), 4294946464)));
            ctx->in_delay_slot = false;
            if (branch_taken_0x103780) {
                ctx->pc = 0x1037B0u;
                goto label_1037b0;
            }
        }
        ctx->pc = 0x103788u;
        SET_GPR_S32(ctx, 2, (int32_t)READ32(ADD32(GPR_U32(ctx, 3), 32)));
        ctx->pc = 0x10378cu;
        SET_GPR_S32(ctx, 5, (int32_t)((uint32_t)72 << 16));
        ctx->pc = 0x103790u;
        WRITE32(ADD32(GPR_U32(ctx, 3), 100), GPR_U32(ctx, 0));
        ctx->pc = 0x103794u;
        SET_GPR_S32(ctx, 6, (int32_t)((uint32_t)67 << 16));
        ctx->pc = 0x103798u;
        SET_GPR_S32(ctx, 5, (int32_t)ADD32(GPR_U32(ctx, 5), 21896));
        ctx->pc = 0x10379cu;
        SET_GPR_S32(ctx, 6, (int32_t)ADD32(GPR_U32(ctx, 6), 4294966280));
        ctx->pc = 0x1037A0u;
        SET_GPR_U32(ctx, 31, 0x1037A8u);
        ctx->pc = 0x1037A4u;
        ctx->in_delay_slot = true;
        ctx->branch_pc = 0x1037A0u;
        SET_GPR_S32(ctx, 4, (int32_t)READ32(ADD32(GPR_U32(ctx, 2), 8)));
        ctx->in_delay_slot = false;
        ctx->pc = 0x2E59E0u;
        if (!runtime->dispatchGuestBranch(rdram, ctx, 0x2E59E0u, 0x1037A0u, 0x1037A8u, PS2Runtime::GuestBranchKind::DirectCall, "JAL")) {
            return;
        }
        ctx->pc = 0x1037A8u;
    label_1037a8:
        ctx->pc = 0x1037a8u;
        SET_GPR_S32(ctx, 2, (int32_t)((uint32_t)73 << 16));
        ctx->pc = 0x1037acu;
        SET_GPR_S32(ctx, 2, (int32_t)FAST_READ32(0x488390u));
    label_1037b0:
        ctx->pc = 0x1037b0u;
        SET_GPR_S32(ctx, 3, (int32_t)READ32(ADD32(GPR_U32(ctx, 2), 96)));
        ctx->pc = 0x1037B4u;
        {
            const bool branch_taken_0x1037b4 = (GPR_U64(ctx, 3) == GPR_U64(ctx, 0));
            ctx->pc = 0x1037B8u;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x1037B4u;
            SET_GPR_S32(ctx, 2, (int32_t)READ32(ADD32(GPR_U32(ctx, 28), 4294935192)));
            ctx->in_delay_slot = false;
            if (branch_taken_0x1037b4) {
                ctx->pc = 0x1038A4u;
                goto label_1038a4;
            }
        }
        ctx->pc = 0x1037BCu;
        {
            const bool branch_taken_0x1037bc = (GPR_U64(ctx, 2) != GPR_U64(ctx, 0));
            ctx->pc = 0x1037C0u;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x1037BCu;
            SET_GPR_U64(ctx, 3, (uint64_t)GPR_U64(ctx, 0) + (uint64_t)GPR_U64(ctx, 0));
            ctx->in_delay_slot = false;
            if (branch_taken_0x1037bc) {
                ctx->pc = 0x1037D4u;
                goto label_1037d4;
            }
        }
        ctx->pc = 0x1037c4u;
        SET_GPR_S32(ctx, 2, (int32_t)((uint32_t)72 << 16));
        ctx->pc = 0x1037c8u;
        SET_GPR_S32(ctx, 2, (int32_t)FAST_READ32(0x485794u));
        ctx->pc = 0x1037ccu;
        SET_GPR_U64(ctx, 2, ~(GPR_U64(ctx, 0) | GPR_U64(ctx, 2)));
        ctx->pc = 0x1037d0u;
        SET_GPR_U64(ctx, 3, ((uint64_t)GPR_U64(ctx, 0) < (uint64_t)GPR_U64(ctx, 2)) ? 1 : 0);
    label_1037d4:
        ctx->pc = 0x1037D4u;
        {
            const bool branch_taken_0x1037d4 = (GPR_U64(ctx, 3) == GPR_U64(ctx, 0));
            ctx->pc = 0x1037D8u;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x1037D4u;
            SET_GPR_S32(ctx, 2, (int32_t)READ32(ADD32(GPR_U32(ctx, 28), 4294935204)));
            ctx->in_delay_slot = false;
            if (branch_taken_0x1037d4) {
                ctx->pc = 0x103878u;
                goto label_103878;
            }
        }
        ctx->pc = 0x1037dcu;
        SET_GPR_S32(ctx, 17, (int32_t)ADD32(GPR_U32(ctx, 0), 96));
        ctx->pc = 0x1037e0u;
        SET_GPR_S32(ctx, 16, (int32_t)((uint32_t)80 << 16));
        ctx->pc = 0x1037e4u;
        SET_GPR_S32(ctx, 4, (int32_t)((uint32_t)66 << 16));
        ctx->pc = 0x1037e8u;
        { int64_t result = (int64_t)GPR_S32(ctx, 2) * (int64_t)GPR_S32(ctx, 17); ctx->lo = (uint64_t)(int64_t)(int32_t)result; ctx->hi = (uint64_t)(int64_t)(int32_t)(result >> 32); SET_GPR_S32(ctx, 2, (int32_t)result); }
        ctx->pc = 0x1037ecu;
        SET_GPR_S32(ctx, 16, (int32_t)ADD32(GPR_U32(ctx, 16), 4294962432));
        ctx->pc = 0x1037f0u;
        SET_GPR_S32(ctx, 4, (int32_t)ADD32(GPR_U32(ctx, 4), 9376));
        ctx->pc = 0x1037f4u;
        SET_GPR_S32(ctx, 2, (int32_t)ADD32(GPR_U32(ctx, 16), GPR_U32(ctx, 2)));
        ctx->pc = 0x1037f8u;
        SET_GPR_S32(ctx, 5, (int32_t)READ32(ADD32(GPR_U32(ctx, 2), 4)));
        ctx->pc = 0x1037FCu;
        SET_GPR_U32(ctx, 31, 0x103804u);
        ctx->pc = 0x103800u;
        ctx->in_delay_slot = true;
        ctx->branch_pc = 0x1037FCu;
        SET_GPR_S32(ctx, 5, (int32_t)ADD32(GPR_U32(ctx, 5), 12));
        ctx->in_delay_slot = false;
        ctx->pc = 0x3FD2B8u;
        if (!runtime->dispatchGuestBranch(rdram, ctx, 0x3FD2B8u, 0x1037FCu, 0x103804u, PS2Runtime::GuestBranchKind::DirectCall, "JAL")) {
            return;
        }
        ctx->pc = 0x103804u;
    label_103804:
        ctx->pc = 0x103804u;
        SET_GPR_S32(ctx, 4, (int32_t)((uint32_t)72 << 16));
        ctx->pc = 0x103808u;
        SET_GPR_S32(ctx, 4, (int32_t)FAST_READ32(0x485794u));
        ctx->pc = 0x10380cu;
        SET_GPR_S32(ctx, 8, (int32_t)ADD32(GPR_U32(ctx, 0), 4294967295));
        ctx->pc = 0x103810u;
        SET_GPR_S32(ctx, 2, (int32_t)((uint32_t)73 << 16));
        ctx->pc = 0x103814u;
        SET_GPR_S32(ctx, 2, (int32_t)FAST_READ32(0x488390u));
        ctx->pc = 0x103818u;
        SET_GPR_S32(ctx, 9, (int32_t)ADD32(GPR_U32(ctx, 0), 1));
        ctx->pc = 0x10381cu;
        { int64_t result = (int64_t)GPR_S32(ctx, 4) * (int64_t)GPR_S32(ctx, 17); ctx->lo = (uint64_t)(int64_t)(int32_t)result; ctx->hi = (uint64_t)(int64_t)(int32_t)(result >> 32); SET_GPR_S32(ctx, 3, (int32_t)result); }
        ctx->pc = 0x103820u;
        SET_GPR_S32(ctx, 5, (int32_t)((uint32_t)72 << 16));
        ctx->pc = 0x103824u;
        SET_GPR_S32(ctx, 7, (int32_t)READ32(ADD32(GPR_U32(ctx, 2), 32)));
        ctx->pc = 0x103828u;
        SET_GPR_S32(ctx, 6, (int32_t)((uint32_t)67 << 16));
        ctx->pc = 0x10382cu;
        SET_GPR_S32(ctx, 5, (int32_t)ADD32(GPR_U32(ctx, 5), 21896));
        ctx->pc = 0x103830u;
        SET_GPR_S32(ctx, 6, (int32_t)ADD32(GPR_U32(ctx, 6), 4294966296));
        ctx->pc = 0x103834u;
        SET_GPR_S32(ctx, 4, (int32_t)ADD32(GPR_U32(ctx, 3), GPR_U32(ctx, 16)));
        ctx->pc = 0x103838u;
        SET_GPR_S32(ctx, 3, (int16_t)READ16(ADD32(GPR_U32(ctx, 4), 92)));
        ctx->pc = 0x10383cu;
        WRITE32(ADD32(GPR_U32(ctx, 2), 4), GPR_U32(ctx, 8));
        ctx->pc = 0x103840u;
        WRITE32(ADD32(GPR_U32(ctx, 2), 0), GPR_U32(ctx, 3));
        ctx->pc = 0x103844u;
        WRITE32(ADD32(GPR_U32(ctx, 2), 100), GPR_U32(ctx, 9));
        ctx->pc = 0x103848u;
        WRITE32(ADD32(GPR_U32(ctx, 2), 96), GPR_U32(ctx, 0));
        ctx->pc = 0x10384Cu;
        SET_GPR_U32(ctx, 31, 0x103854u);
        ctx->pc = 0x103850u;
        ctx->in_delay_slot = true;
        ctx->branch_pc = 0x10384Cu;
        SET_GPR_S32(ctx, 4, (int32_t)READ32(ADD32(GPR_U32(ctx, 7), 8)));
        ctx->in_delay_slot = false;
        ctx->pc = 0x2E59E0u;
        if (!runtime->dispatchGuestBranch(rdram, ctx, 0x2E59E0u, 0x10384Cu, 0x103854u, PS2Runtime::GuestBranchKind::DirectCall, "JAL")) {
            return;
        }
        ctx->pc = 0x103854u;
    label_103854:
        ctx->pc = 0x103854u;
        SET_GPR_S32(ctx, 2, (int32_t)((uint32_t)72 << 16));
        ctx->pc = 0x103858u;
        SET_GPR_S32(ctx, 2, (int32_t)FAST_READ32(0x485770u));
        ctx->pc = 0x10385Cu;
        {
            const bool branch_taken_0x10385c = (GPR_U64(ctx, 2) != GPR_U64(ctx, 0));
            ctx->pc = 0x103860u;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x10385Cu;
            SET_GPR_S32(ctx, 2, (int32_t)READ32(ADD32(GPR_U32(ctx, 28), 4294935192)));
            ctx->in_delay_slot = false;
            if (branch_taken_0x10385c) {
                ctx->pc = 0x103880u;
                goto label_103880;
            }
        }
        ctx->pc = 0x103864u;
        SET_GPR_S32(ctx, 2, (int32_t)ADD32(GPR_U32(ctx, 0), 26));
        ctx->pc = 0x103868u;
        SET_GPR_S32(ctx, 1, (int32_t)((uint32_t)72 << 16));
        ctx->pc = 0x10386cu;
        do { uint32_t _value = static_cast<uint32_t>(GPR_U32(ctx, 0)); ps2TraceGuestWrite(rdram, 0x485774u, 4u, _value, 0u, "WRITE32", ctx); FAST_WRITE32(0x485774u, _value); } while (0);
        ctx->pc = 0x103870u;
        SET_GPR_S32(ctx, 1, (int32_t)((uint32_t)72 << 16));
        ctx->pc = 0x103874u;
        do { uint32_t _value = static_cast<uint32_t>(GPR_U32(ctx, 2)); ps2TraceGuestWrite(rdram, 0x485770u, 4u, _value, 0u, "WRITE32", ctx); FAST_WRITE32(0x485770u, _value); } while (0);
    label_103878:
        ctx->pc = 0x103878u;
        SET_GPR_S32(ctx, 2, (int32_t)((uint32_t)72 << 16));
        ctx->pc = 0x10387cu;
        SET_GPR_S32(ctx, 2, (int32_t)FAST_READ32(0x485788u));
    label_103880:
        ctx->pc = 0x103880u;
        {
            const bool branch_taken_0x103880 = (GPR_U64(ctx, 2) != GPR_U64(ctx, 0));
            ctx->pc = 0x103884u;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x103880u;
            SET_GPR_U64(ctx, 3, (uint64_t)GPR_U64(ctx, 0) + (uint64_t)GPR_U64(ctx, 0));
            ctx->in_delay_slot = false;
            if (branch_taken_0x103880) {
                ctx->pc = 0x103898u;
                goto label_103898;
            }
        }
        ctx->pc = 0x103888u;
        SET_GPR_S32(ctx, 2, (int32_t)((uint32_t)72 << 16));
        ctx->pc = 0x10388cu;
        SET_GPR_S32(ctx, 2, (int32_t)FAST_READ32(0x485794u));
        ctx->pc = 0x103890u;
        SET_GPR_U64(ctx, 2, ~(GPR_U64(ctx, 0) | GPR_U64(ctx, 2)));
        ctx->pc = 0x103894u;
        SET_GPR_U64(ctx, 3, ((uint64_t)GPR_U64(ctx, 2) < (uint64_t)(int64_t)(int32_t)1) ? 1 : 0);
    label_103898:
        ctx->pc = 0x103898u;
        {
            const bool branch_taken_0x103898 = (GPR_U64(ctx, 3) == GPR_U64(ctx, 0));
            ctx->pc = 0x10389Cu;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x103898u;
            SET_GPR_S32(ctx, 2, (int32_t)READ32(ADD32(GPR_U32(ctx, 28), 4294946464)));
            ctx->in_delay_slot = false;
            if (branch_taken_0x103898) {
                ctx->pc = 0x1038A4u;
                goto label_1038a4;
            }
        }
        ctx->pc = 0x1038a0u;
        WRITE32(ADD32(GPR_U32(ctx, 2), 96), GPR_U32(ctx, 0));
    label_1038a4:
        ctx->pc = 0x1038a4u;
        SET_GPR_S32(ctx, 4, (int32_t)((uint32_t)73 << 16));
        ctx->pc = 0x1038a8u;
        SET_GPR_S32(ctx, 4, (int32_t)FAST_READ32(0x488390u));
        ctx->pc = 0x1038acu;
        SET_GPR_S32(ctx, 5, (int32_t)READ32(ADD32(GPR_U32(ctx, 4), 12)));
        ctx->pc = 0x1038B0u;
        {
            const bool branch_taken_0x1038b0 = (GPR_U64(ctx, 5) == GPR_U64(ctx, 0));
            ctx->pc = 0x1038B4u;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x1038B0u;
            SET_GPR_S32(ctx, 3, (int32_t)ADD32(GPR_U32(ctx, 0), 4));
            ctx->in_delay_slot = false;
            if (branch_taken_0x1038b0) {
                ctx->pc = 0x1039E8u;
                goto label_1039e8;
            }
        }
        ctx->pc = 0x1038b8u;
        SET_GPR_S32(ctx, 2, (int32_t)READ32(ADD32(GPR_U32(ctx, 4), 8)));
        ctx->pc = 0x1038bcu;
        SET_GPR_S32(ctx, 2, (int32_t)ADD32(GPR_U32(ctx, 2), 1));
        ctx->pc = 0x1038C0u;
        {
            const bool branch_taken_0x1038c0 = (GPR_U64(ctx, 2) != GPR_U64(ctx, 3));
            ctx->pc = 0x1038C4u;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x1038C0u;
            WRITE32(ADD32(GPR_U32(ctx, 4), 8), GPR_U32(ctx, 2));
            ctx->in_delay_slot = false;
            if (branch_taken_0x1038c0) {
                ctx->pc = 0x1039ECu;
                goto label_1039ec;
            }
        }
        ctx->pc = 0x1038c8u;
        SET_GPR_S32(ctx, 3, (int32_t)ADD32(GPR_U32(ctx, 5), 4294967295));
        ctx->pc = 0x1038ccu;
        SET_GPR_U64(ctx, 2, ((uint64_t)GPR_U64(ctx, 3) < (uint64_t)(int64_t)(int32_t)7) ? 1 : 0);
        ctx->pc = 0x1038D0u;
        {
            const bool branch_taken_0x1038d0 = (GPR_U64(ctx, 2) == GPR_U64(ctx, 0));
            ctx->pc = 0x1038D4u;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x1038D0u;
            SET_GPR_S32(ctx, 2, (int32_t)((uint32_t)67 << 16));
            ctx->in_delay_slot = false;
            if (branch_taken_0x1038d0) {
                ctx->pc = 0x1039ECu;
                goto label_1039ec;
            }
        }
        ctx->pc = 0x1038d8u;
        SET_GPR_S32(ctx, 3, (int32_t)SLL32(GPR_U32(ctx, 3), 2));
        ctx->pc = 0x1038dcu;
        SET_GPR_S32(ctx, 2, (int32_t)ADD32(GPR_U32(ctx, 2), 4294966336));
        ctx->pc = 0x1038e0u;
        SET_GPR_S32(ctx, 3, (int32_t)ADD32(GPR_U32(ctx, 3), GPR_U32(ctx, 2)));
        ctx->pc = 0x1038e4u;
        SET_GPR_S32(ctx, 4, (int32_t)READ32(ADD32(GPR_U32(ctx, 3), 0)));
        ctx->pc = 0x1038E8u;
        {
            const uint32_t jumpTarget = GPR_U32(ctx, 4);
            static int s_jtLogs = 0;
            if (s_jtLogs < 16)
            {
                ++s_jtLogs;
                RUNTIME_LOG("[1036c8-jt] ctrl+0xC=" << GPR_U32(ctx, 5)
                            << " jumpTarget=0x" << std::hex << jumpTarget << std::dec << std::endl);
            }
            ctx->pc = jumpTarget;
            switch (jumpTarget) {
                case 0x1038F0u: goto label_1038f0;
                case 0x103938u: goto label_103938;
                case 0x103950u: goto label_103950;
                case 0x10395Cu: goto label_10395c;
                case 0x103968u: goto label_103968;
                case 0x103984u: goto label_103984;
                case 0x1039A0u: goto label_1039a0;
                case 0x1039E8u: goto label_1039e8;
                case 0x1039ECu: goto label_1039ec;
                default: break;
            }
            if (!runtime->dispatchGuestBranch(rdram, ctx, jumpTarget, 0x1038E8u, 0x0u, PS2Runtime::GuestBranchKind::IndirectJump, "JR")) {
                return;
            }
            goto label_1039ec;
        }
    label_1038f0:
        ctx->pc = 0x1038f0u;
        SET_GPR_S32(ctx, 3, (int32_t)((uint32_t)73 << 16));
        ctx->pc = 0x1038f4u;
        SET_GPR_S32(ctx, 3, (int32_t)FAST_READ32(0x488390u));
        ctx->pc = 0x1038f8u;
        SET_GPR_S32(ctx, 5, (int32_t)((uint32_t)67 << 16));
        ctx->pc = 0x1038fcu;
        SET_GPR_S32(ctx, 5, (int32_t)ADD32(GPR_U32(ctx, 5), 4294966320));
        ctx->pc = 0x103900u;
        SET_GPR_S32(ctx, 2, (int32_t)READ32(ADD32(GPR_U32(ctx, 3), 0)));
        ctx->pc = 0x103904u;
        WRITE32(ADD32(GPR_U32(ctx, 19), 0), GPR_U32(ctx, 2));
        ctx->pc = 0x103908u;
        SET_GPR_S32(ctx, 3, (int32_t)((uint32_t)73 << 16));
        ctx->pc = 0x10390cu;
        SET_GPR_S32(ctx, 3, (int32_t)FAST_READ32(0x488390u));
        ctx->pc = 0x103910u;
        SET_GPR_S32(ctx, 2, (int32_t)READ32(ADD32(GPR_U32(ctx, 3), 4)));
        ctx->pc = 0x103914u;
        WRITE32(ADD32(GPR_U32(ctx, 20), 0), GPR_U32(ctx, 2));
        ctx->pc = 0x103918u;
        SET_GPR_U32(ctx, 31, 0x103920u);
        ctx->pc = 0x10391Cu;
        ctx->in_delay_slot = true;
        ctx->branch_pc = 0x103918u;
        SET_GPR_S32(ctx, 4, (int32_t)READ32(ADD32(GPR_U32(ctx, 19), 0)));
        ctx->in_delay_slot = false;
        ctx->pc = 0x2F4D50u;
        if (!runtime->dispatchGuestBranch(rdram, ctx, 0x2F4D50u, 0x103918u, 0x103920u, PS2Runtime::GuestBranchKind::DirectCall, "JAL")) {
            return;
        }
        ctx->pc = 0x103920u;
    label_103920:
        ctx->pc = 0x103920u;
        {
            const bool branch_taken_0x103920 = (GPR_U64(ctx, 2) == GPR_U64(ctx, 0));
            ctx->pc = 0x103924u;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x103920u;
            SET_GPR_S32(ctx, 2, (int32_t)ADD32(GPR_U32(ctx, 0), 1));
            ctx->in_delay_slot = false;
            if (branch_taken_0x103920) {
                ctx->pc = 0x103938u;
                goto label_103938;
            }
        }
        ctx->pc = 0x103928u;
        SET_GPR_S32(ctx, 2, (int32_t)READ32(ADD32(GPR_U32(ctx, 20), 0)));
        ctx->pc = 0x10392Cu;
        {
            const bool branch_taken_0x10392c = (GPR_U64(ctx, 2) != GPR_U64(ctx, 0));
            ctx->pc = 0x103930u;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x10392Cu;
            SET_GPR_S32(ctx, 2, (int32_t)ADD32(GPR_U32(ctx, 0), 1));
            ctx->in_delay_slot = false;
            if (branch_taken_0x10392c) {
                ctx->pc = 0x103938u;
                goto label_103938;
            }
        }
        ctx->pc = 0x103934u;
        SET_GPR_S32(ctx, 2, (int32_t)ADD32(GPR_U32(ctx, 0), 2));
        ctx->pc = 0x103938u;
    label_103938:
        ctx->pc = 0x103938u;
        WRITE32(ADD32(GPR_U32(ctx, 18), 0), GPR_U32(ctx, 2));
        ctx->pc = 0x10393cu;
        SET_GPR_S32(ctx, 3, (int32_t)ADD32(GPR_U32(ctx, 21), 7920));
        ctx->pc = 0x103940u;
        SET_GPR_S32(ctx, 2, (int32_t)READ32(ADD32(GPR_U32(ctx, 3), 136)));
        ctx->pc = 0x103944u;
        SET_GPR_U64(ctx, 2, GPR_U64(ctx, 2) | (uint64_t)(uint16_t)32);
        ctx->pc = 0x103948u;
        {
            const bool branch_taken_0x103948 = (GPR_U64(ctx, 0) == GPR_U64(ctx, 0));
            ctx->pc = 0x10394Cu;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x103948u;
            WRITE32(ADD32(GPR_U32(ctx, 3), 136), GPR_U32(ctx, 2));
            ctx->in_delay_slot = false;
            if (branch_taken_0x103948) {
                ctx->pc = 0x1039ECu;
                goto label_1039ec;
            }
        }
    label_103950:
        ctx->pc = 0x103950u;
        SET_GPR_S32(ctx, 2, (int32_t)ADD32(GPR_U32(ctx, 0), 3));
        ctx->pc = 0x103954u;
        {
            const bool branch_taken_0x103954 = (GPR_U64(ctx, 0) == GPR_U64(ctx, 0));
            ctx->pc = 0x103958u;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x103954u;
            WRITE32(ADD32(GPR_U32(ctx, 18), 0), GPR_U32(ctx, 2));
            ctx->in_delay_slot = false;
            if (branch_taken_0x103954) {
                ctx->pc = 0x1039ECu;
                goto label_1039ec;
            }
        }
    label_10395c:
        ctx->pc = 0x10395cu;
        SET_GPR_S32(ctx, 2, (int32_t)ADD32(GPR_U32(ctx, 0), 6));
        ctx->pc = 0x103960u;
        {
            const bool branch_taken_0x103960 = (GPR_U64(ctx, 0) == GPR_U64(ctx, 0));
            ctx->pc = 0x103964u;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x103960u;
            WRITE32(ADD32(GPR_U32(ctx, 18), 0), GPR_U32(ctx, 2));
            ctx->in_delay_slot = false;
            if (branch_taken_0x103960) {
                ctx->pc = 0x1039ECu;
                goto label_1039ec;
            }
        }
    label_103968:
        ctx->pc = 0x103968u;
        SET_GPR_S32(ctx, 2, (int32_t)ADD32(GPR_U32(ctx, 0), 7));
        ctx->pc = 0x10396cu;
        SET_GPR_S32(ctx, 4, (int32_t)ADD32(GPR_U32(ctx, 21), 7920));
        ctx->pc = 0x103970u;
        WRITE32(ADD32(GPR_U32(ctx, 18), 0), GPR_U32(ctx, 2));
        ctx->pc = 0x103974u;
        SET_GPR_S32(ctx, 3, (int32_t)READ32(ADD32(GPR_U32(ctx, 4), 136)));
        ctx->pc = 0x103978u;
        SET_GPR_U64(ctx, 3, GPR_U64(ctx, 3) | (uint64_t)(uint16_t)32);
        ctx->pc = 0x10397Cu;
        {
            const bool branch_taken_0x10397c = (GPR_U64(ctx, 0) == GPR_U64(ctx, 0));
            ctx->pc = 0x103980u;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x10397Cu;
            WRITE32(ADD32(GPR_U32(ctx, 4), 136), GPR_U32(ctx, 3));
            ctx->in_delay_slot = false;
            if (branch_taken_0x10397c) {
                ctx->pc = 0x1039ECu;
                goto label_1039ec;
            }
        }
    label_103984:
        ctx->pc = 0x103984u;
        SET_GPR_S32(ctx, 2, (int32_t)((uint32_t)73 << 16));
        ctx->pc = 0x103988u;
        SET_GPR_S32(ctx, 2, (int32_t)FAST_READ32(0x488390u));
        ctx->pc = 0x10398cu;
        SET_GPR_S32(ctx, 4, (int32_t)ADD32(GPR_U32(ctx, 0), 4));
        ctx->pc = 0x103990u;
        SET_GPR_S32(ctx, 3, (int32_t)READ32(ADD32(GPR_U32(ctx, 2), 16)));
        ctx->pc = 0x103994u;
        WRITE32(ADD32(GPR_U32(ctx, 22), 0), GPR_U32(ctx, 3));
        ctx->pc = 0x103998u;
        {
            const bool branch_taken_0x103998 = (GPR_U64(ctx, 0) == GPR_U64(ctx, 0));
            ctx->pc = 0x10399Cu;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x103998u;
            WRITE32(ADD32(GPR_U32(ctx, 18), 0), GPR_U32(ctx, 4));
            ctx->in_delay_slot = false;
            if (branch_taken_0x103998) {
                ctx->pc = 0x1039ECu;
                goto label_1039ec;
            }
        }
    label_1039a0:
        ctx->pc = 0x1039a0u;
        SET_GPR_S32(ctx, 3, (int32_t)((uint32_t)73 << 16));
        ctx->pc = 0x1039a4u;
        SET_GPR_S32(ctx, 3, (int32_t)FAST_READ32(0x488390u));
        ctx->pc = 0x1039a8u;
        SET_GPR_S32(ctx, 5, (int32_t)ADD32(GPR_U32(ctx, 0), 5));
        ctx->pc = 0x1039acu;
        SET_GPR_S32(ctx, 6, (int32_t)((uint32_t)66 << 16));
        ctx->pc = 0x1039b0u;
        SET_GPR_S32(ctx, 4, (int32_t)ADD32(GPR_U32(ctx, 21), 7920));
        ctx->pc = 0x1039b4u;
        SET_GPR_S32(ctx, 2, (int32_t)READ32(ADD32(GPR_U32(ctx, 3), 0)));
        ctx->pc = 0x1039b8u;
        WRITE32(ADD32(GPR_U32(ctx, 19), 0), GPR_U32(ctx, 2));
        ctx->pc = 0x1039bcu;
        SET_GPR_S32(ctx, 3, (int32_t)((uint32_t)73 << 16));
        ctx->pc = 0x1039c0u;
        SET_GPR_S32(ctx, 3, (int32_t)FAST_READ32(0x488390u));
        ctx->pc = 0x1039c4u;
        SET_GPR_S32(ctx, 2, (int32_t)READ32(ADD32(GPR_U32(ctx, 3), 4)));
        ctx->pc = 0x1039c8u;
        WRITE32(ADD32(GPR_U32(ctx, 20), 0), GPR_U32(ctx, 2));
        ctx->pc = 0x1039ccu;
        WRITE32(ADD32(GPR_U32(ctx, 18), 0), GPR_U32(ctx, 5));
        ctx->pc = 0x1039d0u;
        SET_GPR_S32(ctx, 3, (int32_t)FAST_READ32(0x421800u));
        ctx->pc = 0x1039d4u;
        WRITE32(ADD32(GPR_U32(ctx, 22), 0), GPR_U32(ctx, 3));
        ctx->pc = 0x1039d8u;
        SET_GPR_S32(ctx, 2, (int32_t)READ32(ADD32(GPR_U32(ctx, 4), 136)));
        ctx->pc = 0x1039dcu;
        SET_GPR_U64(ctx, 2, GPR_U64(ctx, 2) | (uint64_t)(uint16_t)32);
        ctx->pc = 0x1039E0u;
        {
            const bool branch_taken_0x1039e0 = (GPR_U64(ctx, 0) == GPR_U64(ctx, 0));
            ctx->pc = 0x1039E4u;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x1039E0u;
            WRITE32(ADD32(GPR_U32(ctx, 4), 136), GPR_U32(ctx, 2));
            ctx->in_delay_slot = false;
            if (branch_taken_0x1039e0) {
                ctx->pc = 0x1039ECu;
                goto label_1039ec;
            }
        }
    label_1039e8:
        ctx->pc = 0x1039e8u;
        WRITE32(ADD32(GPR_U32(ctx, 18), 0), GPR_U32(ctx, 0));
    label_1039ec:
        ctx->pc = 0x1039ecu;
        SET_GPR_VEC(ctx, 31, READ128(ADD32(GPR_U32(ctx, 29), 112)));
        ctx->pc = 0x1039f0u;
        SET_GPR_VEC(ctx, 22, READ128(ADD32(GPR_U32(ctx, 29), 96)));
        ctx->pc = 0x1039f4u;
        SET_GPR_VEC(ctx, 21, READ128(ADD32(GPR_U32(ctx, 29), 80)));
        ctx->pc = 0x1039f8u;
        SET_GPR_VEC(ctx, 20, READ128(ADD32(GPR_U32(ctx, 29), 64)));
        ctx->pc = 0x1039fcu;
        SET_GPR_VEC(ctx, 19, READ128(ADD32(GPR_U32(ctx, 29), 48)));
        ctx->pc = 0x103a00u;
        SET_GPR_VEC(ctx, 18, READ128(ADD32(GPR_U32(ctx, 29), 32)));
        ctx->pc = 0x103a04u;
        SET_GPR_VEC(ctx, 17, READ128(ADD32(GPR_U32(ctx, 29), 16)));
        ctx->pc = 0x103a08u;
        SET_GPR_VEC(ctx, 16, READ128(ADD32(GPR_U32(ctx, 29), 0)));
        ctx->pc = 0x103A0Cu;
        {
            const uint32_t jumpTarget = GPR_U32(ctx, 31);
            ctx->pc = 0x103A10u;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x103A0Cu;
            SET_GPR_S32(ctx, 29, (int32_t)ADD32(GPR_U32(ctx, 29), 128));
            ctx->in_delay_slot = false;
            ctx->pc = jumpTarget;
            return;
        }
    }

    // Separate function 0x00103A18..0x00103B28 trapped inside entry_001039ec_0x1039ec.cpp
    inline void func103a18Override(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        switch (ctx->pc) {
            case 0x103ac8u: goto label_103ac8;
            case 0x103ae8u: goto label_103ae8;
            case 0x103b1cu: goto label_103b1c;
            default: break;
        }

        ctx->pc = 0x103a18u;
        SET_GPR_S32(ctx, 2, (int32_t)((uint32_t)73 << 16));
        ctx->pc = 0x103a1cu;
        SET_GPR_S32(ctx, 2, (int32_t)FAST_READ32(0x488390u));
        ctx->pc = 0x103a20u;
        SET_GPR_S32(ctx, 29, (int32_t)ADD32(GPR_U32(ctx, 29), 4294967280));
        ctx->pc = 0x103a24u;
        WRITE128(ADD32(GPR_U32(ctx, 29), 0), GPR_VEC(ctx, 31));
        ctx->pc = 0x103a28u;
        SET_GPR_U64(ctx, 7, (uint64_t)GPR_U64(ctx, 2) + (uint64_t)GPR_U64(ctx, 0));
        ctx->pc = 0x103a2cu;
        SET_GPR_S32(ctx, 2, (int32_t)READ32(ADD32(GPR_U32(ctx, 2), 32)));
        ctx->pc = 0x103A30u;
        {
            const bool branch_taken_0x103a30 = (GPR_U64(ctx, 2) == GPR_U64(ctx, 0));
            ctx->pc = 0x103A34u;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x103A30u;
            SET_GPR_U64(ctx, 3, (uint64_t)GPR_U64(ctx, 0) + (uint64_t)GPR_U64(ctx, 0));
            ctx->in_delay_slot = false;
            if (branch_taken_0x103a30) {
                ctx->pc = 0x103A40u;
                goto label_103a40;
            }
        }
        ctx->pc = 0x103a38u;
        SET_GPR_S32(ctx, 2, (int32_t)READ32(ADD32(GPR_U32(ctx, 2), 12)));
        ctx->pc = 0x103a3cu;
        SET_GPR_U64(ctx, 3, ((uint64_t)GPR_U64(ctx, 2) < (uint64_t)(int64_t)(int32_t)1) ? 1 : 0);
    label_103a40:
        ctx->pc = 0x103A40u;
        {
            const bool branch_taken_0x103a40 = (GPR_U64(ctx, 3) == GPR_U64(ctx, 0));
            ctx->pc = 0x103A44u;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x103A40u;
            SET_GPR_S32(ctx, 2, (int32_t)READ32(ADD32(GPR_U32(ctx, 28), 4294946488)));
            ctx->in_delay_slot = false;
            if (branch_taken_0x103a40) {
                ctx->pc = 0x103AE8u;
                goto label_103ae8;
            }
        }
        ctx->pc = 0x103a48u;
        SET_GPR_S32(ctx, 2, (int32_t)READ32(ADD32(GPR_U32(ctx, 2), 48)));
        ctx->pc = 0x103A4Cu;
        {
            const bool branch_taken_0x103a4c = (GPR_U64(ctx, 2) == GPR_U64(ctx, 0));
            ctx->pc = 0x103A50u;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x103A4Cu;
            SET_GPR_U64(ctx, 3, (uint64_t)GPR_U64(ctx, 0) + (uint64_t)GPR_U64(ctx, 0));
            ctx->in_delay_slot = false;
            if (branch_taken_0x103a4c) {
                ctx->pc = 0x103A6Cu;
                goto label_103a6c;
            }
        }
        ctx->pc = 0x103a54u;
        SET_GPR_S32(ctx, 3, (int32_t)READ32(ADD32(GPR_U32(ctx, 2), 0)));
        ctx->pc = 0x103A58u;
        {
            const bool branch_taken_0x103a58 = (GPR_U64(ctx, 3) == GPR_U64(ctx, 0));
            ctx->pc = 0x103A5Cu;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x103A58u;
            SET_GPR_U64(ctx, 2, (uint64_t)GPR_U64(ctx, 0) + (uint64_t)GPR_U64(ctx, 0));
            ctx->in_delay_slot = false;
            if (branch_taken_0x103a58) {
                ctx->pc = 0x103A68u;
                goto label_103a68;
            }
        }
        ctx->pc = 0x103a60u;
        SET_GPR_S32(ctx, 2, (int32_t)READ32(ADD32(GPR_U32(ctx, 3), 12)));
        ctx->pc = 0x103a64u;
        SET_GPR_U64(ctx, 2, ((uint64_t)GPR_U64(ctx, 2) < (uint64_t)(int64_t)(int32_t)1) ? 1 : 0);
    label_103a68:
        ctx->pc = 0x103a68u;
        SET_GPR_U64(ctx, 3, (uint64_t)GPR_U64(ctx, 2) + (uint64_t)GPR_U64(ctx, 0));
    label_103a6c:
        ctx->pc = 0x103A6Cu;
        {
            const bool branch_taken_0x103a6c = (GPR_U64(ctx, 3) == GPR_U64(ctx, 0));
            ctx->pc = 0x103A70u;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x103A6Cu;
            SET_GPR_S32(ctx, 2, (int32_t)((uint32_t)16 << 16));
            ctx->in_delay_slot = false;
            if (branch_taken_0x103a6c) {
                ctx->pc = 0x103AE8u;
                goto label_103ae8;
            }
        }
        ctx->pc = 0x103a74u;
        SET_GPR_S32(ctx, 5, (int32_t)READ32(ADD32(GPR_U32(ctx, 7), 32)));
        ctx->pc = 0x103a78u;
        SET_GPR_S32(ctx, 2, (int32_t)ADD32(GPR_U32(ctx, 2), 16792));
        ctx->pc = 0x103a7cu;
        SET_GPR_S32(ctx, 4, (int32_t)((uint32_t)16 << 16));
        ctx->pc = 0x103a80u;
        SET_GPR_S32(ctx, 3, (int32_t)READ32(ADD32(GPR_U32(ctx, 5), 8)));
        ctx->pc = 0x103a84u;
        SET_GPR_S32(ctx, 4, (int32_t)ADD32(GPR_U32(ctx, 4), 17704));
        ctx->pc = 0x103a88u;
        WRITE32(ADD32(GPR_U32(ctx, 3), 208), GPR_U32(ctx, 2));
        ctx->pc = 0x103a8cu;
        WRITE32(ADD32(GPR_U32(ctx, 3), 212), GPR_U32(ctx, 7));
        ctx->pc = 0x103a90u;
        SET_GPR_S32(ctx, 2, (int32_t)READ32(ADD32(GPR_U32(ctx, 7), 32)));
        ctx->pc = 0x103a94u;
        SET_GPR_S32(ctx, 3, (int32_t)READ32(ADD32(GPR_U32(ctx, 2), 8)));
        ctx->pc = 0x103a98u;
        WRITE32(ADD32(GPR_U32(ctx, 3), 216), GPR_U32(ctx, 4));
        ctx->pc = 0x103a9cu;
        WRITE32(ADD32(GPR_U32(ctx, 3), 220), GPR_U32(ctx, 0));
        ctx->pc = 0x103aa0u;
        SET_GPR_S32(ctx, 2, (int32_t)READ32(ADD32(GPR_U32(ctx, 7), 96)));
        ctx->pc = 0x103AA4u;
        {
            const bool branch_taken_0x103aa4 = (GPR_U64(ctx, 2) != GPR_U64(ctx, 0));
            ctx->pc = 0x103AA8u;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x103AA4u;
            SET_GPR_S32(ctx, 2, (int32_t)READ32(ADD32(GPR_U32(ctx, 28), 4294946488)));
            ctx->in_delay_slot = false;
            if (branch_taken_0x103aa4) {
                ctx->pc = 0x103AF0u;
                goto label_103af0;
            }
        }
        ctx->pc = 0x103aacu;
        SET_GPR_S32(ctx, 6, (int32_t)READ32(ADD32(GPR_U32(ctx, 7), 48)));
        ctx->pc = 0x103AB0u;
        {
            const bool branch_taken_0x103ab0 = (GPR_U64(ctx, 6) == GPR_U64(ctx, 0));
            ctx->pc = 0x103AB4u;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x103AB0u;
            SET_GPR_S32(ctx, 5, (int32_t)((uint32_t)72 << 16));
            ctx->in_delay_slot = false;
            if (branch_taken_0x103ab0) {
                ctx->pc = 0x103AD4u;
                goto label_103ad4;
            }
        }
        ctx->pc = 0x103ab8u;
        SET_GPR_S32(ctx, 2, (int32_t)READ32(ADD32(GPR_U32(ctx, 7), 32)));
        ctx->pc = 0x103abcu;
        SET_GPR_S32(ctx, 5, (int32_t)ADD32(GPR_U32(ctx, 5), 21896));
        ctx->pc = 0x103AC0u;
        SET_GPR_U32(ctx, 31, 0x103AC8u);
        ctx->pc = 0x103AC4u;
        ctx->in_delay_slot = true;
        ctx->branch_pc = 0x103AC0u;
        SET_GPR_S32(ctx, 4, (int32_t)READ32(ADD32(GPR_U32(ctx, 2), 8)));
        ctx->in_delay_slot = false;
        ctx->pc = 0x2E59E0u;
        if (!runtime->dispatchGuestBranch(rdram, ctx, 0x2E59E0u, 0x103AC0u, 0x103AC8u, PS2Runtime::GuestBranchKind::DirectCall, "JAL")) {
            return;
        }
        ctx->pc = 0x103AC8u;
    label_103ac8:
        ctx->pc = 0x103ac8u;
        SET_GPR_S32(ctx, 2, (int32_t)((uint32_t)73 << 16));
        ctx->pc = 0x103accu;
        SET_GPR_S32(ctx, 2, (int32_t)FAST_READ32(0x488390u));
        ctx->pc = 0x103ad0u;
        WRITE32(ADD32(GPR_U32(ctx, 2), 48), GPR_U32(ctx, 0));
    label_103ad4:
        ctx->pc = 0x103ad4u;
        SET_GPR_S32(ctx, 2, (int32_t)((uint32_t)73 << 16));
        ctx->pc = 0x103ad8u;
        SET_GPR_S32(ctx, 2, (int32_t)FAST_READ32(0x488390u));
        ctx->pc = 0x103adcu;
        SET_GPR_S32(ctx, 3, (int32_t)READ32(ADD32(GPR_U32(ctx, 2), 32)));
        ctx->pc = 0x103AE0u;
        SET_GPR_U32(ctx, 31, 0x103AE8u);
        ctx->pc = 0x103AE4u;
        ctx->in_delay_slot = true;
        ctx->branch_pc = 0x103AE0u;
        SET_GPR_S32(ctx, 4, (int32_t)READ32(ADD32(GPR_U32(ctx, 3), 8)));
        ctx->in_delay_slot = false;
        ctx->pc = 0x2DFA98u;
        if (!runtime->dispatchGuestBranch(rdram, ctx, 0x2DFA98u, 0x103AE0u, 0x103AE8u, PS2Runtime::GuestBranchKind::DirectCall, "JAL")) {
            return;
        }
        ctx->pc = 0x103AE8u;
    label_103ae8:
        ctx->pc = 0x103ae8u;
        SET_GPR_S32(ctx, 2, (int32_t)((uint32_t)73 << 16));
        ctx->pc = 0x103aecu;
        SET_GPR_S32(ctx, 2, (int32_t)FAST_READ32(0x4883A8u));
    label_103af0:
        ctx->pc = 0x103af0u;
        SET_GPR_S32(ctx, 2, (int32_t)READ32(ADD32(GPR_U32(ctx, 2), 48)));
        ctx->pc = 0x103AF4u;
        {
            const bool branch_taken_0x103af4 = (GPR_U64(ctx, 2) == GPR_U64(ctx, 0));
            ctx->pc = 0x103AF8u;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x103AF4u;
            SET_GPR_U64(ctx, 4, (uint64_t)GPR_U64(ctx, 0) + (uint64_t)GPR_U64(ctx, 0));
            ctx->in_delay_slot = false;
            if (branch_taken_0x103af4) {
                ctx->pc = 0x103B14u;
                goto label_103b14;
            }
        }
        ctx->pc = 0x103afcu;
        SET_GPR_S32(ctx, 3, (int32_t)READ32(ADD32(GPR_U32(ctx, 2), 0)));
        ctx->pc = 0x103B00u;
        {
            const bool branch_taken_0x103b00 = (GPR_U64(ctx, 3) == GPR_U64(ctx, 0));
            ctx->pc = 0x103B04u;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x103B00u;
            SET_GPR_U64(ctx, 2, (uint64_t)GPR_U64(ctx, 0) + (uint64_t)GPR_U64(ctx, 0));
            ctx->in_delay_slot = false;
            if (branch_taken_0x103b00) {
                ctx->pc = 0x103B10u;
                goto label_103b10;
            }
        }
        ctx->pc = 0x103b08u;
        SET_GPR_S32(ctx, 2, (int32_t)READ32(ADD32(GPR_U32(ctx, 3), 12)));
        ctx->pc = 0x103b0cu;
        SET_GPR_U64(ctx, 2, ((uint64_t)GPR_U64(ctx, 2) < (uint64_t)(int64_t)(int32_t)1) ? 1 : 0);
    label_103b10:
        ctx->pc = 0x103b10u;
        SET_GPR_U64(ctx, 4, (uint64_t)GPR_U64(ctx, 2) + (uint64_t)GPR_U64(ctx, 0));
    label_103b14:
        ctx->pc = 0x103B14u;
        SET_GPR_U32(ctx, 31, 0x103B1Cu);
        ctx->pc = 0x103B18u;
        ctx->in_delay_slot = true;
        ctx->branch_pc = 0x103B14u;
        SET_GPR_U64(ctx, 4, GPR_U64(ctx, 4) ^ (uint64_t)(uint16_t)1);
        ctx->in_delay_slot = false;
        ctx->pc = 0x32BA20u;
        if (!runtime->dispatchGuestBranch(rdram, ctx, 0x32BA20u, 0x103B14u, 0x103B1Cu, PS2Runtime::GuestBranchKind::DirectCall, "JAL")) {
            return;
        }
        ctx->pc = 0x103B1Cu;
    label_103b1c:
        ctx->pc = 0x103b1cu;
        SET_GPR_VEC(ctx, 31, READ128(ADD32(GPR_U32(ctx, 29), 0)));
        ctx->pc = 0x103B20u;
        {
            const uint32_t jumpTarget = GPR_U32(ctx, 31);
            ctx->pc = 0x103B24u;
            ctx->in_delay_slot = true;
            ctx->branch_pc = 0x103B20u;
            SET_GPR_S32(ctx, 29, (int32_t)ADD32(GPR_U32(ctx, 29), 16));
            ctx->in_delay_slot = false;
            ctx->pc = jumpTarget;
            return;
        }
    }

    namespace primal_mpeg_hle
    {
        struct DecodedFrame
        {
            int width = 0;
            int height = 0;
            std::vector<uint8_t> rgba;
        };

        struct PrimalMpegState
        {
            static constexpr size_t kMaxBufferedFrames = 8u;

            std::mutex mtx;
            std::deque<DecodedFrame> frames;
            DecodedFrame lastFrame;
            std::vector<uint8_t> esBuf;
            bool sawProgramEnd = false;
            uint32_t frameCount = 0u;

#if defined(PS2X_HAS_FFMPEG) && PS2X_HAS_FFMPEG
            AVCodecContext *codecCtx = nullptr;
            AVCodecParserContext *parserCtx = nullptr;
            AVFrame *avFrame = nullptr;
            AVPacket *avPkt = nullptr;
            SwsContext *swsCtx = nullptr;

            void destroyLocked()
            {
                if (swsCtx != nullptr)
                {
                    sws_freeContext(swsCtx);
                    swsCtx = nullptr;
                }
                av_packet_free(&avPkt);
                av_frame_free(&avFrame);
                if (parserCtx != nullptr)
                {
                    av_parser_close(parserCtx);
                    parserCtx = nullptr;
                }
                avcodec_free_context(&codecCtx);
                frames.clear();
                lastFrame = {};
                esBuf.clear();
                sawProgramEnd = false;
                frameCount = 0u;
            }

            void initDecoderLocked()
            {
                destroyLocked();
                av_log_set_level(AV_LOG_ERROR);

                const AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_MPEG2VIDEO);
                if (codec == nullptr)
                {
                    RUNTIME_LOG("[primal-mpeg] ERROR: AV_CODEC_ID_MPEG2VIDEO decoder not found" << std::endl);
                    return;
                }

                codecCtx = avcodec_alloc_context3(codec);
                if (codecCtx == nullptr)
                {
                    destroyLocked();
                    return;
                }
                codecCtx->thread_count = 1;

                if (avcodec_open2(codecCtx, codec, nullptr) < 0)
                {
                    RUNTIME_LOG("[primal-mpeg] ERROR: avcodec_open2 failed" << std::endl);
                    destroyLocked();
                    return;
                }

                parserCtx = av_parser_init(AV_CODEC_ID_MPEG2VIDEO);
                avFrame = av_frame_alloc();
                avPkt = av_packet_alloc();
                if (parserCtx == nullptr || avFrame == nullptr || avPkt == nullptr)
                {
                    RUNTIME_LOG("[primal-mpeg] ERROR: parser/frame/packet alloc failed" << std::endl);
                    destroyLocked();
                }
            }

            void drainFramesLocked()
            {
                if (codecCtx == nullptr || avFrame == nullptr)
                    return;

                while (avcodec_receive_frame(codecCtx, avFrame) == 0)
                {
                    if (avFrame->width > 0 && avFrame->height > 0)
                    {
                        swsCtx = sws_getCachedContext(
                            swsCtx,
                            avFrame->width,
                            avFrame->height,
                            static_cast<AVPixelFormat>(avFrame->format),
                            avFrame->width,
                            avFrame->height,
                            AV_PIX_FMT_RGBA,
                            SWS_BILINEAR,
                            nullptr,
                            nullptr,
                            nullptr);
                        if (swsCtx != nullptr)
                        {
                            DecodedFrame df;
                            df.width = avFrame->width;
                            df.height = avFrame->height;
                            const size_t pxCount = static_cast<size_t>(df.width) * static_cast<size_t>(df.height);
                            df.rgba.resize(pxCount * 4u);

                            uint8_t *dstSlices[4] = {df.rgba.data(), nullptr, nullptr, nullptr};
                            int dstLinesize[4] = {df.width * 4, 0, 0, 0};
                            sws_scale(swsCtx, avFrame->data, avFrame->linesize, 0, df.height, dstSlices, dstLinesize);

                            // Sony libmpeg RGBA32 sets A=0x80 (GS 1.0 alpha scale).
                            for (size_t i = 0; i < pxCount; ++i)
                            {
                                df.rgba[i * 4u + 3u] = 0x80u;
                            }
                            frames.push_back(std::move(df));
                        }
                    }
                    av_frame_unref(avFrame);
                }
            }

            void decodeVideoBytesLocked(const uint8_t *data, size_t size)
            {
                if (codecCtx == nullptr || parserCtx == nullptr || avPkt == nullptr || data == nullptr || size == 0u)
                    return;

                size_t offset = 0u;
                while (offset < size)
                {
                    uint8_t *pktData = nullptr;
                    int pktSize = 0;
                    const int used = av_parser_parse2(
                        parserCtx,
                        codecCtx,
                        &pktData,
                        &pktSize,
                        data + offset,
                        static_cast<int>(size - offset),
                        AV_NOPTS_VALUE,
                        AV_NOPTS_VALUE,
                        0);
                    if (used < 0)
                        break;
                    offset += static_cast<size_t>(used);

                    if (pktSize > 0 && pktData != nullptr)
                    {
                        avPkt->data = pktData;
                        avPkt->size = pktSize;
                        const int sendErr = avcodec_send_packet(codecCtx, avPkt);
                        avPkt->data = nullptr;
                        avPkt->size = 0;
                        if (sendErr == 0)
                        {
                            drainFramesLocked();
                        }
                    }
                }
            }

            void flushEndOfStreamLocked()
            {
                if (codecCtx != nullptr && parserCtx != nullptr && avPkt != nullptr)
                {
                    uint8_t *pktData = nullptr;
                    int pktSize = 0;
                    av_parser_parse2(parserCtx, codecCtx, &pktData, &pktSize, nullptr, 0, AV_NOPTS_VALUE, AV_NOPTS_VALUE, 0);
                    if (pktSize > 0 && pktData != nullptr)
                    {
                        avPkt->data = pktData;
                        avPkt->size = pktSize;
                        const int sendErr = avcodec_send_packet(codecCtx, avPkt);
                        avPkt->data = nullptr;
                        avPkt->size = 0;
                        if (sendErr == 0)
                        {
                            drainFramesLocked();
                        }
                    }
                    avcodec_send_packet(codecCtx, nullptr);
                    drainFramesLocked();
                    avcodec_flush_buffers(codecCtx);
                }
                if (parserCtx != nullptr)
                {
                    av_parser_close(parserCtx);
                    parserCtx = av_parser_init(AV_CODEC_ID_MPEG2VIDEO);
                }
                sawProgramEnd = true;
            }

            void resetStreamLocked()
            {
                if (codecCtx != nullptr)
                {
                    avcodec_flush_buffers(codecCtx);
                }
                if (parserCtx != nullptr)
                {
                    av_parser_close(parserCtx);
                    parserCtx = av_parser_init(AV_CODEC_ID_MPEG2VIDEO);
                }
                frames.clear();
                lastFrame = {};
                esBuf.clear();
                sawProgramEnd = false;
                frameCount = 0u;
            }
#else
            void destroyLocked()
            {
                frames.clear();
                lastFrame = {};
                esBuf.clear();
                sawProgramEnd = false;
                frameCount = 0u;
            }
            void initDecoderLocked() { destroyLocked(); }
            void decodeVideoBytesLocked(const uint8_t *, size_t) {}
            void flushEndOfStreamLocked() { sawProgramEnd = true; }
            void resetStreamLocked() { destroyLocked(); }
#endif
        };

        inline PrimalMpegState &mpegState()
        {
            static PrimalMpegState s;
            return s;
        }

        inline void sceMpegInitHle(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
        {
            (void)rdram;
            (void)runtime;
            PrimalMpegState &state = mpegState();
            std::lock_guard<std::mutex> lock(state.mtx);
            state.destroyLocked();
            SET_GPR_S32(ctx, 2, 0);
            ctx->pc = getRegU32(ctx, 31);
        }

        inline void sceMpegCreateHle(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
        {
            (void)runtime;
            const uint32_t mp = getRegU32(ctx, 4);
            const uint32_t workBuf = getRegU32(ctx, 5);
            const uint32_t workSize = getRegU32(ctx, 6);
            (void)workSize;

            if (mp == 0u || workBuf == 0u)
            {
                RUNTIME_LOG("[primal-mpeg] blocked null sceMpegCreate mp=0x" << std::hex << mp
                            << " work_buf=0x" << workBuf << std::dec << std::endl);
                SET_GPR_U32(ctx, 2, 0u);
                ctx->pc = getRegU32(ctx, 31);
                return;
            }

            uint8_t *mpHost = nullptr;
            uint32_t mpAvail = 0u;
            if (primal_sif_rpc::mapGuestRange(rdram, mp, mpHost, mpAvail) && mpAvail >= 0x48u)
            {
                std::memset(mpHost, 0, 0x48u);
                (void)primal_sif_rpc::writeGuestU32(rdram, mp + 0x40u, (workBuf + 3u) & ~3u);
                for (uint32_t off = 0x10u; off < 0x40u; off += 4u)
                {
                    (void)primal_sif_rpc::writeGuestU32(rdram, mp + off, 0xFFFFFFFFu);
                }
            }

            PrimalMpegState &state = mpegState();
            {
                std::lock_guard<std::mutex> lock(state.mtx);
                state.initDecoderLocked();
            }

            SET_GPR_U32(ctx, 2, mp);
            ctx->pc = getRegU32(ctx, 31);
        }

        inline void sceMpegAddCallbackHle(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
        {
            (void)rdram;
            (void)runtime;
            SET_GPR_S32(ctx, 2, 0);
            ctx->pc = getRegU32(ctx, 31);
        }

        inline void sceMpegAddStrCallbackHle(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
        {
            (void)rdram;
            (void)runtime;
            SET_GPR_S32(ctx, 2, 0);
            ctx->pc = getRegU32(ctx, 31);
        }

        inline void sceMpegDemuxPssRingHle(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
        {
            (void)runtime;
            const uint32_t readPtr = getRegU32(ctx, 5);
            const uint32_t availBytes = getRegU32(ctx, 6);
            const uint32_t ringBase = getRegU32(ctx, 7);
            const uint32_t ringSize = getRegU32(ctx, 8);

            if (availBytes == 0u || ringSize < 16u)
            {
                SET_GPR_S32(ctx, 2, 0);
                ctx->pc = getRegU32(ctx, 31);
                return;
            }

            const uint32_t physRead = readPtr & 0x1FFFFFFFu;
            const uint32_t physBase = ringBase & 0x1FFFFFFFu;
            uint8_t *ringPtr = nullptr;
            uint32_t ringAvail = 0u;
            if (!primal_sif_rpc::mapGuestRange(rdram, physBase, ringPtr, ringAvail) ||
                ringPtr == nullptr ||
                ringAvail < ringSize ||
                physRead < physBase ||
                physRead >= physBase + ringSize)
            {
                SET_GPR_S32(ctx, 2, 0);
                ctx->pc = getRegU32(ctx, 31);
                return;
            }

            const uint32_t readOff = physRead - physBase;
            auto ringU8 = [&](uint32_t offset) -> uint8_t
            {
                return ringPtr[(readOff + offset) % ringSize];
            };
            auto ringCopy = [&](uint32_t offset, uint8_t *dst, uint32_t len)
            {
                const uint32_t start = (readOff + offset) % ringSize;
                const uint32_t first = std::min<uint32_t>(len, ringSize - start);
                std::memcpy(dst, ringPtr + start, first);
                if (first < len)
                {
                    std::memcpy(dst + first, ringPtr, len - first);
                }
            };

            PrimalMpegState &state = mpegState();
            std::lock_guard<std::mutex> lock(state.mtx);

            if (state.frames.size() >= PrimalMpegState::kMaxBufferedFrames)
            {
                SET_GPR_S32(ctx, 2, 0);
                ctx->pc = getRegU32(ctx, 31);
                return;
            }

            uint32_t pos = 0u;
            while (pos + 4u <= availBytes && state.frames.size() < PrimalMpegState::kMaxBufferedFrames)
            {
                if (ringU8(pos) != 0x00u || ringU8(pos + 1u) != 0x00u || ringU8(pos + 2u) != 0x01u)
                {
                    ++pos;
                    continue;
                }

                const uint8_t code = ringU8(pos + 3u);
                if (code == 0xB9u) // MPEG_program_end_code
                {
                    // Stop BEFORE consuming 00 00 01 B9 so FUN_0032ba90's exact readPtr == *(0x4882B4) loop switch fires.
                    if (!state.sawProgramEnd)
                    {
                        state.flushEndOfStreamLocked();
                    }
                    break;
                }
                if (code == 0xBAu) // pack_start_code
                {
                    if (pos + 12u > availBytes)
                        break;
                    if ((ringU8(pos + 4u) & 0xC0u) == 0x40u)
                    {
                        if (pos + 14u > availBytes)
                            break;
                        const uint32_t hdrLen = 14u + static_cast<uint32_t>(ringU8(pos + 13u) & 0x07u);
                        if (pos + hdrLen > availBytes)
                            break;
                        state.sawProgramEnd = false;
                        pos += hdrLen;
                    }
                    else
                    {
                        state.sawProgramEnd = false;
                        pos += 12u;
                    }
                    continue;
                }
                if (code >= 0xBBu) // system header / PES packets
                {
                    if (pos + 6u > availBytes)
                        break;
                    const uint32_t pesLen = (static_cast<uint32_t>(ringU8(pos + 4u)) << 8) | static_cast<uint32_t>(ringU8(pos + 5u));
                    const uint32_t pktTotal = 6u + pesLen;
                    if (pos + pktTotal > availBytes)
                        break;

                    if (code >= 0xE0u && code <= 0xEFu) // MPEG video ES
                    {
                        state.sawProgramEnd = false;
                        uint32_t payloadOff = 6u;
                        if (pesLen >= 3u && (ringU8(pos + 6u) & 0xC0u) == 0x80u)
                        {
                            payloadOff = 9u + static_cast<uint32_t>(ringU8(pos + 8u));
                        }
                        else if (pesLen >= 1u)
                        {
                            while (payloadOff < pktTotal && ringU8(pos + payloadOff) == 0xFFu)
                            {
                                ++payloadOff;
                            }
                            if (payloadOff + 2u <= pktTotal && (ringU8(pos + payloadOff) & 0xC0u) == 0x40u)
                            {
                                payloadOff += 2u;
                            }
                            if (payloadOff < pktTotal)
                            {
                                const uint8_t tsFlags = ringU8(pos + payloadOff);
                                if ((tsFlags & 0xF0u) == 0x20u)
                                    payloadOff += 5u;
                                else if ((tsFlags & 0xF0u) == 0x30u)
                                    payloadOff += 10u;
                                else if (tsFlags == 0x0Fu)
                                    payloadOff += 1u;
                            }
                        }

                        if (payloadOff < pktTotal)
                        {
                            const uint32_t esLen = pktTotal - payloadOff;
                            state.esBuf.resize(esLen);
                            ringCopy(pos + payloadOff, state.esBuf.data(), esLen);
                            state.decodeVideoBytesLocked(state.esBuf.data(), esLen);
                        }
                    }

                    pos += pktTotal;
                    continue;
                }

                ++pos;
            }

            SET_GPR_S32(ctx, 2, static_cast<int32_t>(pos));
            ctx->pc = getRegU32(ctx, 31);
        }

        inline void sceMpegGetPictureHle(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
        {
            (void)runtime;
            const uint32_t mp = getRegU32(ctx, 4);
            const uint32_t rgb32Dst = getRegU32(ctx, 5);
            const uint32_t gp = getRegU32(ctx, 28);

            uint32_t guestW = 0u, guestH = 0u, mbx = 0u, mby = 0u;
            (void)primal_sif_rpc::readGuestU32(rdram, ADD32(gp, 0xFFFFA254u), guestW);
            (void)primal_sif_rpc::readGuestU32(rdram, ADD32(gp, 0xFFFFA258u), guestH);
            (void)primal_sif_rpc::readGuestU32(rdram, ADD32(gp, 0xFFFFA25Cu), mbx);
            (void)primal_sif_rpc::readGuestU32(rdram, ADD32(gp, 0xFFFFA260u), mby);

            if (mbx == 0u || mbx > 64u)
                mbx = (guestW > 0u && guestW <= 1024u) ? ((guestW + 15u) / 16u) : 40u;
            if (mby == 0u || mby > 64u)
                mby = (guestH > 0u && guestH <= 1024u) ? ((guestH + 15u) / 16u) : 28u;

            const uint32_t dstW = mbx * 16u;
            const uint32_t dstH = (guestH > 0u && guestH <= mby * 16u) ? guestH : (mby * 16u);
            const uint32_t stripBytes = 16u * dstH * 4u;
            const uint32_t totalBytes = mbx * stripBytes;

            uint8_t *dstPtr = nullptr;
            uint32_t dstAvail = 0u;
            const bool dstMapped = (rgb32Dst != 0u) && primal_sif_rpc::mapGuestRange(rdram, rgb32Dst, dstPtr, dstAvail);

            PrimalMpegState &state = mpegState();
            std::lock_guard<std::mutex> lock(state.mtx);

            if (!state.frames.empty())
            {
                state.lastFrame = std::move(state.frames.front());
                state.frames.pop_front();
                ++state.frameCount;
            }

            if (dstMapped && dstPtr != nullptr && dstAvail >= totalBytes)
            {
                if (!state.lastFrame.rgba.empty() && state.lastFrame.width > 0 && state.lastFrame.height > 0)
                {
                    const uint32_t srcW = static_cast<uint32_t>(state.lastFrame.width);
                    const uint32_t srcH = static_cast<uint32_t>(state.lastFrame.height);
                    const uint8_t *srcBase = state.lastFrame.rgba.data();
                    for (uint32_t sx = 0u; sx < mbx; ++sx)
                    {
                        const uint32_t srcX = sx * 16u;
                        uint8_t *stripDst = dstPtr + static_cast<size_t>(sx) * stripBytes;
                        for (uint32_t y = 0u; y < dstH; ++y)
                        {
                            uint8_t *dstRow = stripDst + static_cast<size_t>(y) * 64u;
                            if (y < srcH && srcX < srcW)
                            {
                                const uint32_t copyPx = std::min<uint32_t>(16u, srcW - srcX);
                                const uint32_t copyBytes = copyPx * 4u;
                                std::memcpy(dstRow, srcBase + (static_cast<size_t>(y) * srcW + srcX) * 4u, copyBytes);
                                if (copyBytes < 64u)
                                {
                                    std::memset(dstRow + copyBytes, 0, 64u - copyBytes);
                                }
                            }
                            else
                            {
                                std::memset(dstRow, 0, 64u);
                            }
                        }
                    }
                }
                else
                {
                    std::memset(dstPtr, 0, totalBytes);
                }
            }

            if (mp != 0u)
            {
                (void)primal_sif_rpc::writeGuestU32(rdram, mp + 0x00u, dstW);
                (void)primal_sif_rpc::writeGuestU32(rdram, mp + 0x04u, dstH);
                (void)primal_sif_rpc::writeGuestU32(rdram, mp + 0x08u, state.frameCount);
            }

            SET_GPR_S32(ctx, 2, 0);
            ctx->pc = getRegU32(ctx, 31);
        }

        inline void sceMpegIsEndHle(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
        {
            (void)rdram;
            (void)runtime;
            PrimalMpegState &state = mpegState();
            std::lock_guard<std::mutex> lock(state.mtx);
            const int32_t ended = (state.sawProgramEnd && state.frames.empty()) ? 1 : 0;
            SET_GPR_S32(ctx, 2, ended);
            ctx->pc = getRegU32(ctx, 31);
        }

        inline void sceMpegResetHle(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
        {
            (void)rdram;
            (void)runtime;
            PrimalMpegState &state = mpegState();
            std::lock_guard<std::mutex> lock(state.mtx);
            state.resetStreamLocked();
            SET_GPR_S32(ctx, 2, 0);
            ctx->pc = getRegU32(ctx, 31);
        }

        inline void sceMpegDeleteHle(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
        {
            (void)rdram;
            (void)runtime;
            PrimalMpegState &state = mpegState();
            std::lock_guard<std::mutex> lock(state.mtx);
            state.destroyLocked();
            SET_GPR_S32(ctx, 2, 1);
            ctx->pc = getRegU32(ctx, 31);
        }

        inline void install(PS2Runtime &runtime)
        {
            auto bindHle = [&](uint32_t addr, PS2Runtime::RecompiledFunction fn)
            {
                if (runtime.hasFunction(addr))
                    runtime.replaceFunction(addr, fn);
                else
                    runtime.registerFunction(addr, fn);
            };
            bindHle(0x003EBD70u, &sceMpegInitHle);
            bindHle(0x003EBE18u, &sceMpegCreateHle);
            bindHle(0x003EC140u, &sceMpegAddCallbackHle);
            bindHle(0x003EB508u, &sceMpegAddStrCallbackHle);
            bindHle(0x003EB210u, &sceMpegDemuxPssRingHle);
            bindHle(0x003EC030u, &sceMpegGetPictureHle);
            bindHle(0x003EC088u, &sceMpegIsEndHle);
            bindHle(0x003EC098u, &sceMpegResetHle);
            bindHle(0x003EC020u, &sceMpegDeleteHle);
#if defined(PS2X_HAS_FFMPEG) && PS2X_HAS_FFMPEG
            RUNTIME_LOG("[primal-mpeg] HLE installed (FFmpeg=1)" << std::endl);
#else
            RUNTIME_LOG("[primal-mpeg] HLE installed (FFmpeg=0)" << std::endl);
#endif
        }
    }

    inline void applyPrimalDirectorRepair(PS2Runtime &runtime)
    {
        const char *e = std::getenv("PS2_DISABLE_DIRECTOR_REPAIR");
        if (e != nullptr && e[0] == '1')
            return;

        runtime.gs().setDebugHistoryPaused(false);

        g_origDirector = runtime.lookupFunction(0x002F5FD8u);
        g_orig32eae8 = runtime.lookupFunction(0x0032EAE8u);
        g_orig103d40 = runtime.lookupFunction(0x00103D40u);
        g_orig104808 = runtime.lookupFunction(0x00104808u);
        g_orig37e548 = runtime.lookupFunction(0x0037E548u);
        g_orig37e578 = runtime.lookupFunction(0x0037E578u);

        bool ok = true;
        if (g_origDirector)
            ok = runtime.replaceFunction(0x002F5FD8u, &directorWrap) && ok;
        if (g_orig32eae8)
            ok = runtime.replaceFunction(0x0032EAE8u, &eae8Wrap) && ok;
        if (g_orig37e548 && g_orig37e578)
            ok = runtime.replaceFunction(0x0037E548u, &wrap37e548) && ok;
        ok = SplitChainBridge<0x0025C560u, 0x0025C5D8u>::install(runtime) && ok;
        ok = SplitChainBridge<0x0028E188u, 0x0028E228u>::install(runtime) && ok;
        ok = SplitChainBridge<0x0028E228u, 0x0028E410u>::install(runtime) && ok;
        ok = SplitChainBridge<0x00299358u, 0x00299404u>::install(runtime) && ok;
        ok = SplitChainBridge<0x002F5E88u, 0x002F5F98u>::install(runtime) && ok;
        ok = SplitChainBridge<0x003BD9C0u, 0x003BDAC8u>::install(runtime) && ok;
        ok = SplitChainBridge<0x00299408u, 0x0029961Cu>::install(runtime) && ok;
        ok = SplitChainBridge<0x00299620u, 0x002996D8u>::install(runtime) && ok;
        ok = SplitChainBridge<0x00392DA0u, 0x00392FD0u>::install(runtime) && ok;
        ok = SplitChainBridge<0x003A5968u, 0x003A5B30u>::install(runtime) && ok;
        ok = SplitChainBridge<0x0028A9D8u, 0x0028AB9Cu>::install(runtime) && ok;
        ok = SplitChainBridge<0x0028ABA0u, 0x0028AC44u>::install(runtime) && ok;
        ok = SplitChainBridge<0x0028AE20u, 0x0028AFE0u>::install(runtime) && ok;
        runtime.replaceFunction(0x0028AE20u, &wrap28ae20);
        g_orig28ad80 = runtime.lookupFunction(0x0028AD80u);
        if (g_orig28ad80) runtime.replaceFunction(0x0028AD80u, &wrap28ad80);
        ok = SplitChainBridge<0x0028AFE0u, 0x0028B18Cu>::install(runtime) && ok;
        ok = SplitChainBridge<0x0028B438u, 0x0028B54Cu>::install(runtime) && ok;
        ok = SplitChainBridge<0x0028B908u, 0x0028BA48u>::install(runtime) && ok;
        ok = SplitChainBridge<0x0029B0A0u, 0x0029B334u>::install(runtime) && ok;
        ok = SplitChainBridge<0x0032DFF0u, 0x0032E8A8u>::install(runtime) && ok;
        ok = SplitChainBridge<0x003BA190u, 0x003BA1C4u>::install(runtime) && ok;
        ok = SplitChainBridge<0x00329FF0u, 0x0032AB78u>::install(runtime) && ok;
        runtime.replaceFunction(0x00329FF0u, &wrap329ff0);
        ok = SplitChainBridge<0x0011D3D0u, 0x0011F2B8u>::install(runtime) && ok;
        ok = SplitChainBridge<0x00116FE8u, 0x001176E8u>::install(runtime) && ok;
        ok = SplitChainBridge<0x003C2868u, 0x003C2B98u>::install(runtime) && ok;
        ok = SplitChainBridge<0x002F7360u, 0x002F7690u>::install(runtime) && ok;
        ok = SplitChainBridge<0x0032CD00u, 0x0032D270u>::install(runtime) && ok;
        g_orig32cd00b = runtime.lookupFunction(0x0032CD00u);
        if (g_orig32cd00b) runtime.replaceFunction(0x0032CD00u, &wrap32cd00b);
        if (std::getenv("PS2_SKIP_FMV") && std::getenv("PS2_SKIP_FMV")[0] == '1')
            runtime.replaceFunction(0x003EC030u, &skip3ec030);
        g_orig3170d0 = runtime.lookupFunction(0x003170D0u);
        if (g_orig3170d0)
            // PS2_SKIP_3170E0=1: leave 0x3170e0 unregistered so it hits missing-target and is
            // skipped — in probe_after_ipu.log that path led to the SWF title asset load (LBA 358527).
            if (!(std::getenv("PS2_SKIP_3170E0") && std::getenv("PS2_SKIP_3170E0")[0] == '1'))
                runtime.registerFunction(0x003170E0u, &stub3170e0);
        ok = SplitChainBridge<0x00317478u, 0x003174F8u>::install(runtime) && ok;
        runtime.registerFunction(0x0031740Cu, &stub31740c);
        runtime.registerFunction(0x002E5CB8u, &stub2e5cb8);
        runtime.registerFunction(0x002385F0u, &stub2385f0);
        ok = SplitChainBridge<0x00298200u, 0x00298410u>::install(runtime) && ok;
        g_orig298200 = runtime.lookupFunction(0x00298200u);
        if (g_orig298200) runtime.replaceFunction(0x00298200u, &wrap298200);
        ok = SplitChainBridge<0x0011F9C0u, 0x0011FC10u>::install(runtime) && ok;
        ok = SplitChainBridge<0x00121578u, 0x00121D28u>::install(runtime) && ok;
        ok = SplitChainBridge<0x00121D28u, 0x00121E88u>::install(runtime) && ok;
        ok = SplitChainBridge<0x00121E88u, 0x00121F54u>::install(runtime) && ok;
        ok = SplitChainBridge<0x0032A0D8u, 0x0032A154u>::install(runtime) && ok;
        ok = SplitChainBridge<0x0032A158u, 0x0032A978u>::install(runtime) && ok;
        ok = SplitChainBridge<0x00330A40u, 0x00330B1Cu>::install(runtime) && ok;
        ok = SplitChainBridge<0x003A50D0u, 0x003A5254u>::install(runtime) && ok;
        if (runtime.hasFunction(0x003A50D0u)) { g_orig3a50d0 = runtime.lookupFunction(0x003A50D0u); runtime.replaceFunction(0x003A50D0u, &wrap3a50d0); }
        if (runtime.hasFunction(0x003A4648u)) { g_orig3a4648 = runtime.lookupFunction(0x003A4648u); runtime.replaceFunction(0x003A4648u, &wrap3a4648); }
        ok = SplitChainBridge<0x003FD2B8u, 0x003FD504u>::install(runtime) && ok;
        ok = SplitChainBridge<0x00297FE8u, 0x00298194u>::install(runtime) && ok;
        ok = SplitChainBridge<0x0029B6E8u, 0x0029BD68u>::install(runtime) && ok;
        ok = SplitChainBridge<0x0032A85Cu, 0x0032A978u>::install(runtime) && ok;
        ok = SplitChainBridge<0x0032DDA0u, 0x0032DE48u>::install(runtime) && ok;
        ok = SplitChainBridge<0x0029FAF0u, 0x0029FCB0u>::install(runtime) && ok;
        ok = SplitChainBridge<0x0029FCB0u, 0x0029FD10u>::install(runtime) && ok;
        ok = SplitChainBridge<0x0029FD10u, 0x002A0108u>::install(runtime) && ok;
        ok = SplitChainBridge<0x002A0108u, 0x002A03D0u>::install(runtime) && ok;
        ok = SplitChainBridge<0x002A0400u, 0x002A2454u>::install(runtime) && ok;
        ok = SplitChainBridge<0x00102E10u, 0x00102F10u>::install(runtime) && ok;
        ok = SplitChainBridge<0x00103B28u, 0x00103D40u>::install(runtime) && ok;
        ok = SplitChainBridge<0x00105570u, 0x001059F8u>::install(runtime) && ok;
        // #83 Chains 1-8 upgraded to SplitChainResumeBridge (checkpoint-resume safe)
        ok = SplitChainResumeBridge<0x003A75A8u, 0x003A7688u>::install(runtime) && ok;
        ok = SplitChainResumeBridge<0x003A78E8u, 0x003A7970u>::install(runtime) && ok;
        ok = SplitChainResumeBridge<0x003A79F8u, 0x003A7A98u>::install(runtime) && ok;
        ok = SplitChainResumeBridge<0x003A7B28u, 0x003A7F08u>::install(runtime) && ok;
        ok = SplitChainResumeBridge<0x003A7F28u, 0x003A7FB8u>::install(runtime) && ok;
        ok = SplitChainResumeBridge<0x003A7FB8u, 0x003A8020u>::install(runtime) && ok;
        ok = SplitChainResumeBridge<0x003A8040u, 0x003A80D0u>::install(runtime) && ok;
        ok = SplitChainResumeBridge<0x0028CB48u, 0x0028CDD0u>::install(runtime) && ok;
        // #86/#91 Asset/Stream Loader orphan entry_* chains (0x3a4ac8..0x3ab2d8)
        ok = SplitChainResumeBridge<0x003A4AC8u, 0x003A4D00u>::install(runtime) && ok;
        ok = SplitChainResumeBridge<0x003A4D00u, 0x003A4F10u>::install(runtime) && ok;
        ok = SplitChainResumeBridge<0x003A4F10u, 0x003A50D0u>::install(runtime) && ok;
        if (runtime.hasFunction(0x003AA270u))
        {
            if (auto fn3aa270 = runtime.lookupFunction(0x003AA270u))
            {
                runtime.registerFunction(0x003AA278u, fn3aa270);
            }
        }
        ok = SplitChainResumeBridge<0x003A95F0u, 0x003AA2B8u>::install(runtime) && ok;
        ok = SplitChainResumeBridge<0x003AA368u, 0x003AA710u>::install(runtime) && ok;
        ok = SplitChainResumeBridge<0x003AAF38u, 0x003AAF90u>::install(runtime) && ok;
        ok = SplitChainResumeBridge<0x003AAF90u, 0x003AB2D8u>::install(runtime) && ok;
        // #86/#91 SWF Wrapper vtable 0x0044B948 (0x2e5b68..0x2e5c58)
        ok = SplitChainResumeBridge<0x002E5B68u, 0x002E5BD8u>::install(runtime) && ok;
        ok = SplitChainResumeBridge<0x002E5BD8u, 0x002E5C08u>::install(runtime) && ok;
        ok = SplitChainResumeBridge<0x002E5C28u, 0x002E5C58u>::install(runtime) && ok;
        // #86/#91 SWF Player / Sprite Renderer vtable orphan chains (0x2ec250..0x2ee030)
        ok = SplitChainResumeBridge<0x002EC250u, 0x002EC2F0u>::install(runtime) && ok;
        ok = SplitChainResumeBridge<0x002EC390u, 0x002EC500u>::install(runtime) && ok;
        ok = SplitChainResumeBridge<0x002EC500u, 0x002EC6C8u>::install(runtime) && ok;
        ok = SplitChainResumeBridge<0x002ECAB8u, 0x002ECC00u>::install(runtime) && ok;
        ok = SplitChainResumeBridge<0x002ECCB0u, 0x002ECDA8u>::install(runtime) && ok;
        ok = SplitChainResumeBridge<0x002ECDA8u, 0x002ECFC0u>::install(runtime) && ok;
        ok = SplitChainResumeBridge<0x002ECFC0u, 0x002ED060u>::install(runtime) && ok;
        ok = SplitChainResumeBridge<0x002ED080u, 0x002ED128u>::install(runtime) && ok;
        ok = SplitChainResumeBridge<0x002ED3B8u, 0x002ED4D0u>::install(runtime) && ok;
        ok = SplitChainResumeBridge<0x002EDBB8u, 0x002EDF88u>::install(runtime) && ok;
        ok = SplitChainResumeBridge<0x002EDFC8u, 0x002EE030u>::install(runtime) && ok;
        // #99 FUN_003385f0 + VU0 prefix bridges & dropped jr $ra delay-slot $sp restores
        if (runtime.hasFunction(0x00379C88u) && runtime.hasFunction(0x00379C8Cu))
        {
            g_orig379c88 = runtime.lookupFunction(0x00379C88u);
            g_orig379c8c = runtime.lookupFunction(0x00379C8Cu);
            runtime.replaceFunction(0x00379C88u, &wrap379c88);
        }
        if (runtime.hasFunction(0x0037D2A8u) && runtime.hasFunction(0x0037D2ACu))
        {
            g_orig37d2a8 = runtime.lookupFunction(0x0037D2A8u);
            g_orig37d2ac = runtime.lookupFunction(0x0037D2ACu);
            runtime.replaceFunction(0x0037D2A8u, &wrap37d2a8);
        }
        if (runtime.hasFunction(0x003385F0u))
        {
            g_orig3385f0 = runtime.lookupFunction(0x003385F0u);
            runtime.replaceFunction(0x003385F0u, &wrap3385f0);
        }
        // #104 FUN_002cf9e0 switch-table cases 2..10
        runtime.registerFunction(0x002CFA50u, &stub2cf9e0FloatCase<0x2B4u>);
        runtime.registerFunction(0x002CFA68u, &stub2cf9e0FloatCase<0x2B8u>);
        runtime.registerFunction(0x002CFA80u, &stub2cf9e0FloatCase<0x2BCu>);
        runtime.registerFunction(0x002CFA98u, &stub2cf9e0CallCase<0x002CFE30u, 0x002CFA9Cu, 0x002CFAA4u>);
        runtime.registerFunction(0x002CFAACu, &stub2cf9e0CallCase<0x002CFC48u, 0x002CFAB0u, 0x002CFAB8u>);
        runtime.registerFunction(0x002CFAC0u, &stub2cf9e0CallCase<0x002CFCE8u, 0x002CFAC4u, 0x002CFACCu>);
        runtime.registerFunction(0x002CFAD4u, &stub2cfad4);
        runtime.registerFunction(0x002CFAF0u, &stub2cfaf0);
        // #109 FUN_002dbe58 switch-table cases 7, 9, 10, 12
        runtime.registerFunction(0x002DC038u, &stub2dc038);
        runtime.registerFunction(0x002DC050u, &stub2dc050);
        runtime.registerFunction(0x002DC068u, &stub2dc068);
        runtime.registerFunction(0x002DC0CCu, &stub2dc0cc);
        // #110 Missing switch-table case 5 (0x2cb64c) and 4 actor factories merged into destructor tails
        runtime.registerFunction(0x002CB64Cu, &stub2cb64c);
        runtime.registerFunction(0x001449B8u, &primalActorFactoryStub<0x001449B8u, 0x114u, 0x00144540u>);
        runtime.registerFunction(0x00149560u, &primalActorFactoryStub<0x00149560u, 0x280u, 0x00148350u>);
        runtime.registerFunction(0x0014D998u, &primalActorFactoryStub<0x0014D998u, 0x370u, 0x0014CF70u>);
        runtime.registerFunction(0x001A2ED0u, &primalActorFactoryStub<0x001A2ED0u, 0x360u, 0x001A2E08u>);
        for (uint32_t pc1036c8 : {0x001036C8u, 0x0010370Cu, 0x00103714u, 0x00103758u,
                                  0x00103770u, 0x001037A8u, 0x00103804u, 0x00103854u,
                                  0x00103920u, 0x00103938u, 0x00103950u, 0x0010395Cu,
                                  0x00103968u, 0x00103984u, 0x001039A0u, 0x001039E8u,
                                  0x001039ECu})
        {
            runtime.registerFunction(pc1036c8, &func1036c8Override);
        }
        for (uint32_t pc103a18 : {0x00103A18u, 0x00103AC8u, 0x00103AE8u, 0x00103B1Cu})
        {
            runtime.registerFunction(pc103a18, &func103a18Override);
        }
        ok = SplitChainBridge<0x00104A00u, 0x00104B4Cu>::install(runtime) && ok;
        runtime.replaceFunction(0x00104A00u, &wrap104a00);
        g_orig2f6918 = runtime.lookupFunction(0x002F6918u);
        if (g_orig2f6918) runtime.replaceFunction(0x002F6918u, &wrap2f6918);
        g_orig28a400 = runtime.lookupFunction(0x0028A400u);
        if (g_orig28a400) runtime.replaceFunction(0x0028A400u, &wrap28a400);
        g_orig28b888 = runtime.lookupFunction(0x0028B888u);
        if (g_orig28b888) runtime.replaceFunction(0x0028B888u, &wrap28b888);
        g_orig3fbfa0 = runtime.lookupFunction(0x003FBFA0u);
        if (g_orig3fbfa0) runtime.replaceFunction(0x003FBFA0u, &wrap3fbfa0);
        ok = SplitChainBridge<0x003B92E0u, 0x003B93A8u>::install(runtime) && ok;
        ok = SplitChainBridge<0x003B95F8u, 0x003B96ECu>::install(runtime) && ok;
        g_orig11f498 = runtime.lookupFunction(0x0011F498u);
        if (g_orig11f498) runtime.replaceFunction(0x0011F498u, &wrap11f498);
        if (g_orig103d40)
            runtime.replaceFunction(0x00103D40u, &wrap103d40);
        if (g_orig104808)
            runtime.replaceFunction(0x00104808u, &wrap104808);
        g_orig104198 = runtime.lookupFunction(0x00104198u);
        if (g_orig104198)
            runtime.replaceFunction(0x00104198u, &wrap104198);
        static const bool s_gatePrimalTelemetry = [] {
            const char *e = std::getenv("PS2_PRIMAL_VERBOSE_LOGS");
            return e != nullptr && e[0] == '1';
        }();
        if (s_gatePrimalTelemetry)
        {
            HeartbeatProbe<0x003EF3A8u>::install(runtime);
            HeartbeatProbe<0x003EF110u>::install(runtime);
            HeartbeatProbe<0x003EF4B0u>::install(runtime);
            HeartbeatProbe<0x003F0748u>::install(runtime);
            HeartbeatProbe<0x003F03B0u>::install(runtime);
            HeartbeatProbe<0x003A5C90u>::install(runtime); // frame-node dispatch
            HeartbeatProbe<0x003A5D80u>::install(runtime); // frame-node create
        }
        g_orig3e62f8 = runtime.lookupFunction(0x003E62F8u);
        if (g_orig3e62f8) runtime.replaceFunction(0x003E62F8u, &wrap3e62f8);
        g_orig32a148 = runtime.lookupFunction(0x0032A148u);
        if (g_orig32a148) runtime.replaceFunction(0x0032A148u, &wrap32a148);
        if (runtime.hasFunction(0x0032A248u)) { g_orig32a248 = runtime.lookupFunction(0x0032A248u); runtime.replaceFunction(0x0032A248u, &wrap32a248); }
        if (runtime.hasFunction(0x0032A1F0u)) { g_orig32a1f0 = runtime.lookupFunction(0x0032A1F0u); runtime.replaceFunction(0x0032A1F0u, &wrap32a1f0); }
        g_orig32aa48 = runtime.lookupFunction(0x0032AA48u);
        if (g_orig32aa48) runtime.replaceFunction(0x0032AA48u, &wrap32aa48);
        g_orig3a3c40 = runtime.lookupFunction(0x003A3C40u);
        if (g_orig3a3c40) runtime.replaceFunction(0x003A3C40u, &wrap3a3c40);
        runtime.registerFunction(0x00400000u, &ret1stub);
        g_orig2f73a4 = runtime.lookupFunction(0x002F73A4u);
        if (g_orig2f73a4) runtime.replaceFunction(0x002F73A4u, &wrap2f73a4);
        g_orig282640 = runtime.lookupFunction(0x00282640u);
        if (g_orig282640) runtime.replaceFunction(0x00282640u, &wrap282640);
        g_orig32a9e0 = runtime.lookupFunction(0x0032A9E0u);
        if (g_orig32a9e0) runtime.replaceFunction(0x0032A9E0u, &wrap32a9e0); // scene chunk job queue
        if (s_gatePrimalTelemetry)
        {
            HeartbeatProbe<0x003FD2B8u>::install(runtime); // scene request
            HeartbeatProbe<0x0032B168u>::install(runtime);
            HeartbeatProbe<0x0032B348u>::install(runtime);
            HeartbeatProbe<0x0032B738u>::install(runtime);
            HeartbeatProbe<0x0032B910u>::install(runtime);
            HeartbeatProbe<0x0032BA90u>::install(runtime);
            HeartbeatProbe<0x0032C1B8u>::install(runtime);
            HeartbeatProbe<0x0032C238u>::install(runtime);
            HeartbeatProbe<0x0032C330u>::install(runtime);
            HeartbeatProbe<0x0032C5D0u>::install(runtime);
            HeartbeatProbe<0x0032C670u>::install(runtime);
            HeartbeatProbe<0x0032C7A0u>::install(runtime);
            HeartbeatProbe<0x0032C858u>::install(runtime);
            HeartbeatProbe<0x0032AF00u>::install(runtime);
            HeartbeatProbe<0x0032E20Cu>::install(runtime);
        }

        // 1. Missing target 0x311728 -> entry_00311708 lacks case 0x311728u; use stub311728
        g_orig311708 = runtime.lookupFunction(0x00311708u);
        if (g_orig311708)
        {
            runtime.registerFunction(0x00311728u, &stub311728);
            runtime.registerFunction(0x003118A8u, &stub3118a8);
            runtime.registerFunction(0x0031190Cu, &stub31190c);
            if (auto f954 = runtime.lookupFunction(0x00311954u))
                runtime.registerFunction(0x00311974u, f954);
            if (auto f9bc = runtime.lookupFunction(0x003119BCu))
                runtime.registerFunction(0x003119DCu, f9bc);
            runtime.registerFunction(0x00311A6Cu, &stub311a6c);
            runtime.registerFunction(0x00311A84u, &stub311a84);
            runtime.registerFunction(0x00311AA0u, &stub311aa0);
            runtime.registerFunction(0x00311ABCu, &stub311abc);
            runtime.registerFunction(0x00311AD8u, &stub311ad8);
            RUNTIME_LOG("[game_overrides] registered 0x311728 -> stub311728 (+9 jump-table targets): YES");
        }

        // 2. Missing target 0x2385C8 -> bundled wrapper calling 0x002A0400
        runtime.registerFunction(0x002385C8u, &func_2385c8);
        RUNTIME_LOG("[game_overrides] registered 0x2385C8 -> func_2385c8: YES");

        // 3. Thread 2 allocator loop guard for 0x28acb8 / 0x28acc8
        g_orig28acb8 = runtime.lookupFunction(0x0028ACB8u);
        if (g_orig28acb8)
        {
            runtime.replaceFunction(0x0028ACB8u, &wrap_28acb8);
            runtime.replaceFunction(0x0028ACC8u, &wrap_28acb8);
            RUNTIME_LOG("[game_overrides] registered 0x28acb8/0x28acc8 loop guard: YES");
        }

        Eae8CalleeProbe<0x0028A2D8u>::install(runtime);
        Eae8CalleeProbe<0x00330960u>::install(runtime);
        Eae8CalleeProbe<0x0028A4E0u>::install(runtime);
        Eae8CalleeProbe<0x00330F48u>::install(runtime);
        Eae8CalleeProbe<0x00329A18u>::install(runtime);
        Eae8CalleeProbe<0x00329AB0u>::install(runtime);
        Eae8CalleeProbe<0x003C2868u>::install(runtime);
        g_orig2fa198 = runtime.lookupFunction(0x002FA198u);
        if (g_orig2fa198)
            runtime.replaceFunction(0x002FA198u, &wrap2fa198);

        g_orig2f92f0 = runtime.lookupFunction(0x002F92F0u);
        if (g_orig2f92f0)
            runtime.replaceFunction(0x002F92F0u, &wrap2f92f0);
        Eae8CalleeProbe<0x002FA968u>::install(runtime);
        Eae8CalleeProbe<0x00286E90u>::install(runtime);
        Eae8CalleeProbe<0x0023AE20u>::install(runtime);
        Eae8CalleeProbe<0x00103490u>::install(runtime);
        Eae8CalleeProbe<0x00103598u>::install(runtime);
        Eae8CalleeProbe<0x002F85D8u>::install(runtime);
        Eae8CalleeProbe<0x0028A2A0u>::install(runtime);
        SplitChainBridge<0x002E1180u, 0x002E142Cu>::install(runtime);
        SplitChainBridge<0x002E1C98u, 0x002E2578u>::install(runtime);
        SplitChainBridge<0x002E2628u, 0x002E3220u>::install(runtime);
        PrimalInflateAvailInBoost::install(runtime);
        PrimalBezierTessellationGuard::install(runtime);
        PrimalPackedVtablesAndHeapGuard::install(runtime);

        if (s_gatePrimalTelemetry)
        {
            installClusterSweep(runtime);
            installHotClusterLoggers(runtime);
        }
        g_orig2830a0 = runtime.lookupFunction(0x002830A0u);
        if (g_orig2830a0) runtime.replaceFunction(0x002830A0u, &wrap2830a0);
        g_orig30f9f8 = runtime.lookupFunction(0x0030F9F8u);
        if (g_orig30f9f8) runtime.replaceFunction(0x0030F9F8u, &wrap30f9f8);
        g_orig3ebe18 = runtime.lookupFunction(0x003EBE18u);
        if (g_orig3ebe18) runtime.replaceFunction(0x003EBE18u, &wrap3ebe18);
        g_orig32c238 = runtime.lookupFunction(0x0032C238u);
        if (g_orig32c238) runtime.replaceFunction(0x0032C238u, &wrap32c238);
        g_orig3caa08 = runtime.lookupFunction(0x003CAA08u);
        if (g_orig3caa08) runtime.replaceFunction(0x003CAA08u, &wrap3caa08);
        g_orig3ca848 = runtime.lookupFunction(0x003CA848u);
        if (g_orig3ca848) runtime.replaceFunction(0x003CA848u, &wrap3ca848);
        g_orig3ccec0 = runtime.lookupFunction(0x003CCEC0u);
        if (g_orig3ccec0) runtime.replaceFunction(0x003CCEC0u, &wrap3ccec0);
        g_orig32aca8 = runtime.lookupFunction(0x0032ACA8u);
        if (g_orig32aca8) runtime.replaceFunction(0x0032ACA8u, &wrap32aca8);
        { PS2Runtime::RecompiledFunction f = runtime.lookupFunction(0x0032E1D8u); if (f) runtime.registerFunction(0x0032E20Cu, f); RUNTIME_LOG("[alias] 32e20c->32e1d8 " << (f ? "YES" : "NO") << std::endl); }
        { PS2Runtime::RecompiledFunction f = runtime.lookupFunction(0x0032A1E8u); if (f) runtime.registerFunction(0x0032A1F0u, f); RUNTIME_LOG("[alias] 32a1f0->32a1e8 " << (f ? "YES" : "NO") << std::endl); }
        { PS2Runtime::RecompiledFunction f = runtime.lookupFunction(0x0032A220u); if (f) runtime.registerFunction(0x0032A248u, f); RUNTIME_LOG("[alias] 32a248->32a220 " << (f ? "YES" : "NO") << std::endl); }
        g_orig32cf20u = runtime.lookupFunction(0x0032CF20u);
        if (g_orig32cf20u) runtime.replaceFunction(0x0032CF20u, &wrap32cf20u);
        g_orig32b168 = runtime.lookupFunction(0x0032B168u);
        if (g_orig32b168) runtime.replaceFunction(0x0032B168u, &wrap32b168);
        g_orig32b798 = runtime.lookupFunction(0x0032B798u);
        if (g_orig32b798) runtime.replaceFunction(0x0032B798u, &wrap32b798);
        g_orig3a3940 = runtime.lookupFunction(0x003A3940u);
        if (g_orig3a3940) runtime.replaceFunction(0x003A3940u, &wrap3a3940);
        g_orig28a798 = runtime.lookupFunction(0x0028A798u);
        if (g_orig28a798) runtime.replaceFunction(0x0028A798u, &wrap28a798);
        g_orig32a978 = runtime.lookupFunction(0x0032A978u);
        if (g_orig32a978) runtime.replaceFunction(0x0032A978u, &wrap32a978);
        if (!(std::getenv("PS2_SKIP_FMV") && std::getenv("PS2_SKIP_FMV")[0] == '1'))
            primal_mpeg_hle::install(runtime);
        RUNTIME_LOG("[game_overrides] director/32eae8 repair installed: " << (ok ? "YES" : "NO"));
    }

    inline const ps2_game_overrides::Descriptor kPrimalDirectorRepairDescriptor{
        "Primal director (0x2F5FD8) / 0x32EAE8 frame repair",
        "SCUS_971.42",
        0x00100008u,
        0xAB6FB13Cu,
        &applyPrimalDirectorRepair
    };

    inline const ps2_game_overrides::AutoRegister kPrimalDirectorRepairRegistrar{
        kPrimalDirectorRepairDescriptor
    };
}

namespace ps2_game_overrides::primal_model_override
{
    struct ActorOverrideEntry
    {
        std::string key;       // e.g. "jen", "scree", or hex hash
        std::string glbPath;   // path to .glb in mods/models/
        uint32_t expectedBones = 0u; // 47 for Jen, 49 for Scree, 0 = match by key/hash
        Model model{};
        ModelAnimation *anims = nullptr;
        int animCount = 0;
        int animFrame = 0;
        bool loadAttempted = false;
        bool loaded = false;
    };

    struct PendingActorDraw
    {
        std::string key;
        Vector3 position{0.0f, 0.0f, 0.0f};
        float yawDeg = 0.0f;
        float scale = 1.0f;
        uint32_t boneCount = 0u;
    };

    inline std::mutex g_modelMutex;
    inline std::vector<ActorOverrideEntry> g_overrides;
    inline std::vector<PendingActorDraw> g_pendingDraws;
    inline PS2Runtime::RecompiledFunction g_orig29a338 = nullptr;
    inline PS2Runtime::RecompiledFunction g_orig298200 = nullptr;

    inline std::string resolveModelsDir()
    {
        if (const char *envDir = std::getenv("PS2_MODS_MODELS_DIR"))
        {
            if (envDir[0] != '\0')
                return std::string(envDir);
        }
        if (std::filesystem::is_directory("mods/models"))
            return "mods/models";
        if (std::filesystem::is_directory("H:/DeepSeekWorkspace/Primal_SR/mods/models"))
            return "H:/DeepSeekWorkspace/Primal_SR/mods/models";
        return "";
    }

    inline void scanModsModels()
    {
        std::lock_guard<std::mutex> lock(g_modelMutex);
        g_overrides.clear();
        const std::string dir = resolveModelsDir();
        if (dir.empty())
            return;

        std::error_code ec;
        for (const auto &entry : std::filesystem::directory_iterator(dir, ec))
        {
            if (ec || !entry.is_regular_file())
                continue;
            const auto ext = entry.path().extension().string();
            if (ext != ".glb" && ext != ".GLB" && ext != ".gltf" && ext != ".GLTF")
                continue;

            ActorOverrideEntry item;
            item.key = entry.path().stem().string();
            item.glbPath = entry.path().string();
            if (item.key == "jen" || item.key == "0x50959e1a" || item.key == "50959e1a")
                item.expectedBones = 47u;
            else if (item.key == "scree" || item.key == "0x4bacb5ef" || item.key == "4bacb5ef")
                item.expectedBones = 49u;
            g_overrides.push_back(std::move(item));
        }
        if (!g_overrides.empty())
        {
            RUNTIME_LOG("[stageC:models] discovered " << g_overrides.size()
                        << " replacement model(s) in " << dir);
        }
    }

    inline uint32_t readDmaCursorStructPtr(uint8_t *rdram)
    {
        uint32_t g4F1F98 = 0u;
        if (!primal_sif_rpc::readGuestU32(rdram, 0x004F1F98u, g4F1F98) || g4F1F98 == 0u)
            return 0u;
        uint32_t p10 = 0u, p50 = 0u, p0 = 0u, cursorStruct = 0u;
        if (!primal_sif_rpc::readGuestU32(rdram, g4F1F98 + 0x10u, p10) || p10 == 0u)
            return 0u;
        if (!primal_sif_rpc::readGuestU32(rdram, p10 + 0x50u, p50) || p50 == 0u)
            return 0u;
        if (!primal_sif_rpc::readGuestU32(rdram, p50, p0) || p0 == 0u)
            return 0u;
        if (!primal_sif_rpc::readGuestU32(rdram, p0 + 0x250u, cursorStruct) || cursorStruct == 0u)
            return 0u;
        return cursorStruct;
    }

    inline float readGuestF32(uint8_t *rdram, uint32_t addr)
    {
        uint32_t bits = 0u;
        if (!primal_sif_rpc::readGuestU32(rdram, addr, bits))
            return 0.0f;
        float f = 0.0f;
        std::memcpy(&f, &bits, sizeof(f));
        return f;
    }

    inline void wrap29a338(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        bool hasAnyOverride = false;
        {
            std::lock_guard<std::mutex> lock(g_modelMutex);
            hasAnyOverride = !g_overrides.empty();
        }
        if (!hasAnyOverride)
        {
            if (g_orig29a338) g_orig29a338(rdram, ctx, runtime);
            return;
        }

        const uint32_t cursorStruct = readDmaCursorStructPtr(rdram);
        uint32_t dmaBefore = 0u;
        if (cursorStruct != 0u)
            (void)primal_sif_rpc::readGuestU32(rdram, cursorStruct, dmaBefore);

        // Execute original FUN_0029a338 so EE RAM root-motion, skeleton, and collision state stay synced.
        if (g_orig29a338) g_orig29a338(rdram, ctx, runtime);

        if (cursorStruct == 0u || dmaBefore == 0u)
            return;

        uint32_t dmaAfter = 0u;
        if (!primal_sif_rpc::readGuestU32(rdram, cursorStruct, dmaAfter) || dmaAfter <= dmaBefore)
            return;

        // Scan emitted DMAC1/VIF1 words for bone-matrix UNPACK V4-32 (0x6C000042 | (numBones << 18)).
        uint32_t detectedBones = 0u;
        uint32_t matrixBaseAddr = 0u;
        for (uint32_t addr = dmaBefore; addr + 16u <= dmaAfter; addr += 4u)
        {
            uint32_t w = 0u;
            if (!primal_sif_rpc::readGuestU32(rdram, addr, w))
                break;
            if ((w & 0xFC00FFFFu) == 0x6C000042u)
            {
                detectedBones = (w >> 18) & 0xFFu;
                matrixBaseAddr = (addr & ~0xFu) + 16u;
                break;
            }
        }
        if (detectedBones == 0u)
            return;

        std::string matchedKey;
        {
            std::lock_guard<std::mutex> lock(g_modelMutex);
            for (const auto &ov : g_overrides)
            {
                if (ov.expectedBones != 0u && ov.expectedBones == detectedBones)
                {
                    matchedKey = ov.key;
                    break;
                }
            }
            if (!matchedKey.empty())
            {
                PendingActorDraw draw;
                draw.key = matchedKey;
                draw.boneCount = detectedBones;
                // Bone 0 (pelvis/root) 4x4 matrix row 3 translation at +0x30..+0x38.
                draw.position.x = readGuestF32(rdram, matrixBaseAddr + 0x30u);
                draw.position.y = readGuestF32(rdram, matrixBaseAddr + 0x34u);
                draw.position.z = readGuestF32(rdram, matrixBaseAddr + 0x38u);
                const float fx = readGuestF32(rdram, matrixBaseAddr + 0x20u);
                const float fz = readGuestF32(rdram, matrixBaseAddr + 0x28u);
                draw.yawDeg = std::atan2(fx, fz) * (180.0f / 3.14159265f);
                g_pendingDraws.push_back(std::move(draw));
            }
        }

        // Suppress the legacy VIF1/GS draw packet for the replaced actor by rewinding the DMA cursor.
        if (!matchedKey.empty())
        {
            (void)primal_sif_rpc::writeGuestU32(rdram, cursorStruct, dmaBefore);
        }
    }

    inline void wrap298200(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        if (g_orig298200) g_orig298200(rdram, ctx, runtime);
    }

    inline void drawHostModelOverlay(PS2Runtime &, float dstX, float dstY, float dstW, float dstH, void *)
    {
        std::vector<PendingActorDraw> draws;
        {
            std::lock_guard<std::mutex> lock(g_modelMutex);
            if (g_overrides.empty() || g_pendingDraws.empty())
                return;
            draws.swap(g_pendingDraws);
            for (auto &ov : g_overrides)
            {
                if (!ov.loadAttempted)
                {
                    ov.loadAttempted = true;
                    ov.model = LoadModel(ov.glbPath.c_str());
                    ov.loaded = (ov.model.meshCount > 0);
                    if (ov.loaded)
                    {
                        ov.anims = LoadModelAnimations(ov.glbPath.c_str(), &ov.animCount);
                    }
                    RUNTIME_LOG("[stageC:models] loaded '" << ov.glbPath
                                << "' meshes=" << ov.model.meshCount
                                << " anims=" << ov.animCount);
                }
            }
        }

        Camera3D cam{};
        cam.position = Vector3{0.0f, 2.0f, 6.0f};
        cam.target = Vector3{0.0f, 1.0f, 0.0f};
        cam.up = Vector3{0.0f, 1.0f, 0.0f};
        cam.fovy = 45.0f;
        cam.projection = CAMERA_PERSPECTIVE;

        BeginScissorMode(static_cast<int>(dstX), static_cast<int>(dstY),
                         static_cast<int>(dstW), static_cast<int>(dstH));
        BeginMode3D(cam);
        std::lock_guard<std::mutex> lock(g_modelMutex);
        for (const auto &d : draws)
        {
            for (auto &ov : g_overrides)
            {
                if (!ov.loaded || ov.key != d.key)
                    continue;
                if (ov.anims != nullptr && ov.animCount > 0 && ov.anims[0].frameCount > 0)
                {
                    ov.animFrame = (ov.animFrame + 1) % ov.anims[0].frameCount;
                    UpdateModelAnimation(ov.model, ov.anims[0], ov.animFrame);
                }
                DrawModelEx(ov.model, d.position, Vector3{0.0f, 1.0f, 0.0f}, d.yawDeg,
                            Vector3{d.scale, d.scale, d.scale}, WHITE);
                break;
            }
        }
        EndMode3D();
        EndScissorMode();
    }

    inline void shutdownHostModelOverlay(PS2Runtime &, float, float, float, float, void *)
    {
        std::lock_guard<std::mutex> lock(g_modelMutex);
        for (auto &ov : g_overrides)
        {
            if (ov.anims != nullptr)
            {
                UnloadModelAnimations(ov.anims, ov.animCount);
                ov.anims = nullptr;
                ov.animCount = 0;
            }
            if (ov.loaded)
            {
                UnloadModel(ov.model);
                ov.loaded = false;
            }
        }
    }

    inline void applyPrimalModelOverride(PS2Runtime &runtime)
    {
        static bool s_installed = false;
        if (s_installed)
            return;
        const char *e = std::getenv("PS2_DISABLE_STAGE_C_MODELS");
        if (e != nullptr && e[0] == '1')
            return;
        s_installed = true;

        scanModsModels();
        auto cur29a338 = runtime.lookupFunction(0x0029A338u);
        if (cur29a338 && cur29a338 != &wrap29a338)
        {
            g_orig29a338 = cur29a338;
            runtime.replaceFunction(0x0029A338u, &wrap29a338);
        }
        runtime.setHostOverlayCallbacks(&drawHostModelOverlay, &shutdownHostModelOverlay, nullptr);
        RUNTIME_LOG("[game_overrides] Stage C model override hook installed (29a338="
                    << (g_orig29a338 ? "YES" : "NO") << ")");
    }

    inline const ps2_game_overrides::Descriptor kPrimalModelOverrideDescriptor{
        "Primal Stage C glTF model override",
        "SCUS_971.42",
        0x00100008u,
        0xAB6FB13Cu,
        &applyPrimalModelOverride
    };

    inline const ps2_game_overrides::AutoRegister kPrimalModelOverrideRegistrar{
        kPrimalModelOverrideDescriptor
    };
}

namespace ps2_game_overrides::primal_expansion_realm
{
    struct RlexHeader
    {
        char magic[8];
        uint32_t version;
        float box0[6];
        float oct0[4];
        uint32_t cne0Count;
        uint32_t cne0Off;
        uint32_t spawnCount;
        uint32_t spawnOff;
        uint32_t spawnSize;
        uint32_t glbOff;
        uint32_t glbSize;
    };

    inline std::mutex g_realmMutex;
    inline bool g_realmLoaded = false;
    inline bool g_realmActive = false;
    inline RlexHeader g_header{};
    inline std::vector<uint8_t> g_cne0Bytes;
    inline std::string g_cachedGlbPath;
    inline Model g_realmModel{};
    inline bool g_realmModelAttempted = false;
    inline bool g_realmModelReady = false;
    inline uint32_t g_eeCne0Addr = 0u;
    inline uint32_t g_eeMsh0Addr = 0u;
    inline uint32_t g_eeOct0Addr = 0u;
    inline PS2Runtime::RecompiledFunction g_orig2f4b30 = nullptr;

    inline std::string resolveRealmPath()
    {
        if (const char *p = std::getenv("PS2_EXPANSION_REALM_PATH"))
        {
            if (p[0] != '\0' && std::filesystem::is_regular_file(p))
                return std::string(p);
        }
        if (std::filesystem::is_regular_file("mods/realms/REALM_EXPANSION_01.rlex"))
            return "mods/realms/REALM_EXPANSION_01.rlex";
        if (std::filesystem::is_regular_file("H:/DeepSeekWorkspace/Primal_SR/mods/realms/REALM_EXPANSION_01.rlex"))
            return "H:/DeepSeekWorkspace/Primal_SR/mods/realms/REALM_EXPANSION_01.rlex";
        return "";
    }

    inline void loadRealmPackage()
    {
        std::lock_guard<std::mutex> lock(g_realmMutex);
        if (g_realmLoaded)
            return;
        const std::string path = resolveRealmPath();
        if (path.empty())
            return;

        std::ifstream f(path, std::ios::binary);
        if (!f.is_open())
            return;
        RlexHeader hdr{};
        f.read(reinterpret_cast<char *>(&hdr), sizeof(hdr));
        if (!f || std::memcmp(hdr.magic, "RLEX01\0\0", 8) != 0)
            return;

        const uint32_t cne0BytesLen = hdr.cne0Count * 32u;
        g_cne0Bytes.resize(cne0BytesLen);
        if (cne0BytesLen > 0u)
        {
            f.seekg(static_cast<std::streamoff>(hdr.cne0Off), std::ios::beg);
            f.read(reinterpret_cast<char *>(g_cne0Bytes.data()), cne0BytesLen);
        }

        if (hdr.glbSize > 0u)
        {
            std::vector<uint8_t> glb(hdr.glbSize);
            f.seekg(static_cast<std::streamoff>(hdr.glbOff), std::ios::beg);
            f.read(reinterpret_cast<char *>(glb.data()), hdr.glbSize);
            std::filesystem::path cachePath = std::filesystem::path(path).parent_path() / "REALM_EXPANSION_01_env.glb";
            std::ofstream out(cachePath, std::ios::binary | std::ios::trunc);
            if (out.is_open())
            {
                out.write(reinterpret_cast<const char *>(glb.data()), hdr.glbSize);
                g_cachedGlbPath = cachePath.string();
            }
        }

        g_header = hdr;
        g_realmLoaded = true;
        RUNTIME_LOG("[stageD:realm] loaded '" << path << "' cne0=" << hdr.cne0Count
                    << " spawns=" << hdr.spawnCount << " glbBytes=" << hdr.glbSize);
    }

    inline void injectCollisionIntoEeRam(uint8_t *rdram, PS2Runtime *runtime)
    {
        std::lock_guard<std::mutex> lock(g_realmMutex);
        if (!g_realmLoaded || g_eeMsh0Addr != 0u || runtime == nullptr)
            return;

        const uint32_t cne0Size = static_cast<uint32_t>(g_cne0Bytes.size());
        const uint32_t totalSize = 0x20u + 0x44u + cne0Size + 16u;
        const uint32_t base = runtime->guestMalloc(totalSize, 16u);
        if (base == 0u)
            return;

        g_eeOct0Addr = base;
        g_eeMsh0Addr = base + 0x20u;
        g_eeCne0Addr = base + 0x64u;

        // OCT0 (0x20 bytes): cx, cy, cz, half_size
        for (int i = 0; i < 4; ++i)
        {
            uint32_t bits = 0u;
            std::memcpy(&bits, &g_header.oct0[i], sizeof(bits));
            (void)primal_sif_rpc::writeGuestU32(rdram, g_eeOct0Addr + static_cast<uint32_t>(i * 4), bits);
        }
        // MSH0 (0x44 bytes): flags |= 1 at +0x00, cne0_ptr at +0x38
        (void)primal_sif_rpc::writeGuestU32(rdram, g_eeMsh0Addr + 0x00u, 1u);
        (void)primal_sif_rpc::writeGuestU32(rdram, g_eeMsh0Addr + 0x38u, g_eeCne0Addr);

        // CNE0 (32 bytes per triangle)
        if (cne0Size > 0u && (g_eeCne0Addr + cne0Size) <= PS2_RAM_SIZE)
        {
            std::memcpy(rdram + g_eeCne0Addr, g_cne0Bytes.data(), cne0Size);
        }

        g_realmActive = true;
        RUNTIME_LOG("[stageD:realm] injected EE collision: OCT0=0x" << std::hex << g_eeOct0Addr
                    << " MSH0=0x" << g_eeMsh0Addr << " CNE0=0x" << g_eeCne0Addr
                    << std::dec << " (" << g_header.cne0Count << " planes)");
    }

    inline void wrap2f4b30(uint8_t *rdram, R5900Context *ctx, PS2Runtime *runtime)
    {
        if (g_orig2f4b30) g_orig2f4b30(rdram, ctx, runtime);
        const char *envActive = std::getenv("PS2_EXPANSION_REALM");
        if (envActive != nullptr && envActive[0] == '1')
        {
            injectCollisionIntoEeRam(rdram, runtime);
        }
    }

    inline void drawRealmAndModelsOverlay(PS2Runtime &runtime, float dstX, float dstY, float dstW, float dstH, void *userData)
    {
        ps2_game_overrides::primal_model_override::drawHostModelOverlay(runtime, dstX, dstY, dstW, dstH, userData);

        std::lock_guard<std::mutex> lock(g_realmMutex);
        if (!g_realmActive || g_cachedGlbPath.empty())
            return;

        if (!g_realmModelAttempted)
        {
            g_realmModelAttempted = true;
            g_realmModel = LoadModel(g_cachedGlbPath.c_str());
            g_realmModelReady = (g_realmModel.meshCount > 0);
            RUNTIME_LOG("[stageD:realm] loaded env glb '" << g_cachedGlbPath
                        << "' meshes=" << g_realmModel.meshCount);
        }
        if (!g_realmModelReady)
            return;

        Camera3D cam{};
        cam.position = Vector3{0.0f, 5.0f, 12.0f};
        cam.target = Vector3{g_header.oct0[0], g_header.oct0[1], g_header.oct0[2]};
        cam.up = Vector3{0.0f, 1.0f, 0.0f};
        cam.fovy = 45.0f;
        cam.projection = CAMERA_PERSPECTIVE;

        BeginScissorMode(static_cast<int>(dstX), static_cast<int>(dstY),
                         static_cast<int>(dstW), static_cast<int>(dstH));
        BeginMode3D(cam);
        DrawModel(g_realmModel, Vector3{0.0f, 0.0f, 0.0f}, 1.0f, WHITE);
        EndMode3D();
        EndScissorMode();
    }

    inline void shutdownRealmAndModelsOverlay(PS2Runtime &runtime, float a, float b, float c, float d, void *userData)
    {
        ps2_game_overrides::primal_model_override::shutdownHostModelOverlay(runtime, a, b, c, d, userData);
        std::lock_guard<std::mutex> lock(g_realmMutex);
        if (g_realmModelReady)
        {
            UnloadModel(g_realmModel);
            g_realmModelReady = false;
        }
    }

    inline void applyPrimalExpansionRealm(PS2Runtime &runtime)
    {
        static bool s_installed = false;
        if (s_installed)
            return;
        const char *e = std::getenv("PS2_DISABLE_STAGE_D_REALM");
        if (e != nullptr && e[0] == '1')
            return;
        s_installed = true;

        loadRealmPackage();
        auto cur2f4b30 = runtime.lookupFunction(0x002F4B30u);
        if (cur2f4b30 && cur2f4b30 != &wrap2f4b30)
        {
            g_orig2f4b30 = cur2f4b30;
            runtime.replaceFunction(0x002F4B30u, &wrap2f4b30);
        }
        runtime.setHostOverlayCallbacks(&drawRealmAndModelsOverlay, &shutdownRealmAndModelsOverlay, nullptr);
        RUNTIME_LOG("[game_overrides] Stage D REALM_EXPANSION_01 hook installed (2f4b30="
                    << (g_orig2f4b30 ? "YES" : "NO") << ")");
    }

    inline const ps2_game_overrides::Descriptor kPrimalExpansionRealmDescriptor{
        "Primal Stage D REALM_EXPANSION_01 loader",
        "SCUS_971.42",
        0x00100008u,
        0xAB6FB13Cu,
        &applyPrimalExpansionRealm
    };

    inline const ps2_game_overrides::AutoRegister kPrimalExpansionRealmRegistrar{
        kPrimalExpansionRealmDescriptor
    };
}

#endif // PS2_GAME_OVERRIDES_H
