#include "../iop_service.h"
#include "../rpc_reply.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace ps2x::iop::detail
{
    namespace
    {
        // Service ids used by the classic fileio IRX module.
        constexpr uint32_t kFileioSid = 0x80000003u;
        constexpr uint32_t kFileioExtendedSid = 0x80000001u;

        // Function numbers of the fileio protocol (see fileio-common.h).
        constexpr uint32_t kFioOpen = 0u;
        constexpr uint32_t kFioClose = 1u;
        constexpr uint32_t kFioRead = 2u;
        constexpr uint32_t kFioWrite = 3u;
        constexpr uint32_t kFioLseek = 4u;
        constexpr uint32_t kFioIoctl = 5u;

        constexpr uint32_t kFioPathMax = 256u;

        struct OpenFile
        {
            uint64_t handle = 0u;
            uint64_t position = 0u;
            uint64_t size = 0u;
        };

        class FileioService final : public IopService
        {
        public:
            explicit FileioService(IopHost &host)
                : m_host(host)
            {
            }

            [[nodiscard]] std::string_view name() const override
            {
                return "fileio";
            }

            [[nodiscard]] std::span<const uint32_t> sids() const override
            {
                return m_sids;
            }

            void reset() override
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                for (auto &entry : m_files)
                {
                    m_host.closeHostFile(entry.second.handle);
                }
                m_files.clear();
                m_nextFd = 1u;
            }

            [[nodiscard]] RpcResult handleRpc(const RpcRequest &request) override
            {
                RpcResult result{};
                result.handled = true;
                result.resultAddress = request.receive.address;

                switch (request.function)
                {
                case kFioOpen:
                    return handleOpen(request, result);
                case kFioClose:
                    return handleClose(request, result);
                case kFioRead:
                    return handleRead(request, result);
                case kFioLseek:
                    return handleLseek(request, result);
                case kFioWrite:
                case kFioIoctl:
                default:
                    writeInt(request.receive, -1);
                    logInfo(request, "unsupported function");
                    return result;
                }
            }

        private:
            void writeInt(GuestBuffer receive, int32_t value)
            {
                const std::array<uint32_t, 1> words{static_cast<uint32_t>(value)};
                (void)writeRpcWords(m_host, receive, words);
            }

            [[nodiscard]] RpcResult handleOpen(const RpcRequest &request, RpcResult result)
            {
                int32_t mode = 0;
                std::array<char, kFioPathMax + 1u> name{};
                if (request.send.address != 0u)
                {
                    (void)m_host.readGuest(request.send.address, &mode, sizeof(mode));
                    (void)m_host.readGuest(request.send.address + sizeof(mode),
                                           name.data(),
                                           kFioPathMax);
                }
                name[kFioPathMax] = '\0';

                const std::string path = m_host.translateGuestPath(std::string_view(name.data()));
                const uint64_t handle = m_host.openHostFile(path);
                if (handle == 0u)
                {
                    writeInt(request.receive, -1);
                    logInfo(request, std::string("open failed ") + name.data());
                    return result;
                }

                OpenFile file{};
                file.handle = handle;
                (void)m_host.hostFileSize(handle, file.size);

                int32_t fd = -1;
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    fd = static_cast<int32_t>(m_nextFd++);
                    m_files.emplace(static_cast<uint32_t>(fd), file);
                }

                writeInt(request.receive, fd);
                logInfo(request, std::string("open ") + name.data() + " mode=0x" + std::to_string(mode) +
                                     " fd=" + std::to_string(fd));
                return result;
            }

            [[nodiscard]] RpcResult handleClose(const RpcRequest &request, RpcResult result)
            {
                int32_t fd = -1;
                if (request.send.address != 0u)
                {
                    (void)m_host.readGuest(request.send.address, &fd, sizeof(fd));
                }

                bool closed = false;
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    const auto it = m_files.find(static_cast<uint32_t>(fd));
                    if (it != m_files.end())
                    {
                        m_host.closeHostFile(it->second.handle);
                        m_files.erase(it);
                        closed = true;
                    }
                }

                writeInt(request.receive, closed ? 0 : -1);
                logInfo(request, "close fd=" + std::to_string(fd));
                return result;
            }

            [[nodiscard]] RpcResult handleRead(const RpcRequest &request, RpcResult result)
            {
                // struct _fio_read_arg { int fd; void *ptr; int size; ... }
                int32_t fd = -1;
                uint32_t destination = 0u;
                int32_t size = 0;
                if (request.send.address != 0u)
                {
                    (void)m_host.readGuest(request.send.address, &fd, sizeof(fd));
                    (void)m_host.readGuest(request.send.address + 4u, &destination, sizeof(destination));
                    (void)m_host.readGuest(request.send.address + 8u, &size, sizeof(size));
                }

                if (size < 0)
                {
                    size = 0;
                }

                std::vector<uint8_t> buffer(static_cast<size_t>(size), 0u);
                size_t bytesRead = 0u;
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    const auto it = m_files.find(static_cast<uint32_t>(fd));
                    if (it == m_files.end())
                    {
                        writeInt(request.receive, -1);
                        logInfo(request, "read on unknown fd=" + std::to_string(fd));
                        return result;
                    }

                    OpenFile &file = it->second;
                    if (!m_host.readHostFile(file.handle,
                                             file.position,
                                             buffer.data(),
                                             buffer.size(),
                                             bytesRead))
                    {
                        bytesRead = 0u;
                    }
                    file.position += bytesRead;
                }

                if (bytesRead != 0u && destination != 0u)
                {
                    (void)m_host.writeGuest(destination, buffer.data(), bytesRead);
                }

                writeInt(request.receive, static_cast<int32_t>(bytesRead));
                logInfo(request, "read fd=" + std::to_string(fd) + " size=" + std::to_string(size) +
                                     " bytes=" + std::to_string(bytesRead));
                return result;
            }

            [[nodiscard]] RpcResult handleLseek(const RpcRequest &request, RpcResult result)
            {
                // struct _fio_lseek_arg { int fd; int offset; int whence; }
                int32_t fd = -1;
                int32_t offset = 0;
                int32_t whence = 0;
                if (request.send.address != 0u)
                {
                    (void)m_host.readGuest(request.send.address, &fd, sizeof(fd));
                    (void)m_host.readGuest(request.send.address + 4u, &offset, sizeof(offset));
                    (void)m_host.readGuest(request.send.address + 8u, &whence, sizeof(whence));
                }

                int64_t position = -1;
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    const auto it = m_files.find(static_cast<uint32_t>(fd));
                    if (it != m_files.end())
                    {
                        OpenFile &file = it->second;
                        int64_t base = 0;
                        if (whence == 1)
                        {
                            base = static_cast<int64_t>(file.position);
                        }
                        else if (whence == 2)
                        {
                            base = static_cast<int64_t>(file.size);
                        }
                        position = base + offset;
                        if (position < 0)
                        {
                            position = 0;
                        }
                        file.position = static_cast<uint64_t>(position);
                    }
                }

                writeInt(request.receive, static_cast<int32_t>(position));
                logInfo(request, "lseek fd=" + std::to_string(fd) + " offset=" + std::to_string(offset) +
                                     " whence=" + std::to_string(whence) + " result=" +
                                     std::to_string(position));
                return result;
            }

            void logInfo(const RpcRequest &request, const std::string &message)
            {
                std::ostringstream out;
                out << "FILEIO " << message << " sid=0x" << std::hex << request.sid
                    << " function=0x" << request.function
                    << " send=0x" << request.send.address
                    << " size=0x" << request.send.size;
                m_host.log(LogLevel::Info, out.str());
            }

            IopHost &m_host;
            mutable std::mutex m_mutex;
            std::map<uint32_t, OpenFile> m_files;
            uint32_t m_nextFd = 1u;
            const std::array<uint32_t, 2> m_sids{kFileioSid, kFileioExtendedSid};
        };
    }

    std::unique_ptr<IopService> createFileioService(IopHost &host)
    {
        return std::make_unique<FileioService>(host);
    }
}
