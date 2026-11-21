#pragma once

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

namespace primal::harness
{
    struct ScriptEvent
    {
        uint64_t startFrame = 0;
        uint64_t endFrame = 0;
        uint16_t buttonsMask = 0xFFFFu; // Active-low: low byte -> p[2], high byte -> p[3]
        uint8_t lx = 128u;
        uint8_t ly = 128u;
        uint8_t rx = 128u;
        uint8_t ry = 128u;
        bool hasAnalog = false;
        bool screenshot = false;
        std::string screenshotName;
        bool refGs = false;
    };

    struct HarnessConfig
    {
        bool headless = false;
        bool refGs = false;
        bool enabled = false;
        std::string inputScriptPath;
        std::string shotsDir = "logs/shots";
        std::string exploreLogPath = "logs/explore.log";
        uint32_t shotInterval = 0;
        uint64_t maxFrames = 0;
    };

    class State
    {
    public:
        static State &instance()
        {
            static State s;
            return s;
        }

        HarnessConfig &config() { return m_config; }
        const HarnessConfig &config() const { return m_config; }

        void initFromEnv()
        {
            if (const char *h = std::getenv("PRIMAL_HEADLESS"))
            {
                if (h[0] == '1')
                {
                    m_config.headless = true;
                    m_config.enabled = true;
                }
            }
            if (const char *r = std::getenv("PRIMAL_REF_GS"))
            {
                if (r[0] == '1')
                {
                    m_config.refGs = true;
                    m_config.enabled = true;
                }
            }
            if (const char *sd = std::getenv("PRIMAL_SHOTS_DIR"))
            {
                if (sd[0] != '\0')
                {
                    m_config.shotsDir = sd;
                }
            }
            if (const char *el = std::getenv("PRIMAL_EXPLORE_LOG"))
            {
                if (el[0] != '\0')
                {
                    m_config.exploreLogPath = el;
                }
            }
            if (const char *si = std::getenv("PRIMAL_SHOT_INTERVAL"))
            {
                if (si[0] != '\0')
                {
                    m_config.shotInterval = static_cast<uint32_t>(std::strtoul(si, nullptr, 10));
                    m_config.enabled = true;
                }
            }
            if (const char *mf = std::getenv("PRIMAL_MAX_FRAMES"))
            {
                if (mf[0] != '\0')
                {
                    m_config.maxFrames = static_cast<uint64_t>(std::strtoull(mf, nullptr, 10));
                    m_config.enabled = true;
                }
            }
            if (const char *is = std::getenv("PRIMAL_INPUT_SCRIPT"))
            {
                if (is[0] != '\0')
                {
                    loadInputScript(is);
                }
            }
        }

        bool loadInputScript(const std::string &path)
        {
            m_config.inputScriptPath = path;
            m_config.enabled = true;

            std::ifstream f(path);
            if (!f.is_open())
            {
                std::cerr << "[harness] Failed to open input script: " << path << std::endl;
                return false;
            }
            std::ostringstream ss;
            ss << f.rdbuf();
            const std::string text = ss.str();

            m_events.clear();
            parseTopLevelUint(text, "max_frames", m_config.maxFrames);
            uint64_t interval = 0;
            if (parseTopLevelUint(text, "shot_interval", interval))
            {
                m_config.shotInterval = static_cast<uint32_t>(interval);
            }

            // Parse "events" or "frames" array of objects
            size_t arrPos = text.find("\"events\"");
            if (arrPos == std::string::npos)
            {
                arrPos = text.find("\"frames\"");
            }
            if (arrPos != std::string::npos)
            {
                size_t lb = text.find('[', arrPos);
                if (lb != std::string::npos)
                {
                    size_t i = lb + 1;
                    while (i < text.size())
                    {
                        while (i < text.size() && std::isspace(static_cast<unsigned char>(text[i]))) ++i;
                        if (i >= text.size() || text[i] == ']') break;
                        if (text[i] == '{')
                        {
                            size_t objEnd = findMatchingBrace(text, i);
                            if (objEnd == std::string::npos) break;
                            std::string obj = text.substr(i, objEnd - i + 1);
                            m_events.push_back(parseEventObject(obj));
                            i = objEnd + 1;
                        }
                        else
                        {
                            ++i;
                        }
                    }
                }
            }

            std::cout << "[harness] Loaded input script: " << path
                      << " events=" << m_events.size()
                      << " maxFrames=" << m_config.maxFrames
                      << " shotInterval=" << m_config.shotInterval
                      << std::endl;
            return true;
        }

        bool hasScript() const { return !m_events.empty() || !m_config.inputScriptPath.empty(); }

        void applyScriptedPad(uint64_t frame, uint8_t *padBuf)
        {
            if (padBuf == nullptr || m_events.empty())
            {
                return;
            }
            uint16_t mask = 0xFFFFu;
            uint8_t lx = 128u, ly = 128u, rx = 128u, ry = 128u;
            bool hasAnalog = false;

            for (const auto &ev : m_events)
            {
                if (frame >= ev.startFrame && frame < ev.endFrame)
                {
                    mask &= ev.buttonsMask;
                    if (ev.hasAnalog)
                    {
                        lx = ev.lx;
                        ly = ev.ly;
                        rx = ev.rx;
                        ry = ev.ry;
                        hasAnalog = true;
                    }
                    if (ev.screenshot && m_lastShotEventFrame != frame)
                    {
                        m_lastShotEventFrame = frame;
                        requestScreenshot(ev.screenshotName, ev.refGs);
                    }
                }
            }

            padBuf[2] = static_cast<uint8_t>(mask & 0xFFu);
            padBuf[3] = static_cast<uint8_t>((mask >> 8) & 0xFFu);
            if (hasAnalog && (padBuf[1] == 0x73u || padBuf[1] == 0x79u))
            {
                padBuf[4] = rx;
                padBuf[5] = ry;
                padBuf[6] = lx;
                padBuf[7] = ly;
            }
        }

        void requestScreenshot(const std::string &name = "", bool refGs = false)
        {
            std::lock_guard<std::mutex> lock(m_shotMutex);
            m_pendingShot = true;
            m_pendingShotName = name;
            m_pendingShotRefGs = refGs;
        }

        bool consumeScreenshotRequest(std::string &outName, bool &outRefGs)
        {
            std::lock_guard<std::mutex> lock(m_shotMutex);
            if (!m_pendingShot)
            {
                return false;
            }
            m_pendingShot = false;
            outName = std::move(m_pendingShotName);
            m_pendingShotName.clear();
            outRefGs = m_pendingShotRefGs;
            m_pendingShotRefGs = false;
            return true;
        }

        void ensureExploreLogOpen()
        {
            if (m_logOpenTried) return;
            m_logOpenTried = true;
            if (m_config.exploreLogPath.empty()) return;
            std::error_code ec;
            const auto parent = std::filesystem::path(m_config.exploreLogPath).parent_path();
            if (!parent.empty())
            {
                std::filesystem::create_directories(parent, ec);
            }
            m_exploreLog.open(m_config.exploreLogPath, std::ios::out | std::ios::trunc);
            if (m_exploreLog.is_open())
            {
                m_exploreLog << "# Primal Test Harness Explore Log\n";
                m_exploreLog.flush();
            }
        }

        void logDiscoveredPc(uint64_t frame, uint32_t pc)
        {
            if (!m_config.enabled || pc < 0x00100000u || pc >= 0x00500000u) return;
            const uint32_t wordIdx = (pc - 0x00100000u) >> 2;
            const uint32_t byteIdx = wordIdx >> 3;
            const uint8_t bitMask = static_cast<uint8_t>(1u << (wordIdx & 7u));
            if (m_seenPcBits.empty())
            {
                std::lock_guard<std::mutex> lock(m_logMutex);
                if (m_seenPcBits.empty()) m_seenPcBits.assign(0x20000u, 0u);
            }
            if ((m_seenPcBits[byteIdx] & bitMask) != 0u) return;
            std::lock_guard<std::mutex> lock(m_logMutex);
            if ((m_seenPcBits[byteIdx] & bitMask) != 0u) return;
            m_seenPcBits[byteIdx] |= bitMask;
            ++m_discoveredCount;
            ensureExploreLogOpen();
            if (m_exploreLog.is_open())
            {
                m_exploreLog << "[func] frame=" << frame
                             << " pc=0x" << std::hex << pc << std::dec
                             << " total_discovered=" << m_discoveredCount << "\n";
            }
        }

        void logFrame(uint64_t frame,
                      uint64_t tick,
                      double frameMs,
                      double uploadMs,
                      double drawMs,
                      uint32_t nonzeroPx,
                      uint64_t totalPx,
                      double avgLuma,
                      uint32_t pc)
        {
            if (!m_config.enabled) return;
            std::lock_guard<std::mutex> lock(m_logMutex);
            ensureExploreLogOpen();
            if (pc >= 0x00100000u && pc < 0x00500000u && m_seenPcs.insert(pc).second)
            {
                if (m_exploreLog.is_open())
                {
                    m_exploreLog << "[func] frame=" << frame
                                 << " pc=0x" << std::hex << pc << std::dec
                                 << " total_discovered=" << m_seenPcs.size() << "\n";
                }
            }
            if (m_exploreLog.is_open())
            {
                m_exploreLog << "[frame] frame=" << frame
                             << " tick=" << tick
                             << " frame_ms=" << std::fixed << std::setprecision(2) << frameMs
                             << " upload_ms=" << uploadMs
                             << " draw_ms=" << drawMs
                             << " nonzero=" << nonzeroPx << "/" << totalPx
                             << " avg_luma=" << std::setprecision(2) << avgLuma
                             << " pc=0x" << std::hex << pc << std::dec << "\n";
                if ((frame % 30u) == 0u)
                {
                    m_exploreLog.flush();
                }
            }
        }

        void logShotSaved(uint64_t frame, const std::string &path, bool refGs, uint32_t nonzeroPx, uint64_t totalPx)
        {
            std::lock_guard<std::mutex> lock(m_logMutex);
            ensureExploreLogOpen();
            if (m_exploreLog.is_open())
            {
                m_exploreLog << "[shot] frame=" << frame
                             << (refGs ? " mode=ref-gs" : " mode=normal")
                             << " nonzero=" << nonzeroPx << "/" << totalPx
                             << " path=" << path << "\n";
                m_exploreLog.flush();
            }
        }

    private:
        State() = default;

        static size_t findMatchingBrace(const std::string &s, size_t openPos)
        {
            int depth = 0;
            bool inStr = false;
            for (size_t i = openPos; i < s.size(); ++i)
            {
                char c = s[i];
                if (c == '"' && (i == 0 || s[i - 1] != '\\')) inStr = !inStr;
                if (inStr) continue;
                if (c == '{') ++depth;
                else if (c == '}')
                {
                    --depth;
                    if (depth == 0) return i;
                }
            }
            return std::string::npos;
        }

        static bool parseTopLevelUint(const std::string &s, const char *key, uint64_t &out)
        {
            std::string pat = std::string("\"") + key + "\"";
            size_t pos = s.find(pat);
            if (pos == std::string::npos) return false;
            size_t colon = s.find(':', pos + pat.size());
            if (colon == std::string::npos) return false;
            size_t valPos = colon + 1;
            while (valPos < s.size() && std::isspace(static_cast<unsigned char>(s[valPos]))) ++valPos;
            if (valPos >= s.size() || !std::isdigit(static_cast<unsigned char>(s[valPos]))) return false;
            out = static_cast<uint64_t>(std::strtoull(s.c_str() + valPos, nullptr, 10));
            return true;
        }

        static bool parseBool(const std::string &s, const char *key, bool &out)
        {
            std::string pat = std::string("\"") + key + "\"";
            size_t pos = s.find(pat);
            if (pos == std::string::npos) return false;
            size_t colon = s.find(':', pos + pat.size());
            if (colon == std::string::npos) return false;
            size_t valPos = colon + 1;
            while (valPos < s.size() && std::isspace(static_cast<unsigned char>(s[valPos]))) ++valPos;
            if (s.compare(valPos, 4, "true") == 0) { out = true; return true; }
            if (s.compare(valPos, 5, "false") == 0) { out = false; return true; }
            return false;
        }

        static bool parseString(const std::string &s, const char *key, std::string &out)
        {
            std::string pat = std::string("\"") + key + "\"";
            size_t pos = s.find(pat);
            if (pos == std::string::npos) return false;
            size_t colon = s.find(':', pos + pat.size());
            if (colon == std::string::npos) return false;
            size_t q1 = s.find('"', colon + 1);
            if (q1 == std::string::npos) return false;
            size_t q2 = s.find('"', q1 + 1);
            if (q2 == std::string::npos) return false;
            out = s.substr(q1 + 1, q2 - q1 - 1);
            return true;
        }

        static uint16_t buttonBitFromName(std::string name)
        {
            for (char &c : name) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            if (name == "SELECT")   return 0x0001u;
            if (name == "L3")       return 0x0002u;
            if (name == "R3")       return 0x0004u;
            if (name == "START")    return 0x0008u;
            if (name == "UP")       return 0x0010u;
            if (name == "RIGHT")    return 0x0020u;
            if (name == "DOWN")     return 0x0040u;
            if (name == "LEFT")     return 0x0080u;
            if (name == "L2")       return 0x0100u;
            if (name == "R2")       return 0x0200u;
            if (name == "L1")       return 0x0400u;
            if (name == "R1")       return 0x0800u;
            if (name == "TRIANGLE") return 0x1000u;
            if (name == "CIRCLE")   return 0x2000u;
            if (name == "CROSS" || name == "X") return 0x4000u;
            if (name == "SQUARE")   return 0x8000u;
            return 0u;
        }

        static ScriptEvent parseEventObject(const std::string &obj)
        {
            ScriptEvent ev;
            uint64_t frame = 0, startF = 0, endF = 0, dur = 1;
            if (parseTopLevelUint(obj, "start_frame", startF))
            {
                ev.startFrame = startF;
                if (parseTopLevelUint(obj, "end_frame", endF))
                    ev.endFrame = endF;
                else if (parseTopLevelUint(obj, "duration", dur))
                    ev.endFrame = startF + dur;
                else
                    ev.endFrame = startF + 1;
            }
            else if (parseTopLevelUint(obj, "frame", frame))
            {
                ev.startFrame = frame;
                if (parseTopLevelUint(obj, "duration", dur))
                    ev.endFrame = frame + dur;
                else
                    ev.endFrame = frame + 1;
            }

            uint64_t axis = 128;
            if (parseTopLevelUint(obj, "lx", axis)) { ev.lx = static_cast<uint8_t>(std::min<uint64_t>(255, axis)); ev.hasAnalog = true; }
            if (parseTopLevelUint(obj, "ly", axis)) { ev.ly = static_cast<uint8_t>(std::min<uint64_t>(255, axis)); ev.hasAnalog = true; }
            if (parseTopLevelUint(obj, "rx", axis)) { ev.rx = static_cast<uint8_t>(std::min<uint64_t>(255, axis)); ev.hasAnalog = true; }
            if (parseTopLevelUint(obj, "ry", axis)) { ev.ry = static_cast<uint8_t>(std::min<uint64_t>(255, axis)); ev.hasAnalog = true; }

            parseBool(obj, "screenshot", ev.screenshot);
            std::string shotName;
            if (parseString(obj, "screenshot", shotName) && !shotName.empty())
            {
                ev.screenshot = true;
                ev.screenshotName = shotName;
            }
            parseBool(obj, "ref_gs", ev.refGs);

            size_t bPos = obj.find("\"buttons\"");
            if (bPos != std::string::npos)
            {
                size_t lb = obj.find('[', bPos);
                size_t rb = (lb != std::string::npos) ? obj.find(']', lb) : std::string::npos;
                if (lb != std::string::npos && rb != std::string::npos)
                {
                    size_t i = lb + 1;
                    while (i < rb)
                    {
                        size_t q1 = obj.find('"', i);
                        if (q1 == std::string::npos || q1 >= rb) break;
                        size_t q2 = obj.find('"', q1 + 1);
                        if (q2 == std::string::npos || q2 >= rb) break;
                        std::string bname = obj.substr(q1 + 1, q2 - q1 - 1);
                        ev.buttonsMask &= static_cast<uint16_t>(~buttonBitFromName(bname));
                        i = q2 + 1;
                    }
                }
            }
            return ev;
        }

        HarnessConfig m_config;
        std::vector<ScriptEvent> m_events;
        uint64_t m_lastShotEventFrame = UINT64_MAX;
        std::mutex m_shotMutex;
        bool m_pendingShot = false;
        std::string m_pendingShotName;
        bool m_pendingShotRefGs = false;

        std::mutex m_logMutex;
        std::ofstream m_exploreLog;
        bool m_logOpenTried = false;
        std::unordered_set<uint32_t> m_seenPcs;
        std::vector<uint8_t> m_seenPcBits;
        uint64_t m_discoveredCount = 0;
    };

    inline HarnessConfig &config() { return State::instance().config(); }
    inline void initFromEnv() { State::instance().initFromEnv(); }
    inline bool loadInputScript(const std::string &path) { return State::instance().loadInputScript(path); }
    inline bool hasScript() { return State::instance().hasScript(); }
    inline void applyScriptedPad(uint64_t frame, uint8_t *padBuf) { State::instance().applyScriptedPad(frame, padBuf); }
    inline bool consumeScreenshotRequest(std::string &outName, bool &outRefGs) { return State::instance().consumeScreenshotRequest(outName, outRefGs); }
    inline void logDiscoveredPc(uint64_t frame, uint32_t pc) { State::instance().logDiscoveredPc(frame, pc); }
    inline void logFrame(uint64_t frame, uint64_t tick, double frameMs, double uploadMs, double drawMs, uint32_t nonzeroPx, uint64_t totalPx, double avgLuma, uint32_t pc)
    {
        State::instance().logFrame(frame, tick, frameMs, uploadMs, drawMs, nonzeroPx, totalPx, avgLuma, pc);
    }
    inline void logShotSaved(uint64_t frame, const std::string &path, bool refGs, uint32_t nonzeroPx, uint64_t totalPx)
    {
        State::instance().logShotSaved(frame, path, refGs, nonzeroPx, totalPx);
    }
} // namespace primal::harness
