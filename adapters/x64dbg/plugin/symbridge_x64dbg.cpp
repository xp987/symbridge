// symbridge x64dbg adapter.
//
// Mirrors the Python IDA adapter: connects to the symbridge broker, applies
// remote name/comment/type updates to x64dbg, and pushes local annotations back. x64dbg
// emits no reliable label/comment-change event, so local->broker is done with
// a background poll+diff thread (~750ms). Echo is prevented by recording every
// value we *apply* into the same "last seen" maps the poll diffs against, so an
// applied remote change is never re-broadcast.
//
// Address model: on the wire we carry only (module, rva). x64dbg's LabelInfo /
// CommentInfo already give us mod+rva directly; to apply we resolve
// addr = Script::Module::BaseFromName(mod) + rva.
//
// Build: see CMakeLists.txt (links x64dbg.lib, x64bridge.lib, jansson, ws2_32).

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>

#include "pluginmain.h"
#include "type_sync.h"

#include <atomic>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

static std::string toLower(std::string s)
{
    for (auto& c : s)
        c = (char)tolower((unsigned char)c);
    return s;
}

static std::string wideToUtf8(const std::wstring& value)
{
    if (value.empty())
        return {};
    int length = WideCharToMultiByte(CP_UTF8, 0, value.data(), (int)value.size(),
                                     nullptr, 0, nullptr, nullptr);
    if (length <= 0)
        return {};
    std::string result((size_t)length, '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, value.data(), (int)value.size(),
                            result.data(), length, nullptr, nullptr) != length)
        return {};
    return result;
}

// Unix epoch seconds, matching Python's time.time() so last-write-wins agrees.
static double nowSeconds()
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    const double EPOCH_DIFF = 11644473600.0; // 1601 -> 1970
    return (double)u.QuadPart / 1e7 - EPOCH_DIFF;
}

// ---------------------------------------------------------------------------
// broker client (Winsock + jansson, newline-delimited JSON)
// ---------------------------------------------------------------------------

class BrokerClient
{
public:
    using MsgHandler = void (*)(json_t* root);

    bool connect(const std::string& host, int port, const std::string& clientId,
                 const std::string& tool, MsgHandler onMsg)
    {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
            return false;

        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        addrinfo* res = nullptr;
        std::string portStr = std::to_string(port);
        if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0 || !res)
        {
            WSACleanup();
            return false;
        }
        sock_ = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sock_ == INVALID_SOCKET || ::connect(sock_, res->ai_addr, (int)res->ai_addrlen) != 0)
        {
            freeaddrinfo(res);
            close();
            return false;
        }
        freeaddrinfo(res);

        clientId_ = clientId;
        tool_ = tool;
        onMsg_ = onMsg;
        running_ = true;

        // hello
        json_t* hello = json_object();
        json_object_set_new(hello, "type", json_string("hello"));
        json_object_set_new(hello, "client_id", json_string(clientId_.c_str()));
        json_object_set_new(hello, "tool", json_string(tool_.c_str()));
        sendRaw(hello);
        json_decref(hello);

        reader_ = std::thread(&BrokerClient::readLoop, this);
        return true;
    }

    void close()
    {
        running_ = false;
        if (sock_ != INVALID_SOCKET)
        {
            shutdown(sock_, SD_BOTH);
            closesocket(sock_);
            sock_ = INVALID_SOCKET;
        }
        if (reader_.joinable())
            reader_.join();
        WSACleanup();
    }

    bool connected() const { return running_ && sock_ != INVALID_SOCKET; }

    void sendUpdate(const char* record, json_t* data, const std::string& origin)
    {
        json_t* msg = json_object();
        json_object_set_new(msg, "type", json_string("update"));
        json_object_set_new(msg, "origin", json_string(origin.c_str()));
        json_object_set_new(msg, "record", json_string(record));
        json_object_set_new(msg, "data", data); // steals data's ref
        sendRaw(msg);
        json_decref(msg);
    }

    void sendRaw(json_t* msg)
    {
        char* s = json_dumps(msg, JSON_COMPACT);
        if (!s)
            return;
        std::string line(s);
        free(s);
        line.push_back('\n');
        std::lock_guard<std::mutex> lk(sendMutex_);
        if (sock_ == INVALID_SOCKET)
            return;
        send(sock_, line.data(), (int)line.size(), 0);
    }

private:
    void readLoop()
    {
        std::string buf;
        char chunk[4096];
        while (running_)
        {
            int n = recv(sock_, chunk, sizeof(chunk), 0);
            if (n <= 0)
                break;
            buf.append(chunk, n);
            size_t pos;
            while ((pos = buf.find('\n')) != std::string::npos)
            {
                std::string line = buf.substr(0, pos);
                buf.erase(0, pos + 1);
                if (line.empty())
                    continue;
                json_error_t err;
                json_t* root = json_loads(line.c_str(), 0, &err);
                if (!root)
                    continue;
                if (onMsg_)
                    onMsg_(root);
                json_decref(root);
            }
        }
        running_ = false;
    }

    SOCKET sock_ = INVALID_SOCKET;
    std::thread reader_;
    std::atomic<bool> running_{false};
    std::mutex sendMutex_;
    std::string clientId_, tool_;
    MsgHandler onMsg_ = nullptr;
};

// ---------------------------------------------------------------------------
// adapter (single global instance)
// ---------------------------------------------------------------------------

class Adapter
{
public:
    void start()
    {
        const char* host = getenv("SYMBRIDGE_HOST");
        const char* portEnv = getenv("SYMBRIDGE_PORT");
        std::string h = host ? host : "127.0.0.1";
        int p = portEnv ? atoi(portEnv) : 9100;
        origin_ = "x64dbg:" + std::to_string(GetCurrentProcessId());
        refreshModule();

        if (!client_.connect(h, p, origin_, "x64dbg", &Adapter::onMessageStatic))
        {
            _plugin_logprintf("[symbridge] could not connect to broker %s:%d\n", h.c_str(), p);
            return;
        }
        _plugin_logprintf("[symbridge] connected as %s to %s:%d\n", origin_.c_str(), h.c_str(), p);
        runningPoll_ = true;
        poll_ = std::thread(&Adapter::pollLoop, this);
    }

    void stop()
    {
        runningPoll_ = false;
        if (poll_.joinable())
            poll_.join();
        client_.close();
        _plugin_logprintf("[symbridge] disconnected\n");
    }

    bool connected() const { return client_.connected(); }

    // Push every current label/comment regardless of diff (menu action).
    void pushAll()
    {
        if (!DbgIsDebugging())
        {
            _plugin_logprintf("[symbridge] push: not debugging\n");
            return;
        }
        refreshModule();
        scanLabels(true);
        scanComments(true);
        syncLocalTypeFile(true);
        _plugin_logprintf("[symbridge] pushed all labels/comments/types\n");
    }

    bool watchTypeFile(const std::string& path)
    {
        if(!DbgIsDebugging())
        {
            _plugin_logprintf("[symbridge] watch types: not debugging\n");
            return false;
        }
        refreshModule();
        std::filesystem::path candidate = std::filesystem::u8path(path);
        std::error_code ec;
        if(!std::filesystem::is_regular_file(candidate, ec))
        {
            _plugin_logprintf("[symbridge] type header not found: %s\n", path.c_str());
            return false;
        }
        std::string module = currentModule();
        {
            std::lock_guard<std::mutex> lk(localTypeMutex_);
            if(watchedModule_ != module)
                localOwnedTypes_.clear();
            localTypePath_ = std::move(candidate);
            watchedModule_ = module;
            localTypeWriteTime_ = {};
        }
        _plugin_logprintf("[symbridge] watching type header for %s: %s\n",
                          module.c_str(), path.c_str());
        return syncLocalTypeFile(true);
    }

    bool syncTypes()
    {
        return syncLocalTypeFile(true);
    }

    // Called on CB_CREATEPROCESS: the main module is now loaded, so pick up its
    // name and apply anything that arrived before it existed.
    void onDebugStart()
    {
        refreshModule();
        flushPending();
        // Types are not address-based, but they are module-scoped on the wire.
        // Re-import the aggregate belonging to the newly loaded main module.
        reloadCurrentTypes();
    }

    // -- inbound (reader thread) --------------------------------------------

    static void onMessageStatic(json_t* root); // defined after g_adapter

    void onMessage(json_t* root)
    {
        const char* type = json_string_value(json_object_get(root, "type"));
        if (!type)
            return;
        if (strcmp(type, "snapshot") == 0)
        {
            json_t* records = json_object_get(root, "records");
            size_t n = json_array_size(records);
            for (size_t i = 0; i < n; i++)
            {
                json_t* wire = json_array_get(records, i);
                const char* record = json_string_value(json_object_get(wire, "record"));
                if (!record || strcmp(record, "type") != 0)
                    applyWire(wire, true);
            }
            // A snapshot is authoritative, including the empty case. Rebuild
            // the type cache atomically so reconnecting cannot retain types
            // that disappeared from a restarted/replaced broker state.
            replaceTypesFromSnapshot(records);
            reloadCurrentTypes();
            // The broker snapshot can predate edits in the x64dbg-owned local
            // header. Re-overlay and publish that file after every snapshot.
            syncLocalTypeFile(true);
        }
        else if (strcmp(type, "update") == 0)
        {
            applyWire(root, false);
        }
    }

private:
    void flushPending()
    {
        std::vector<Pending> items;
        {
            std::lock_guard<std::mutex> lk(pendingMutex_);
            items.swap(pending_);
        }
        for (auto& p : items)
        {
            if (p.kind == PEND_LABEL)
                applyLabel(p.module, p.rva, p.text);
            else
                applyComment(p.module, p.rva, p.text);
        }
    }

    // Returns true when the wire item was a valid type record. deferTypeReload
    // lets snapshot handling collect all declarations before invoking ParseTypes.
    bool applyWire(json_t* wire, bool deferTypeReload)
    {
        const char* record = json_string_value(json_object_get(wire, "record"));
        json_t* data = json_object_get(wire, "data");
        if (!record || !data)
            return false;
        const char* mod = json_string_value(json_object_get(data, "module"));
        if (!mod)
            return false;
        std::string module = toLower(mod);

        if (strcmp(record, "type") == 0)
        {
            const char* name = json_string_value(json_object_get(data, "name"));
            const char* decl = json_string_value(json_object_get(data, "decl"));
            bool deleted = json_is_true(json_object_get(data, "deleted"));
            if (!name || !*name || (!deleted && (!decl || !*decl)))
                return false;
            bool changed = deleted
                ? eraseType(module, name)
                : storeType(module, name, decl);
            if (changed && !deferTypeReload && module == currentModule())
                reloadCurrentTypes();
            return true;
        }

        duint rva = (duint)json_integer_value(json_object_get(data, "rva"));

        if (strcmp(record, "symbol") == 0)
        {
            const char* name = json_string_value(json_object_get(data, "name"));
            if (name)
                applyLabel(module, rva, name);
        }
        else if (strcmp(record, "comment") == 0)
        {
            const char* text = json_string_value(json_object_get(data, "text"));
            if (text)
                applyComment(module, rva, text);
        }
        return false;
    }

    bool storeType(const std::string& module, const std::string& name,
                   const std::string& decl)
    {
        std::lock_guard<std::mutex> lk(typeMutex_);
        auto& moduleTypes = typeDecls_[module];
        auto it = moduleTypes.find(name);
        if (it != moduleTypes.end() && it->second == decl)
            return false;
        moduleTypes[name] = decl;
        return true;
    }

    void replaceTypesFromSnapshot(json_t* records)
    {
        std::map<std::string, std::map<std::string, std::string>> replacement;
        size_t n = json_array_size(records);
        for (size_t i = 0; i < n; i++)
        {
            json_t* wire = json_array_get(records, i);
            const char* record = json_string_value(json_object_get(wire, "record"));
            if (!record || strcmp(record, "type") != 0)
                continue;
            json_t* data = json_object_get(wire, "data");
            const char* module = json_string_value(json_object_get(data, "module"));
            const char* name = json_string_value(json_object_get(data, "name"));
            const char* decl = json_string_value(json_object_get(data, "decl"));
            bool deleted = json_is_true(json_object_get(data, "deleted"));
            if (!module || !*module || !name || !*name || deleted || !decl || !*decl)
                continue;
            replacement[toLower(module)][name] = decl;
        }
        std::lock_guard<std::mutex> lk(typeMutex_);
        typeDecls_.swap(replacement);
    }

    bool eraseType(const std::string& module, const std::string& name)
    {
        std::lock_guard<std::mutex> lk(typeMutex_);
        auto moduleIt = typeDecls_.find(module);
        if(moduleIt == typeDecls_.end())
            return false;
        bool changed = moduleIt->second.erase(name) != 0;
        if(moduleIt->second.empty())
            typeDecls_.erase(moduleIt);
        return changed;
    }

    std::string currentModule()
    {
        std::lock_guard<std::mutex> lk(stateMutex_);
        return module_;
    }

    // Write a complete, immutable header generation and queue x64dbg's native
    // C parser. DbgCmdExec is asynchronous, so overwriting/deleting a shared
    // file immediately would race the command-processing thread. Each queued
    // command gets its own directory while the basename remains constant:
    // ParseTypes uses that basename as the owner and replaces the preceding
    // symbridge generation rather than accumulating stale definitions.
    void reloadCurrentTypes()
    {
        std::string module = currentModule();
        if (module.empty())
            return;

        std::map<std::string, std::string> declarations;
        unsigned long long generation;
        std::wstring root;
        {
            std::lock_guard<std::mutex> lk(typeMutex_);
            auto it = typeDecls_.find(module);
            if (it != typeDecls_.end())
                declarations = it->second;
            generation = ++typeGeneration_;

            if (typeTempRoot_.empty())
            {
                wchar_t temp[MAX_PATH] = L"";
                DWORD len = GetTempPathW(MAX_PATH, temp);
                if (len == 0 || len >= MAX_PATH)
                {
                    _plugin_logprintf("[symbridge] GetTempPath failed for type import\n");
                    return;
                }
                typeTempRoot_ = std::wstring(temp) + L"symbridge_" +
                    std::to_wstring(GetCurrentProcessId());
            }
            root = typeTempRoot_;
        }

        if (!CreateDirectoryW(root.c_str(), nullptr) &&
            GetLastError() != ERROR_ALREADY_EXISTS)
        {
            _plugin_logprintf("[symbridge] cannot create type temp directory\n");
            return;
        }

        // A PID can eventually be reused while its old temp tree remains.
        // Advance until this process owns a fresh immutable generation path.
        std::wstring generationDir;
        for (;;)
        {
            generationDir = root + L"\\" + std::to_wstring(generation);
            if (CreateDirectoryW(generationDir.c_str(), nullptr))
                break;
            if (GetLastError() != ERROR_ALREADY_EXISTS)
            {
                _plugin_logprintf("[symbridge] cannot create type generation directory\n");
                return;
            }
            std::lock_guard<std::mutex> lk(typeMutex_);
            generation = ++typeGeneration_;
        }

        const std::wstring header = generationDir + L"\\symbridge_types.h";
        {
            std::ofstream out(
                std::filesystem::path(header), std::ios::binary | std::ios::trunc
            );
            if (!out)
            {
                _plugin_logprintf("[symbridge] cannot write type header\n");
                return;
            }
            out << "/* generated by symbridge for " << module << " */\n";
            for (const auto& item : declarations)
            {
                out << item.second;
                if (item.second.empty() || item.second.back() != '\n')
                    out << '\n';
            }
            if (!out)
            {
                _plugin_logprintf("[symbridge] failed while writing type header\n");
                return;
            }
        }

        std::string headerUtf8 = wideToUtf8(header);
        if (headerUtf8.empty())
        {
            _plugin_logprintf("[symbridge] cannot encode type header path as UTF-8\n");
            return;
        }
        std::string command = "ParseTypes \"" + headerUtf8 + "\"";
        if (!DbgCmdExec(command.c_str()))
        {
            _plugin_logprintf("[symbridge] could not queue ParseTypes for %s\n", module.c_str());
            return;
        }
        _plugin_logprintf(
            "[symbridge] queued %llu type declaration(s) for %s\n",
            (unsigned long long)declarations.size(), module.c_str());
    }

    void applyLabel(const std::string& module, duint rva, const std::string& name)
    {
        duint base = Script::Module::BaseFromName(module.c_str());
        if (!base)
        {
            // Module not loaded yet (e.g. Connect before the target is running).
            // Buffer and retry when the process starts.
            std::lock_guard<std::mutex> lk(pendingMutex_);
            pending_.push_back({PEND_LABEL, module, rva, name});
            return;
        }
        std::lock_guard<std::mutex> lk(stateMutex_);
        // 4-arg overload (…, manual, temporary) picked explicitly to avoid an
        // ambiguous-overload error against the 3-arg form.
        Script::Label::Set(base + rva, name.c_str(), true, false);
        lastLabels_[rva] = name; // seed so the poll won't echo it back
        GuiUpdateAllViews();
    }

    void applyComment(const std::string& module, duint rva, const std::string& text)
    {
        duint base = Script::Module::BaseFromName(module.c_str());
        if (!base)
        {
            std::lock_guard<std::mutex> lk(pendingMutex_);
            pending_.push_back({PEND_COMMENT, module, rva, text});
            return;
        }
        std::lock_guard<std::mutex> lk(stateMutex_);
        Script::Comment::Set(base + rva, text.c_str(), true);
        lastComments_[rva] = text;
        GuiUpdateAllViews();
    }

    // -- outbound poll (poll thread) ----------------------------------------

    void pollLoop()
    {
        while (runningPoll_)
        {
            Sleep(750);
            if (!client_.connected() || !DbgIsDebugging())
                continue;
            refreshModule();
            scanLabels(false);
            scanComments(false);
            syncLocalTypeFile(false);
        }
    }

    bool syncLocalTypeFile(bool force)
    {
        std::filesystem::path path;
        std::string module;
        std::filesystem::file_time_type oldWriteTime;
        {
            std::lock_guard<std::mutex> lk(localTypeMutex_);
            if(localTypePath_.empty())
                return false;
            path = localTypePath_;
            module = watchedModule_;
            oldWriteTime = localTypeWriteTime_;
        }
        if(module.empty() || module != currentModule())
            return false;

        std::error_code ec;
        auto writeTime = std::filesystem::last_write_time(path, ec);
        if(ec)
            return false;
        if(!force && writeTime == oldWriteTime)
            return false;

        std::ifstream input(path, std::ios::binary);
        if(!input)
            return false;
        std::string source((std::istreambuf_iterator<char>(input)),
                           std::istreambuf_iterator<char>());
        auto parsed = symbridge::parseNamedTypes(source);

        std::map<std::string, std::string> previous;
        {
            std::lock_guard<std::mutex> lk(localTypeMutex_);
            // Another poll/command may have won while I/O was in progress.
            if(!force && localTypeWriteTime_ == writeTime)
                return false;
            previous = localOwnedTypes_;
            localOwnedTypes_ = parsed;
            localTypeWriteTime_ = writeTime;
        }

        const double changedAt = nowSeconds();
        bool changed = false;
        for(const auto& oldType : previous)
        {
            if(parsed.find(oldType.first) == parsed.end())
            {
                eraseType(module, oldType.first);
                sendType(module, oldType.first, "", true, changedAt);
                changed = true;
            }
        }
        for(const auto& newType : parsed)
        {
            auto old = previous.find(newType.first);
            if(force || old == previous.end() || old->second != newType.second)
            {
                storeType(module, newType.first, newType.second);
                sendType(module, newType.first, newType.second, false, changedAt);
                changed = true;
            }
        }
        if(changed)
        {
            reloadCurrentTypes();
            _plugin_logprintf("[symbridge] synced %llu local type declaration(s)\n",
                              (unsigned long long)parsed.size());
        }
        return true;
    }

    void refreshModule()
    {
        char name[MAX_MODULE_SIZE] = "";
        if (Script::Module::GetMainModuleName(name))
        {
            std::lock_guard<std::mutex> lk(stateMutex_);
            module_ = toLower(name);
        }
    }

    void scanLabels(bool forceAll)
    {
        BridgeList<Script::Label::LabelInfo> labels;
        if (!Script::Label::GetList(&labels))
            return;
        std::lock_guard<std::mutex> lk(stateMutex_);
        for (int i = 0; i < labels.Count(); i++)
        {
            auto& L = labels[i];
            if (toLower(L.mod) != module_)
                continue;
            std::string text = L.text;
            auto it = lastLabels_.find(L.rva);
            if (forceAll || it == lastLabels_.end() || it->second != text)
            {
                lastLabels_[L.rva] = text;
                sendSymbol(module_, L.rva, text);
            }
        }
    }

    void scanComments(bool forceAll)
    {
        BridgeList<Script::Comment::CommentInfo> comments;
        if (!Script::Comment::GetList(&comments))
            return;
        std::lock_guard<std::mutex> lk(stateMutex_);
        for (int i = 0; i < comments.Count(); i++)
        {
            auto& C = comments[i];
            if (toLower(C.mod) != module_)
                continue;
            std::string text = C.text;
            auto it = lastComments_.find(C.rva);
            if (forceAll || it == lastComments_.end() || it->second != text)
            {
                lastComments_[C.rva] = text;
                sendComment(module_, C.rva, text);
            }
        }
    }

    void sendSymbol(const std::string& module, duint rva, const std::string& name)
    {
        json_t* d = json_object();
        json_object_set_new(d, "module", json_string(module.c_str()));
        json_object_set_new(d, "rva", json_integer((json_int_t)rva));
        json_object_set_new(d, "name", json_string(name.c_str()));
        json_object_set_new(d, "origin", json_string(origin_.c_str()));
        json_object_set_new(d, "ts", json_real(nowSeconds()));
        client_.sendUpdate("symbol", d, origin_);
    }

    void sendComment(const std::string& module, duint rva, const std::string& text)
    {
        json_t* d = json_object();
        json_object_set_new(d, "module", json_string(module.c_str()));
        json_object_set_new(d, "rva", json_integer((json_int_t)rva));
        json_object_set_new(d, "text", json_string(text.c_str()));
        json_object_set_new(d, "kind", json_string("regular")); // x64dbg has one comment slot
        json_object_set_new(d, "origin", json_string(origin_.c_str()));
        json_object_set_new(d, "ts", json_real(nowSeconds()));
        client_.sendUpdate("comment", d, origin_);
    }

    void sendType(const std::string& module, const std::string& name,
                  const std::string& decl, bool deleted, double ts)
    {
        if(!client_.connected())
            return;
        json_t* d = json_object();
        json_object_set_new(d, "module", json_string(module.c_str()));
        json_object_set_new(d, "name", json_string(name.c_str()));
        json_object_set_new(d, "decl", json_string(decl.c_str()));
        json_object_set_new(d, "deleted", json_boolean(deleted));
        json_object_set_new(d, "origin", json_string(origin_.c_str()));
        json_object_set_new(d, "ts", json_real(ts));
        client_.sendUpdate("type", d, origin_);
    }

    enum PendingKind
    {
        PEND_LABEL,
        PEND_COMMENT,
    };
    struct Pending
    {
        PendingKind kind;
        std::string module;
        duint rva;
        std::string text;
    };

    BrokerClient client_;
    std::string origin_;
    std::string module_;
    std::atomic<bool> runningPoll_{false};
    std::thread poll_;
    std::mutex stateMutex_;
    std::map<duint, std::string> lastLabels_;
    std::map<duint, std::string> lastComments_;
    std::mutex typeMutex_;
    std::map<std::string, std::map<std::string, std::string>> typeDecls_;
    unsigned long long typeGeneration_ = 0;
    std::wstring typeTempRoot_;
    std::mutex localTypeMutex_;
    std::filesystem::path localTypePath_;
    std::filesystem::file_time_type localTypeWriteTime_{};
    std::string watchedModule_;
    std::map<std::string, std::string> localOwnedTypes_;
    std::mutex pendingMutex_;
    std::vector<Pending> pending_;
};

static Adapter g_adapter;

void Adapter::onMessageStatic(json_t* root)
{
    g_adapter.onMessage(root);
}

static bool CBCONNECT(int, char**)
{
    if (g_adapter.connected())
    {
        _plugin_logprintf("[symbridge] already connected\n");
        return true;
    }
    g_adapter.start();
    return g_adapter.connected();
}

static bool CBDISCONNECT(int, char**)
{
    g_adapter.stop();
    return true;
}

static bool CBPUSHALL(int, char**)
{
    if (!g_adapter.connected())
    {
        _plugin_logprintf("[symbridge] push: not connected\n");
        return false;
    }
    g_adapter.pushAll();
    return true;
}

static bool CBWATCHTYPES(int argc, char** argv)
{
    if(argc < 2 || !argv[1] || !*argv[1])
    {
        _plugin_logprintf("[symbridge] usage: symbridgewatchtypes \"C:\\path\\types.h\"\n");
        return false;
    }
    if(!g_adapter.connected())
    {
        _plugin_logprintf("[symbridge] watch types: not connected\n");
        return false;
    }
    return g_adapter.watchTypeFile(argv[1]);
}

static bool CBSYNCTYPES(int, char**)
{
    if(!g_adapter.connected())
    {
        _plugin_logprintf("[symbridge] sync types: not connected\n");
        return false;
    }
    return g_adapter.syncTypes();
}

// ---------------------------------------------------------------------------
// plugin lifecycle
// ---------------------------------------------------------------------------

static int g_pluginHandle = 0;

enum MenuEntry
{
    MENU_CONNECT = 0,
    MENU_DISCONNECT,
    MENU_PUSHALL,
};

static void CBCREATEPROCESS(CBTYPE, void*)
{
    g_adapter.onDebugStart();
}

static void CBMENUENTRY(CBTYPE, void* callbackInfo)
{
    PLUG_CB_MENUENTRY* info = (PLUG_CB_MENUENTRY*)callbackInfo;
    switch (info->hEntry)
    {
    case MENU_CONNECT:
        if (g_adapter.connected())
            _plugin_logprintf("[symbridge] already connected\n");
        else
            g_adapter.start();
        break;
    case MENU_DISCONNECT:
        g_adapter.stop();
        break;
    case MENU_PUSHALL:
        g_adapter.pushAll();
        break;
    }
}

bool pluginit(PLUG_INITSTRUCT* initStruct)
{
    initStruct->sdkVersion = PLUG_SDKVERSION;
    initStruct->pluginVersion = PLUGIN_VERSION;
    strncpy_s(initStruct->pluginName, PLUGIN_NAME, _TRUNCATE);
    g_pluginHandle = initStruct->pluginHandle;
    _plugin_registercallback(g_pluginHandle, CB_MENUENTRY, CBMENUENTRY);
    _plugin_registercallback(g_pluginHandle, CB_CREATEPROCESS, CBCREATEPROCESS);
    _plugin_registercommand(g_pluginHandle, "symbridgeconnect", CBCONNECT, false);
    _plugin_registercommand(g_pluginHandle, "symbridgedisconnect", CBDISCONNECT, false);
    _plugin_registercommand(g_pluginHandle, "symbridgepush", CBPUSHALL, true);
    _plugin_registercommand(g_pluginHandle, "symbridgewatchtypes", CBWATCHTYPES, true);
    _plugin_registercommand(g_pluginHandle, "symbridgetypesync", CBSYNCTYPES, true);
    _plugin_logprintf("[symbridge] plugin loaded (v%d)\n", PLUGIN_VERSION);
    return true;
}

bool plugstop()
{
    g_adapter.stop();
    _plugin_unregistercallback(g_pluginHandle, CB_MENUENTRY);
    _plugin_unregistercallback(g_pluginHandle, CB_CREATEPROCESS);
    _plugin_unregistercommand(g_pluginHandle, "symbridgeconnect");
    _plugin_unregistercommand(g_pluginHandle, "symbridgedisconnect");
    _plugin_unregistercommand(g_pluginHandle, "symbridgepush");
    _plugin_unregistercommand(g_pluginHandle, "symbridgewatchtypes");
    _plugin_unregistercommand(g_pluginHandle, "symbridgetypesync");
    return true;
}

void plugsetup(PLUG_SETUPSTRUCT* setupStruct)
{
    int hMenu = setupStruct->hMenu;
    _plugin_menuaddentry(hMenu, MENU_CONNECT, "Connect to broker");
    _plugin_menuaddentry(hMenu, MENU_DISCONNECT, "Disconnect");
    _plugin_menuaddseparator(hMenu);
    _plugin_menuaddentry(hMenu, MENU_PUSHALL, "Push all annotations");
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID)
{
    return TRUE;
}
