#pragma once

#include <cctype>
#include <map>
#include <string>
#include <string_view>

namespace symbridge
{
namespace detail
{
inline bool identStart(char c)
{
    return std::isalpha(static_cast<unsigned char>(c)) || c == '_';
}

inline bool identChar(char c)
{
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
}

inline void skipQuoted(std::string_view text, size_t& pos, char quote)
{
    ++pos;
    while(pos < text.size())
    {
        if(text[pos] == '\\' && pos + 1 < text.size())
            pos += 2;
        else if(text[pos++] == quote)
            break;
    }
}

inline void skipTrivia(std::string_view text, size_t& pos)
{
    for(;;)
    {
        while(pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos])))
            ++pos;
        if(pos + 1 < text.size() && text[pos] == '/' && text[pos + 1] == '/')
        {
            pos = text.find('\n', pos + 2);
            if(pos == std::string_view::npos)
                pos = text.size();
            continue;
        }
        if(pos + 1 < text.size() && text[pos] == '/' && text[pos + 1] == '*')
        {
            auto end = text.find("*/", pos + 2);
            pos = end == std::string_view::npos ? text.size() : end + 2;
            continue;
        }
        break;
    }
}

inline std::string readIdentifier(std::string_view text, size_t& pos)
{
    if(pos >= text.size() || !identStart(text[pos]))
        return {};
    const size_t start = pos++;
    while(pos < text.size() && identChar(text[pos]))
        ++pos;
    return std::string(text.substr(start, pos - start));
}

inline size_t matchingBrace(std::string_view text, size_t open)
{
    int depth = 0;
    for(size_t pos = open; pos < text.size();)
    {
        if(text[pos] == '\'' || text[pos] == '"')
        {
            skipQuoted(text, pos, text[pos]);
            continue;
        }
        if(pos + 1 < text.size() && text[pos] == '/' &&
           (text[pos + 1] == '/' || text[pos + 1] == '*'))
        {
            skipTrivia(text, pos);
            continue;
        }
        if(text[pos] == '{')
            ++depth;
        else if(text[pos] == '}' && --depth == 0)
            return pos;
        ++pos;
    }
    return std::string_view::npos;
}

inline std::string trimDeclaration(std::string_view text)
{
    while(!text.empty() && std::isspace(static_cast<unsigned char>(text.front())))
        text.remove_prefix(1);
    while(!text.empty() && std::isspace(static_cast<unsigned char>(text.back())))
        text.remove_suffix(1);
    std::string result(text);
    result.push_back('\n');
    return result;
}
}

// Extract complete top-level named C aggregate definitions. This intentionally
// accepts the common interchange subset rather than pretending to be a full C
// parser; x64dbg's ParseTypes remains the authority that validates declarations.
inline std::map<std::string, std::string> parseNamedTypes(std::string_view text)
{
    std::map<std::string, std::string> result;
    size_t pos = 0;
    size_t previousTokenStart = 0;
    std::string previousToken;

    while(pos < text.size())
    {
        detail::skipTrivia(text, pos);
        if(pos >= text.size())
            break;
        if(text[pos] == '#')
        {
            pos = text.find('\n', pos + 1);
            if(pos == std::string_view::npos)
                break;
            continue;
        }
        if(text[pos] == '\'' || text[pos] == '"')
        {
            detail::skipQuoted(text, pos, text[pos]);
            continue;
        }
        if(!detail::identStart(text[pos]))
        {
            ++pos;
            continue;
        }

        const size_t tokenStart = pos;
        std::string token = detail::readIdentifier(text, pos);
        if(token != "struct" && token != "union" && token != "enum")
        {
            previousTokenStart = tokenStart;
            previousToken = std::move(token);
            continue;
        }

        size_t cursor = pos;
        detail::skipTrivia(text, cursor);
        std::string name = detail::readIdentifier(text, cursor);
        if(name.empty())
        {
            previousToken = token;
            previousTokenStart = tokenStart;
            continue;
        }
        detail::skipTrivia(text, cursor);
        if(cursor >= text.size() || text[cursor] != '{')
        {
            pos = cursor;
            previousToken = token;
            previousTokenStart = tokenStart;
            continue; // forward declaration or a use of an existing type
        }

        const size_t close = detail::matchingBrace(text, cursor);
        if(close == std::string_view::npos)
            break;
        size_t semicolon = close + 1;
        while(semicolon < text.size() && text[semicolon] != ';')
        {
            if(text[semicolon] == '\'' || text[semicolon] == '"')
                detail::skipQuoted(text, semicolon, text[semicolon]);
            else
                ++semicolon;
        }
        if(semicolon >= text.size())
            break;

        const size_t declarationStart = previousToken == "typedef"
            ? previousTokenStart
            : tokenStart;
        result[name] = detail::trimDeclaration(
            text.substr(declarationStart, semicolon - declarationStart + 1));
        pos = semicolon + 1;
        previousToken.clear();
    }
    return result;
}
}
