#include "../adapters/x64dbg/plugin/type_sync.h"

#include <cassert>
#include <string>

int main()
{
    const std::string source = R"(
        // Forward declarations are deliberately ignored.
        struct Forward;
        struct Foo {
            int a;
            char text[8]; // braces in comments: { }
        };
        union Value { int i; float f; };
        enum Kind { K_A, K_B };
    )";
    auto parsed = symbridge::parseNamedTypes(source);
    assert(parsed.size() == 3);
    assert(parsed.at("Foo").find("char text[8]") != std::string::npos);
    assert(parsed.at("Value").find("union Value") == 0);
    assert(parsed.at("Kind").find("enum Kind") == 0);

    auto edited = symbridge::parseNamedTypes(
        "struct Foo { int a; char text[16]; };\n"
        "struct Renamed { unsigned long long q; };\n");
    assert(edited.size() == 2);
    assert(edited.at("Foo").find("text[16]") != std::string::npos);
    assert(edited.count("Renamed") == 1);
    assert(edited.count("Value") == 0); // caller turns this diff into tombstone
    return 0;
}
