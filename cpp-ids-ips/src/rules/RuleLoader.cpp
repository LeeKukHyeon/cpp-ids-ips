#define PCRE2_CODE_UNIT_WIDTH 8
#include "RuleLoader.h"
#include <fstream>
#include <sstream>
#include <regex>
#include <iostream>
#include <algorithm>
#include <cctype>

Rule::~Rule() {
    if (pcre_code) pcre2_code_free(pcre_code);
}

static inline std::string trim(const std::string& s) {
    auto a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    auto b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

std::string RuleLoader::toLower(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(), [](unsigned char c) { return std::tolower(c); });
    return r;
}

bool RuleLoader::loadRules(const std::string& filename, std::string& err) {
    std::ifstream ifs(filename);
    if (!ifs.is_open()) {
        err = "failed to open rules file: " + filename;
        return false;
    }

    std::string line;
    int lineno = 0;
    while (std::getline(ifs, line)) {
        lineno++;
        std::string t = trim(line);
        if (t.empty() || t[0] == '#') continue;
        try {
            parseRuleLine(t);
        }
        catch (const std::exception& ex) {
            std::ostringstream ss;
            ss << "error parsing rule at " << filename << ":" << lineno << " : " << ex.what();
            err = ss.str();
            return false;
        }
    }
    return true;
}

void RuleLoader::parseRuleLine(const std::string& line) {
    std::regex headerRx(R"(^(\w+)\s+(\w+)\s+(.+?)\s+\-\>\s+(.+?)\s+\((.+)\)$)");
    std::smatch m;
    if (!std::regex_match(line, m, headerRx)) {
        // try to allow 'flow' style header (flow ... (opts) )
        std::regex flowRx(R"(^flow\s+(.+?)\s+\((.+)\)$)");
        if (!std::regex_match(line, m, flowRx)) {
            throw std::runtime_error("invalid rule header");
        }
        else {
            // treat as generic with options in m[2]
            std::string optstr = m[2];
            // create rule object and parse options only
            std::string tline = "alert tcp any any -> any any (" + optstr + ")";
            parseRuleLine(tline); // reuse
            return;
        }
    }

    std::string optstr = m[5];

    auto rule = std::make_shared<Rule>();
    rule->action = m[1];

    std::smatch mm;
    std::regex msgRx(R"(msg\s*:\s*\"([^\"]+)\")");
    if (std::regex_search(optstr, mm, msgRx)) rule->msg = mm[1];

    std::regex sidRx(R"(sid\s*:\s*([0-9]+))");
    if (std::regex_search(optstr, mm, sidRx)) rule->sid = std::stoi(mm[1]);
    std::regex revRx(R"(rev\s*:\s*([0-9]+))");
    if (std::regex_search(optstr, mm, revRx)) rule->rev = std::stoi(mm[1]);

    std::regex classRx(R"(classtype\s*:\s*([a-zA-Z0-9_\-]+))");
    if (std::regex_search(optstr, mm, classRx)) rule->classtype = mm[1];

    std::regex sevRx(R"(severity\s*:\s*([0-9]+))");
    if (std::regex_search(optstr, mm, sevRx)) rule->severity = std::stoi(mm[1]);

    std::regex confRx(R"(confidence\s*:\s*([0-9\.]+))");
    if (std::regex_search(optstr, mm, confRx)) rule->confidence = std::stod(mm[1]);

    std::regex actRx(R"(action\s*:\s*([a-zA-Z_]+))");
    if (std::regex_search(optstr, mm, actRx)) rule->action = mm[1];

    std::regex contentRx(R"(content\s*:\s*\"([^\"]+)\")");
    if (std::regex_search(optstr, mm, contentRx)) {
        rule->fast_content = toLower(mm[1]);
    }

    std::regex pcreRx(R"(pcre\s*:\s*\"(.*?)\")");
    if (std::regex_search(optstr, mm, pcreRx)) {
        rule->pcre_pattern = mm[1];
        std::string err;
        rule->pcre_code = compilePcre(rule->pcre_pattern, err);
        if (!rule->pcre_code) {
            std::cerr << "[RuleLoader] Warning: failed to compile pcre for sid=" << rule->sid << " pattern=" << rule->pcre_pattern << " : " << err << std::endl;
            rule->pcre_pattern.clear();
        }
    }

    // generic metadata parsing - pick up key:value or key:"value"
    std::regex metaRx(R"((\w+)\s*:\s*\"?([^\;\"\)]+)\"?)");
    auto start = optstr.cbegin();
    std::smatch sm;
    while (std::regex_search(start, optstr.cend(), sm, metaRx)) {
        std::string k = sm[1]; std::string v = sm[2];
        if (k != "msg" && k != "sid" && k != "rev" && k != "content" && k != "pcre" && k != "classtype" && k != "severity" && k != "confidence" && k != "action") {
            rule->metadata[k] = trim(v);
        }
        start = sm.suffix().first;
    }

    if (rule->sid == 0 && rule->msg.empty()) {
        throw std::runtime_error("rule missing sid and msg");
    }

    rules.push_back(rule);
}

pcre2_code* RuleLoader::compilePcre(const std::string& pattern, std::string& err) {
    int errornumber = 0;
    PCRE2_SIZE erroroffset = 0;
    uint32_t options = PCRE2_CASELESS;
    pcre2_code* re = pcre2_compile(
        (PCRE2_SPTR)pattern.c_str(),
        pattern.length(),
        options,
        &errornumber,
        &erroroffset,
        NULL
    );
    if (!re) {
        PCRE2_UCHAR buffer[256];
        pcre2_get_error_message(errornumber, buffer, sizeof(buffer));
        std::ostringstream ss;
        ss << "PCRE compile error: " << buffer << " at offset " << erroroffset;
        err = ss.str();
    }
    return re;
}

bool Rule::match(const unsigned char* payload, size_t len) const {
    if (!enabled) return false;
    // fast content check
    if (!fast_content.empty()) {
        std::string pl((const char*)payload, len);
        std::string pl_low = RuleLoader::toLower(pl);
        if (pl_low.find(fast_content) == std::string::npos) {
            return false;
        }
    }
    // pcre match if present
    if (pcre_code) {
        pcre2_match_data* mdata = pcre2_match_data_create_from_pattern(pcre_code, NULL);
        int rc = pcre2_match(pcre_code, (PCRE2_SPTR)payload, (PCRE2_SIZE)len, 0, 0, mdata, NULL);
        pcre2_match_data_free(mdata);
        return rc >= 0;
    }
    // if only fast_content present and matched, that's enough
    return !fast_content.empty();
}
