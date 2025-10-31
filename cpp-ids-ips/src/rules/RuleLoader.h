#pragma once
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <pcre2.h>

struct Rule {
    int sid = 0;
    int rev = 0;
    std::string msg;
    std::string classtype;
    int severity = 5;
    double confidence = 1.0;
    std::string action = "alert"; // alert, drop, monitor, block_temp
    std::string fast_content; // lowercased
    std::string pcre_pattern;
    pcre2_code* pcre_code = nullptr;
    bool enabled = true;
    std::map<std::string, std::string> metadata;

    ~Rule();
    bool match(const unsigned char* payload, size_t len) const;
};

class RuleLoader {
public:
    RuleLoader() = default;
    ~RuleLoader() = default;

    bool loadRules(const std::string& filename, std::string& err);
    const std::vector<std::shared_ptr<Rule>>& getRules() const { return rules; }

    static std::string toLower(const std::string& s);

private:
    std::vector<std::shared_ptr<Rule>> rules;
    void parseRuleLine(const std::string& line);
    pcre2_code* compilePcre(const std::string& pattern, std::string& err);
};
