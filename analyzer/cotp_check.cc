#include <hilti/rt/libhilti.h>

#include <zeek/analyzer/Manager.h>

bool is_cotp_available() {
    static bool res=false;
    static bool cached=false;
    if(!cached) {
        res=bool(zeek::analyzer_mgr->GetAnalyzerTag("COTP"));
        cached=true;
    }
    return res;
}
