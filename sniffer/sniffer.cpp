//inspired by https://github.com/aircrack-ng/aircrack-ng/

#include <iostream>
#include <string>
#include <fstream>
#include <cstdlib>  
#include <vector>
#include <cctype>
#include <windows.h>

static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

static std::string lower(const std::string& s) {
    std::string r = s;
    for (size_t i = 0; i < r.size(); i++) r[i] = (char)std::tolower((unsigned char)r[i]);
    return r;
}

static std::string upper(const std::string& s) {
    std::string r = s;
    for (size_t i = 0; i < r.size(); i++) r[i] = (char)std::toupper((unsigned char)r[i]);
    return r;
}

static std::string aftercolon(const std::string& s) {
    size_t p = s.find(':');
    if (p == std::string::npos) return "";
    return trim(s.substr(p + 1));
}

struct Net {
    std::string bssid;
    std::string ssid;
    std::string auth;
    std::string enc;
    std::string signal;
    std::string channel;
    std::string stations;
    std::string util;
};

static int findnet(const std::vector<Net>& v, const std::string& b) {
    std::string ub = upper(b);
    for (size_t i = 0; i < v.size(); i++) {
        if (v[i].bssid == ub) return (int)i;
    }
    return -1;
}

static void parsefile(const std::string& fname, std::vector<Net>& nets) {
    std::ifstream in(fname);
    if (!in.is_open()) return;
    std::vector<std::string> lines;
    std::string l;
    while (std::getline(in, l)) lines.push_back(l);
    in.close();

    std::string ssid = "";
    std::string auth = "";
    std::string enc = "";
    std::string bssid = "";
    std::string signal = "";
    std::string channel = "";
    std::string stations = "";
    std::string util = "";

    for (size_t i = 0; i < lines.size(); i++) {
        std::string t = lower(trim(lines[i]));
        if (t.find("ssid") == 0 && t.find("bssid") == std::string::npos) {
            ssid = aftercolon(lines[i]);
            auth = "";
            enc = "";
        }
        if (t.find("auth") != std::string::npos) auth = aftercolon(lines[i]);
        if (t.find("enc") != std::string::npos) enc = aftercolon(lines[i]);
        if (t.find("bssid") != std::string::npos) {
            if (bssid != "") {
                int idx = findnet(nets, bssid);
                if (idx == -1) {
                    Net n;
                    n.bssid = upper(bssid); n.ssid = ssid; n.auth = auth; n.enc = enc;
                    n.signal = signal; n.channel = channel; n.stations = stations; n.util = util;
                    nets.push_back(n);
                }
                else {
                    if (signal > nets[idx].signal) nets[idx].signal = signal;
                }
            }
            bssid = aftercolon(lines[i]);
            signal = ""; channel = ""; stations = ""; util = "";
        }
        if (t.find("sig") != std::string::npos) signal = aftercolon(lines[i]);
        if (t.find("ch") != std::string::npos && t.find("util") == std::string::npos) channel = aftercolon(lines[i]);
        if (t.find("st") != std::string::npos) stations = aftercolon(lines[i]);
        if (t.find("util") != std::string::npos) util = aftercolon(lines[i]);
    }

    if (bssid != "") {
        int idx = findnet(nets, bssid);
        if (idx == -1) {
            Net n;
            n.bssid = upper(bssid); n.ssid = ssid; n.auth = auth; n.enc = enc;
            n.signal = signal; n.channel = channel; n.stations = stations; n.util = util;
            nets.push_back(n);
        }
        else {
            if (signal > nets[idx].signal) nets[idx].signal = signal;
        }
    }
}

int main() {

    std::vector<Net> nets;

    std::cout << "sniffing...\n";

    for (int sec = 15; sec > 0; sec--) {
        std::cout << "\reta " << sec << "s   ";
        std::cout.flush();

        size_t before = nets.size();

        std::string cmd = "netsh wlan show networks mode=bssid > scan" + std::to_string(sec) + ".txt";
        system(cmd.c_str());
        parsefile("scan" + std::to_string(sec) + ".txt", nets);

        if (nets.size() > before) {
            for (size_t i = before; i < nets.size(); i++) {
                std::cout << "\nclient found " << nets[i].bssid << " " << nets[i].ssid << "\n";
            }
        }

        Sleep(1000);
    }

    std::cout << "\rfound            \n";

    std::cout << "BSSID                CH  SIG  ST  UTIL  AUTH  ENC  SSID\n";
    std::cout << "---------------------------------------------------------------\n";

    for (size_t i = 0; i < nets.size(); i++) {
        std::cout << nets[i].bssid << "  " << nets[i].channel << "   " << nets[i].signal << "  "
            << nets[i].stations << "   " << nets[i].util << "  " << nets[i].auth << "  "
            << nets[i].enc << "  " << nets[i].ssid << "\n";
    }
    std::cout << "\ndata count: " << nets.size() << "\n";
    std::cout << "beacons/data/mb/wps need monitor mode visit https://github.com/aircrack-ng/aircrack-ng for more info  :)\n";

    system("pause");
    return 0;
}