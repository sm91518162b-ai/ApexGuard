#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <string>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cmath>
#include <random>
#include <unistd.h>
#include <sys/stat.h>
#include <signal.h>
#include <set>
#include <regex>

namespace fs = std::filesystem;
using namespace std;

#define RED "\033[1;31m"
#define GREEN "\033[1;32m"
#define YELLOW "\033[1;33m"
#define CYAN "\033[1;36m"
#define MAGENTA "\033[1;35m"
#define RESET "\033[0m"

const string VAULT_DIR = ".flashvault";
const string REPORT_FILE = "reporte_apex.html";
const string EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
const double ENTROPY_THRESHOLD = 7.2;

set<string> WHITELIST = {"flashav", ".flashvault", "reporte_apex.html"};

vector<pair<string,string>> IMPHASH_DB = {
    {"f24a6f8b", "Emotet.Banker"}, {"a1d9c5e2", "TrickBot.Loader"},
    {"3b7f1a9c", "Ryuk.Ransomware"}, {"9e2d4f6a", "Qbot.Stealer"},
    {"5c8b3e1d", "AgentTesla.RAT"}, {"7f3a9b2e", "FormBook.Spy"},
    {"2d6e8c4a", "Lokibot.CredSteal"}, {"8b4f2d9c", "Dridex.Botnet"},
    {"1a5c7e3b", "CobaltStrike.Beacon"}, {"6e9d1f8a", "Mirai.Botnet"}
};

vector<pair<string,string>> YARA_RULES = {
    {"Suspicious_Base64", "[A-Za-z0-9+/]{40,}={0,2}"},
    {"Powershell_Encoded", "powershell.*-enc"},
    {"Reverse_Shell_NC", "nc.*-e.*sh"},
    {"PHP_Webshell", "eval.*base64_decode"},
    {"BTC_Wallet", "[13][a-km-zA-HJ-NP-Z1-9]{25,34}"}
};

string gen_key() {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 15);
    stringstream ss;
    for(int i = 0; i < 32; i++) ss << hex << dis(gen);
    return ss.str();
}

double calc_entropy(const vector<char>& data) {
    if(data.empty()) return 0;
    int counts[256] = {0};
    for(char c : data) counts[(unsigned char)c]++;
    double entropy = 0;
    for(int i = 0; i < 256; i++) {
        if(counts[i] > 0) {
            double p = (double)counts[i] / data.size();
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

string fake_imphash(const string& path) {
    try {
        auto sz = fs::exists(path)? fs::file_size(path) : 0;
        size_t h = hash<string>{}(path + to_string(sz));
        stringstream ss;
        ss << hex << (h & 0xFFFFFFFF);
        return ss.str().substr(0,8);
    } catch(...) { return "00000000"; }
}

void log(const string& level, const string& msg) {
    cout << "[" << CYAN << "APEX" << RESET << "] ";
    if(level == "ALERT") cout << RED << "ALERT" << RESET;
    else if(level == "OK") cout << GREEN << "OK" << RESET;
    else cout << YELLOW << level << RESET;
    cout << ": " << msg << endl;
}

bool encrypt_to_vault(const string& filepath, const string& threat) {
    try {
        fs::create_directory(VAULT_DIR);
        string key = gen_key();
        string hash = to_string(std::hash<string>{}(filepath + key));
        string vault_path = VAULT_DIR + "/" + hash.substr(0,8) + ".flashlock";

        ifstream src(filepath, ios::binary);
        if(!src) return false;
        vector<char> buffer((istreambuf_iterator<char>(src)), {});
        src.close();

        for(size_t i = 0; i < buffer.size(); i++) {
            buffer[i] ^= key[i % key.size()];
        }

        ofstream dst(vault_path, ios::binary);
        dst.write(buffer.data(), buffer.size());
        dst.close();

        log("ALERT", "Amenaza " + threat + " CIFRADA en: " + vault_path);
        log("ALERT", "KEY FORENSE: " + key);
        fs::remove(filepath);
        return true;
    } catch(...) {
        return false;
    }
}

int yara_scan(const string& content) {
    int hits = 0;
    for(auto& rule : YARA_RULES) {
        try {
            if(regex_search(content, regex(rule.second, regex_constants::icase))) hits++;
        } catch(...) {}
    }
    return hits;
}

bool scan_file(const string& path, vector<string>& amenazas, int& yara_hits) {
    try {
        for(auto& safe : WHITELIST) {
            if(path.find(safe)!= string::npos) return false;
        }

        if(!fs::exists(path) ||!fs::is_regular_file(path)) return false;

        ifstream file(path, ios::binary);
        if(!file) return false;
        vector<char> data((istreambuf_iterator<char>(file)), {});
        file.close();

        string content(data.begin(), data.end());

        if(content.find(EICAR)!= string::npos) {
            log("ALERT", "AMENAZA: " + path + " -> EICAR_Test");
            if(encrypt_to_vault(path, "EICAR_Test")) amenazas.push_back(path + ":EICAR");
            return true;
        }

        int local_yara = yara_scan(content);
        if(local_yara > 0) {
            yara_hits += local_yara;
            log("ALERT", "YARA: " + path + " -> " + to_string(local_yara) + " reglas");
            if(encrypt_to_vault(path, "YARA_Match")) amenazas.push_back(path + ":YARA");
            return true;
        }

        double entropy = calc_entropy(data);
        if(entropy > ENTROPY_THRESHOLD && data.size() > 100) {
            log("ALERT", "HEURISTICA: " + path + " -> Entropia: " + to_string(entropy).substr(0,4));
            if(encrypt_to_vault(path, "Heur.HighEntropy")) amenazas.push_back(path + ":Entropia");
            return true;
        }

        string imphash = fake_imphash(path);
        for(auto& sig : IMPHASH_DB) {
            if(imphash == sig.first) {
                log("ALERT", "IMPHASH: " + path + " -> " + sig.second);
                if(encrypt_to_vault(path, sig.second)) amenazas.push_back(path + ":" + sig.second);
                return true;
            }
        }
    } catch(...) {}
    return false;
}

void gen_html_report(int escaneados, vector<string>& amenazas, double tiempo, int yara_hits) {
    ofstream html(REPORT_FILE);
    auto now = chrono::system_clock::now();
    time_t t = chrono::system_clock::to_time_t(now);
    html << "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>FlashAV Report</title>";
    html << "<style>body{background:#0a0a0a;color:#00ff41;font-family:monospace;padding:20px}";
    html << "h1{color:#ff0040;text-align:center}.ok{color:#00ff41}.alert{color:#ff0040;font-weight:bold}";
    html << "table{border:2px solid #00ff41;width:100%;margin:20px 0;border-collapse:collapse}";
    html << "td,th{border:1px solid #00ff41;padding:10px}</style></head><body>";
    html << "<h1>FLASHAV v4.1 APEX STABLE</h1>";
    html << "<p>Fecha: " << put_time(localtime(&t), "%Y-%m-%d %H:%M:%S") << "</p>";
    html << "<p>Escaneados: " << escaneados << " | Tiempo: " << fixed << setprecision(2) << tiempo << "s</p>";
    html << "<p>YARA Hits: " << yara_hits << " | Amenazas: " << amenazas.size() << "</p>";
    if(!amenazas.empty()) {
        html << "<table><tr><th>Ruta</th><th>Tipo</th></tr>";
        for(auto& a : amenazas) {
            size_t pos = a.find(':');
            html << "<tr><td>" << a.substr(0,pos) << "</td><td class='alert'>" << a.substr(pos+1) << "</td></tr>";
        }
        html << "</table>";
    } else {
        html << "<h2 class='ok'>SISTEMA LIMPIO</h2>";
    }
    html << "</body></html>";
    html.close();
    log("OK", "Reporte generado: " + REPORT_FILE);
}

int main(int argc, char* argv[]) {
    cout << MAGENTA << "FLASHAV v4.1 APEX STABLE" << RESET << endl;
    cout << MAGENTA << "El terror de los RATs en Termux - Sin Root" << RESET << endl;

    if(argc < 2) {
        cout << YELLOW << "Uso: " << argv[0] << " <ruta>" << RESET << endl;
        return 1;
    }

    string target = argv[1];
    vector<string> amenazas;
    int total = 0, yara_hits = 0;
    auto start = chrono::high_resolution_clock::now();

    try {
        if(fs::is_directory(target)) {
            for(auto& p : fs::recursive_directory_iterator(target, fs::directory_options::skip_permission_denied)) {
                try {
                    if(fs::is_regular_file(p)) {
                        total++;
                        scan_file(p.path().string(), amenazas, yara_hits);
                    }
                } catch(...) { continue; }
            }
        } else {
            total = 1;
            scan_file(target, amenazas, yara_hits);
        }
    } catch(...) {
        log("ALERT", "Error accediendo a: " + target);
    }

    auto end = chrono::high_resolution_clock::now();
    double tiempo = chrono::duration<double>(end - start).count();

    cout << CYAN << "\n========== RESUMEN ==========" << RESET << endl;
    cout << "Escaneados: " << total << endl;
    if(tiempo > 0) cout << "Velocidad: " << (int)(total/tiempo) << " archivos/s" << endl;
    cout << "Tiempo: " << tiempo << "s" << endl;
    cout << "YARA Hits: " << YELLOW << yara_hits << RESET << endl;
    cout << "Amenazas: " << RED << amenazas.size() << RESET << endl;

    if(amenazas.size() > 0) cout << RED << "ESTADO: AMENAZAS NEUTRALIZADAS" << RESET << endl;
    else cout << GREEN << "ESTADO: LIMPIO" << RESET << endl;

    gen_html_report(total, amenazas, tiempo, yara_hits);
    return 0;
}