#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <regex>
#include <unordered_map>
#include <memory>
#include <iomanip>
#include <array>
#include <cstring>

using namespace std;

// ───────────────────────────────
// 🔹 Minimal SHA256 (No OpenSSL)
// ───────────────────────────────
uint32_t rotr(uint32_t x, uint32_t n){ return (x >> n) | (x << (32 - n)); }

string sha256(const string &input) {
    const uint32_t k[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };
    vector<uint8_t> data(input.begin(), input.end());
    uint64_t bitlen = data.size() * 8;
    data.push_back(0x80);
    while ((data.size() % 64) != 56) data.push_back(0x00);
    for (int i = 7; i >= 0; --i) data.push_back((bitlen >> (i * 8)) & 0xff);

    uint32_t h[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    for (size_t chunk = 0; chunk < data.size(); chunk += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (data[chunk + 4*i] << 24) | (data[chunk + 4*i + 1] << 16)
                 | (data[chunk + 4*i + 2] << 8) | data[chunk + 4*i + 3];
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3);
            uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i=0;i<64;++i){
            uint32_t S1=rotr(e,6)^rotr(e,11)^rotr(e,25);
            uint32_t ch=(e&f)^((~e)&g);
            uint32_t temp1=hh+S1+ch+k[i]+w[i];
            uint32_t S0=rotr(a,2)^rotr(a,13)^rotr(a,22);
            uint32_t maj=(a&b)^(a&c)^(b&c);
            uint32_t temp2=S0+maj;
            hh=g; g=f; f=e; e=d+temp1; d=c; c=b; b=a; a=temp1+temp2;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }
    ostringstream oss;
    for (int i=0;i<8;++i)
        oss << hex << setw(8) << setfill('0') << h[i];
    return oss.str();
}

// ───────────────────────────────
// 🔹 Tokenizer
// ───────────────────────────────
vector<string> tokenize(const string& src) {
    regex token_re(R"([\w]+|[{}();=+\-*/<>])");
    sregex_iterator it(src.begin(), src.end(), token_re);
    sregex_iterator end;
    vector<string> tokens;
    for (; it != end; ++it) tokens.push_back(it->str());
    return tokens;
}

// ───────────────────────────────
// 🔹 AST 구조체
// ───────────────────────────────
struct Node {
    string kind, name, type, value;
    vector<shared_ptr<Node>> children;
};

// ───────────────────────────────
// 🔹 Parser
// ───────────────────────────────
shared_ptr<Node> parse_class(const vector<string>& t, size_t& i) {
    auto node = make_shared<Node>();
    node->kind = "Class";
    node->name = t[i + 1];
    i += 2;

    if (t[i] != "{") return node;
    ++i;
    while (i < t.size() && t[i] != "}") {
        if (t[i] == "int" || t[i] == "String" || t[i] == "void") {
            string type = t[i++], name = t[i++];
            if (t[i] == "(") {
                auto m = make_shared<Node>();
                m->kind = "Method"; m->type = type; m->name = name;
                while (i < t.size() && t[i] != "{") ++i; ++i;
                string body; while (i < t.size() && t[i] != "}") body += t[i++] + " "; ++i;
                m->value = body; node->children.push_back(m);
            } else if (t[i] == "=") {
                ++i; string val = t[i++];
                auto v = make_shared<Node>();
                v->kind = "Var"; v->type = type; v->name = name; v->value = val;
                node->children.push_back(v);
                if (t[i] == ";") ++i;
            }
        } else ++i;
    }
    ++i; return node;
}

// ───────────────────────────────
// 🔹 Semantic Interpreter
// ───────────────────────────────
class SemanticRuntime {
    unordered_map<string, string> vars;
    vector<string> ledger;

public:
    void runMethod(const shared_ptr<Node>& m) {
        ledger.push_back("Run " + m->name);
        interpret(m->value);
    }

    void interpret(const string& src) {
        vector<string> tok = tokenize(src);
        for (size_t i = 0; i < tok.size(); ++i) {
            if (tok[i] == "System" && i + 5 < tok.size()) {
                if (tok[i+1]=="."&&tok[i+2]=="out"&&tok[i+3]=="."&&tok[i+4]=="println") {
                    i+=6; string msg;
                    while (i < tok.size() && tok[i] != ")") msg += tok[i++] + " ";
                    cout << "🖨️ " << regex_replace(msg, regex("\""), "") << endl;
                    ledger.push_back("Print: " + msg);
                }
            } else if (tok[i]=="int" && i+2<tok.size() && tok[i+2]=="=") {
                string name=tok[i+1], val=tok[i+3];
                vars[name]=val;
                cout << "📦 " << name << " = " << val << endl;
                ledger.push_back("Var: "+name+"="+val);
                i+=3;
            }
        }
    }

    void writeLedger() {
        ofstream f("proofledger.txt");
        string concat;
        for (auto&s:ledger) concat+=s;
        f<<"# ProofLedger\nHash: "<<sha256(concat)<<"\n\n";
        for (auto&s:ledger) f<<"- "<<s<<"\n";
        f.close();
        cout<<"🧾 Ledger saved (SHA256 chain)\n";
    }
};

// ───────────────────────────────
// 🔹 main
// ───────────────────────────────
int main(int argc, char* argv[]) {
    if (argc<2){cerr<<"Usage: semantic_jvmfree_run <file.java>\n";return 1;}
    ifstream fin(argv[1]);
    if(!fin.is_open()){cerr<<"Error: cannot open "<<argv[1]<<endl;return 1;}
    stringstream buf; buf<<fin.rdbuf();
    auto tokens=tokenize(buf.str());
    size_t i=0; shared_ptr<Node> cls;
    while(i<tokens.size()){if(tokens[i]=="class")cls=parse_class(tokens,i);else ++i;}
    if(!cls){cerr<<"Error: no class found.\n";return 1;}
    SemanticRuntime rt;
    for(auto&m:cls->children)
        if(m->kind=="Method"&&m->name=="main")
            rt.runMethod(m);
    rt.writeLedger();
}
