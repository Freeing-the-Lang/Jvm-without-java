#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <regex>
#include <unordered_map>
#include <memory>
#include <iomanip>
#include <openssl/sha.h>

using namespace std;

// ───────────────────────────────
// 🔹 SHA256 ProofLedger
// ───────────────────────────────
string sha256(const string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)input.c_str(), input.size(), hash);
    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    return ss.str();
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
    stringstream buf; buf<<fin.rdbuf();
    auto tokens=tokenize(buf.str());
    size_t i=0; shared_ptr<Node> cls;
    while(i<tokens.size()){if(tokens[i]=="class")cls=parse_class(tokens,i);else ++i;}
    SemanticRuntime rt;
    for(auto&m:cls->children)if(m->kind=="Method"&&m->name=="main")rt.runMethod(m);
    rt.writeLedger();
}
