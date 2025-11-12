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
#include <cstdint>
using namespace std;

// ───────────────────────────────
// 🔹 안전 SHA256 (Windows 포함 완전판)
// ───────────────────────────────
static inline uint32_t ROTR(uint32_t x, uint32_t n){return (x>>n)|(x<<(32-n));}

string sha256(const string &input){
    const uint32_t K[64]={
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };
    vector<uint8_t> data(input.begin(),input.end());
    uint64_t bitlen=(uint64_t)data.size()*8ULL;
    data.push_back(0x80);
    while((data.size()%64)!=56)data.push_back(0x00);
    for(int i=7;i>=0;--i)data.push_back((bitlen>>(i*8))&0xFF);

    uint32_t H[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                   0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};

    for(size_t chunk=0;chunk+64<=data.size();chunk+=64){
        uint32_t w[64]={0};
        for(int i=0;i<16;i++){
            size_t idx=chunk+4*i;
            if(idx+3>=data.size()) break;
            w[i]=((uint32_t)data[idx]<<24)|((uint32_t)data[idx+1]<<16)|
                 ((uint32_t)data[idx+2]<<8)|((uint32_t)data[idx+3]);
        }
        for(int i=16;i<64;i++){
            uint32_t s0=ROTR(w[i-15],7)^ROTR(w[i-15],18)^(w[i-15]>>3);
            uint32_t s1=ROTR(w[i-2],17)^ROTR(w[i-2],19)^(w[i-2]>>10);
            w[i]=w[i-16]+s0+w[i-7]+s1;
        }
        uint32_t a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
        for(int i=0;i<64;i++){
            uint32_t S1=ROTR(e,6)^ROTR(e,11)^ROTR(e,25);
            uint32_t ch=(e&f)^((~e)&g);
            uint32_t temp1=h+S1+ch+K[i]+w[i];
            uint32_t S0=ROTR(a,2)^ROTR(a,13)^ROTR(a,22);
            uint32_t maj=(a&b)^(a&c)^(b&c);
            uint32_t temp2=S0+maj;
            h=g; g=f; f=e; e=d+temp1; d=c; c=b; b=a; a=temp1+temp2;
        }
        H[0]+=a;H[1]+=b;H[2]+=c;H[3]+=d;H[4]+=e;H[5]+=f;H[6]+=g;H[7]+=h;
    }

    ostringstream oss;
    for(int i=0;i<8;i++)
        oss<<hex<<setw(8)<<setfill('0')<<H[i];
    return oss.str();
}

// ───────────────────────────────
// 🔹 Java-like Tokenizer & Parser
// ───────────────────────────────
vector<string> tokenize(const string& src){
    regex r(R"([\w]+|[{}();=+\-*/<>])");
    sregex_iterator it(src.begin(),src.end(),r),end;
    vector<string>t;
    for(;it!=end;++it)t.push_back(it->str());
    return t;
}
struct Node{string kind,name,type,value;vector<shared_ptr<Node>>children;};

shared_ptr<Node> parse_class(const vector<string>&t,size_t&i){
    if(i+1>=t.size())return nullptr;
    auto n=make_shared<Node>();n->kind="Class";n->name=t[i+1];i+=2;
    if(i>=t.size()||t[i]!="{")return n;
    ++i;
    while(i<t.size()&&t[i]!="}"){
        if((t[i]=="int"||t[i]=="String"||t[i]=="void") && i+1<t.size()){
            string ty=t[i++],nm=t[i++];
            if(i<t.size()&&t[i]=="("){
                auto m=make_shared<Node>();m->kind="Method";m->type=ty;m->name=nm;
                while(i<t.size()&&t[i]!="{")++i;
                if(i<t.size())++i;
                string b;
                while(i<t.size()&&t[i]!="}")b+=t[i++]+" ";
                if(i<t.size())++i;
                m->value=b;n->children.push_back(m);
            }else if(i<t.size()&&t[i]=="="){
                ++i;if(i>=t.size())break;string val=t[i++];
                auto v=make_shared<Node>();v->kind="Var";v->type=ty;v->name=nm;v->value=val;
                n->children.push_back(v);
                if(i<t.size()&&t[i]==";")++i;
            }
        }else ++i;
    }
    if(i<t.size())++i;
    return n;
}

// ───────────────────────────────
// 🔹 Semantic Runtime
// ───────────────────────────────
class SemanticRuntime{
    unordered_map<string,string>vars;
    vector<string>ledger;
public:
    void runMethod(const shared_ptr<Node>&m){
        if(!m)return;
        ledger.push_back("Run "+m->name);
        interpret(m->value);
    }
    void interpret(const string&src){
        vector<string>tok=tokenize(src);
        for(size_t i=0;i<tok.size();++i){
            if(tok[i]=="System"&&i+5<tok.size()){
                if(tok[i+1]=="."&&tok[i+2]=="out"&&tok[i+3]=="."&&tok[i+4]=="println"){
                    i+=6;string msg;
                    while(i<tok.size()&&tok[i]!=")")msg+=tok[i++]+" ";
                    cout<<"🖨️ "<<regex_replace(msg,regex("\""),"")<<endl;
                    ledger.push_back("Print: "+msg);
                }
            }else if(tok[i]=="int"&&i+3<tok.size()&&tok[i+2]=="="){
                string name=tok[i+1],val=tok[i+3];
                vars[name]=val;
                cout<<"📦 "<<name<<" = "<<val<<endl;
                ledger.push_back("Var: "+name+"="+val);
                i+=3;
            }
        }
    }
    void writeLedger(){
        ofstream f("proofledger.txt");
        string c;for(auto&s:ledger)c+=s;
        f<<"# ProofLedger\nHash: "<<sha256(c)<<"\n\n";
        for(auto&s:ledger)f<<"- "<<s<<"\n";
        f.close();
        cout<<"🧾 Ledger saved (SHA256 chain)\n";
    }
};

// ───────────────────────────────
// 🔹 Main
// ───────────────────────────────
int main(int argc,char*argv[]){
    if(argc<2){cerr<<"Usage: semantic_jvmfree_run <file.java>\n";return 1;}
    ifstream fin(argv[1]);
    if(!fin.is_open()){cerr<<"Error: cannot open "<<argv[1]<<endl;return 1;}
    stringstream buf;buf<<fin.rdbuf();
    auto tok=tokenize(buf.str());
    size_t i=0;shared_ptr<Node>cls;
    while(i<tok.size()){
        if(tok[i]=="class")cls=parse_class(tok,i);
        else ++i;
    }
    if(!cls){
        cerr<<"Error: no class found.\n";
        return 1;
    }
    SemanticRuntime rt;
    for(auto&m:cls->children)
        if(m->kind=="Method"&&m->name=="main")
            rt.runMethod(m);
    rt.writeLedger();
    return 0; // ✅ 정상 종료
}
