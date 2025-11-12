#include <iostream>
#include <fstream>
#include <sstream>
#include <regex>
#include <vector>
#include <memory>
using namespace std;

struct Node { string kind,name,type,value; vector<shared_ptr<Node>> children; };
vector<string> tokenize(const string&s){regex r(R"([\w]+|[{}();=+\-*/<>])");sregex_iterator i(s.begin(),s.end(),r),e;vector<string>v;for(;i!=e;++i)v.push_back(i->str());return v;}
shared_ptr<Node> parse_class(const vector<string>&t,size_t&i){auto n=make_shared<Node>();n->kind="Class";n->name=t[i+1];i+=2;++i;while(i<t.size()&&t[i]!="}"){if(t[i]=="int"||t[i]=="String"||t[i]=="void"){string ty=t[i++],nm=t[i++];if(t[i]=="("){auto m=make_shared<Node>();m->kind="Method";m->type=ty;m->name=nm;while(t[i]!="{")++i;++i;string b;while(t[i]!="}")b+=t[i++]+" ";++i;m->value=b;n->children.push_back(m);}else if(t[i]=="="){++i;string val=t[i++];auto v=make_shared<Node>();v->kind="Var";v->type=ty;v->name=nm;v->value=val;n->children.push_back(v);if(t[i]==";")++i;}}else ++i;}++i;return n;}
void emit_cpp(const shared_ptr<Node>&r,ostream&o){o<<"#include <iostream>\n#include <string>\nusing namespace std;\n\nstruct "<<r->name<<"{\n";for(auto&c:r->children){if(c->kind=="Var")o<<"    "<<(c->type=="String"?"string":c->type)<<" "<<c->name<<"="<<c->value<<";\n";if(c->kind=="Method")o<<"    void "<<c->name<<"(){"<<" // body: "<<c->value<<" }\n";}o<<"};\n\nint main(){ "<<r->name<<" o;o.main();return 0;}\n";}
int main(int argc,char*argv[]){if(argc<2){cerr<<"Usage: semantic_jvmfreec <file.java>\n";return 1;}ifstream f(argv[1]);stringstream b;b<<f.rdbuf();auto tok=tokenize(b.str());size_t i=0;shared_ptr<Node>r;while(i<tok.size()){if(tok[i]=="class")r=parse_class(tok,i);else ++i;}ofstream o("out.cpp");emit_cpp(r,o);cout<<"✅ out.cpp generated\n";}
