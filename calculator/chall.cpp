#include <iostream>
#include <unordered_map>
#include <string>
#include <algorithm>

class Int128 {
public:
    __int128 v;
    Int128(__int128 x = 0) : v(x) {}

    static Int128 fromstring(const std::string& s) {
        __int128 val = 0;
        for (char c : s) val = val * 10 + (c - '0');
        return Int128(val);
    }

    std::string tostring() const {
        if (v == 0) return "0";
        __int128 x = v;
        bool neg = false;
        if (x < 0) { neg = true; x = -x; }
        std::string s;
        while (x) { s.push_back('0' + x % 10); x /= 10; }
        if (neg) s.push_back('-');
        reverse(s.begin(), s.end());
        return s;
    }

    Int128 operator+(const Int128& o) const { return Int128(v + o.v); }
    Int128 operator-(const Int128& o) const { return Int128(v - o.v); }
    Int128 operator*(const Int128& o) const { return Int128(v * o.v); }
    Int128 operator/(const Int128& o) const {
        if (o.v == 0) throw std::runtime_error("Division by zero");
        return Int128(v / o.v);
    }
};


enum class Op { ADD, SUB, MUL, DIV };

std::unordered_map<std::string, size_t> memo;
std::vector<Int128> memo_vec;

size_t getMemo(const std::string& s) {
    if (!memo.count(s))
        memo[s] = memo_vec.size();
    memo_vec.push_back(0);
    return memo[s];
}

bool isNumber(const std::string& s) {
    for (char c : s) if (!isdigit(c)) return false;
    return true;
}

Int128 eval(const std::string& L, Op op, const std::string& R, Int128& memo_l, Int128& memo_r);

Int128 evalAtom(const std::string& s, Int128& memo_s) {
    if (isNumber(s)) {
        memo_s = Int128::fromstring(s);
        return memo_s;
    }

    // find lowest-precedence operator from right
    int best = -1, prec = 10;
    for (int i = 0; i < s.size(); i++) {
        int p = (s[i]=='+'||s[i]=='-') ? 1 :
                (s[i]=='*'||s[i]=='/') ? 2 : 100;
        if (p <= prec) { prec = p; best = i; }
    }

    if (best == -1) {
        throw std::runtime_error("Bad expression");
    }

    std::string L = s.substr(0, best);
    L.erase(remove_if(L.begin(), L.end(), ::isspace), L.end());
    std::string R = s.substr(best+1);
    R.erase(remove_if(R.begin(), R.end(), ::isspace), R.end());

    Op op = (s[best] == '+') ? Op::ADD :
            (s[best] == '-') ? Op::SUB :
            (s[best] == '*') ? Op::MUL : Op::DIV;

    memo_s = eval(L, op, R, memo_vec[getMemo(L)], memo_vec[getMemo(R)]);
    return memo_s;
}

Int128 eval(const std::string& L, Op op, const std::string& R, Int128& memo_l, Int128& memo_r) {
    if (memo_l.v == 0)
        memo_l = evalAtom(L, memo_l);
    if (memo_r.v == 0)
        memo_r = evalAtom(R, memo_r);
    Int128 res;
    if (op == Op::ADD) res = memo_l + memo_r;
    else if (op == Op::SUB) res = memo_l - memo_r;
    else if (op == Op::MUL) res = memo_l * memo_r;
    else res = memo_l / memo_r;

    return res;
}

int main() {
    setvbuf(stdin,NULL,_IONBF,0);
    setvbuf(stdout,NULL,_IONBF,0);

    while (true) {
        std::string s;
        std::cout << "Enter expression (or quit): ";
        getline(std::cin, s);
        if (s == "quit") {
            std::cout << "Bye!" << std::endl;
            return 0;
        }
        if (s == "reset") {
            memo = std::unordered_map<std::string, size_t>();
            memo_vec = std::vector<Int128>();
            continue;
        }
        try {
            std::string res = evalAtom(s, memo_vec[getMemo(s)]).tostring();
            std::cout << "Result = " << res << std::endl;
        } catch (std::exception& e) {
            std::cout << "Error: " << e.what() << std::endl;
        }
    }
}