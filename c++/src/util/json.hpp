#ifndef R2P_UTIL_JSON_HPP
#define R2P_UTIL_JSON_HPP

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace r2p {

class Json {
public:
    enum Type { kNull, kBool, kInt, kString, kArray, kObject };

    Json() : type_(kNull), bool_val_(false), int_val_(0) {}
    static Json make_null() { return Json(); }
    static Json make_bool(bool v) {
        Json j;
        j.type_ = kBool;
        j.bool_val_ = v;
        return j;
    }
    static Json make_int(int64_t v) {
        Json j;
        j.type_ = kInt;
        j.int_val_ = v;
        return j;
    }
    static Json make_string(const std::string& v) {
        Json j;
        j.type_ = kString;
        j.str_val_ = v;
        return j;
    }
    static Json make_array() {
        Json j;
        j.type_ = kArray;
        return j;
    }
    static Json make_object() {
        Json j;
        j.type_ = kObject;
        return j;
    }

    Type type() const { return type_; }
    bool is_null() const { return type_ == kNull; }
    bool is_bool() const { return type_ == kBool; }
    bool is_int() const { return type_ == kInt; }
    bool is_string() const { return type_ == kString; }
    bool is_array() const { return type_ == kArray; }
    bool is_object() const { return type_ == kObject; }

    bool as_bool(bool def = false) const { return type_ == kBool ? bool_val_ : def; }
    int64_t as_int(int64_t def = 0) const { return type_ == kInt ? int_val_ : def; }
    const std::string& as_string() const { return str_val_; }
    const std::vector<Json>& as_array() const { return arr_val_; }
    std::vector<Json>& as_array() { return arr_val_; }
    const std::map<std::string, Json>& as_object() const { return obj_val_; }
    std::map<std::string, Json>& as_object() { return obj_val_; }

    const Json* get(const std::string& key) const {
        if (type_ != kObject) return nullptr;
        std::map<std::string, Json>::const_iterator it = obj_val_.find(key);
        return (it == obj_val_.end()) ? nullptr : &it->second;
    }

    void push(const Json& v) {
        if (type_ == kArray) arr_val_.push_back(v);
    }

    void set(const std::string& key, const Json& v) {
        if (type_ == kObject) obj_val_[key] = v;
    }

    // Compact RFC 8259 dump (no spaces, UTF-8 preserved — matches NIP-01 serialization).
    std::string dump_compact() const;
    // Pretty-printed JSON with 2-space indent (for config.json / encodings.json).
    std::string dump_pretty(int indent = 0) const;

    static bool parse(const std::string& text, Json& out);

private:
    Type type_;
    bool bool_val_;
    int64_t int_val_;
    std::string str_val_;
    std::vector<Json> arr_val_;
    std::map<std::string, Json> obj_val_;
};

}  // namespace r2p

#endif
