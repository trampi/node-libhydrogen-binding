std::string get_constructor_name(v8::Local<v8::Value> val);
std::string local_string_to_string(v8::MaybeLocal<v8::String> val);
void dbg(void* arr, size_t len, char* text);
