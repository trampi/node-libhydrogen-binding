#include <nan.h>

#include "binding.h"

using namespace v8;

extern "C" {
  #include "hydrogen.c"
}

NAN_METHOD(_hydro_init) {
  info.GetReturnValue().Set(hydro_init());
}

NAN_METHOD(_hydro_random_u32) {
  info.GetReturnValue().Set(hydro_random_u32());
}

NAN_METHOD(_hydro_random_uniform) {
  Isolate* isolate = info.GetIsolate();
  if (info.Length() != 1) {
    isolate->ThrowException(Nan::TypeError(
        String::NewFromUtf8(isolate, "Wrong number of arguments, expected one")));
    return;
  }

  if (!info[0]->IsNumber()) {
    isolate->ThrowException(Nan::TypeError(
          String::NewFromUtf8(isolate, "expected a number")));
    return;
  }

  info.GetReturnValue().Set(hydro_random_uniform(info[0]->NumberValue()));
}

NAN_METHOD(_hydro_secretbox_keygen) {
  uint8_t * key = new uint8_t[hydro_secretbox_KEYBYTES];
  hydro_secretbox_keygen(key);
  auto result = Nan::NewBuffer((char*) key, hydro_secretbox_KEYBYTES).ToLocalChecked();
  info.GetReturnValue().Set(result);
}

NAN_GETTER(_hydro_secretbox_KEYBYTES) {
  info.GetReturnValue().Set(hydro_secretbox_KEYBYTES);
}

NAN_METHOD(_hydro_secretbox_encrypt) {
  Isolate* isolate = info.GetIsolate();

  // message, key, msgId, context

  if (info.Length() != 4) {
    isolate->ThrowException(Nan::TypeError(
        String::NewFromUtf8(isolate, "Wrong number of arguments, expected 4")));
    return;
  }

  if (!info[0]->IsString()) { // TODO: not only strings
    isolate->ThrowException(Nan::TypeError(
          String::NewFromUtf8(isolate, "expected message to be a string")));
    return;
  }

  if (!info[1]->IsUint8Array()) {
    const char* error = std::string("expected key to be a Uint8Array, got '" + get_constructor_name(info[1]) + "'").c_str();
    isolate->ThrowException(Nan::TypeError(
          String::NewFromUtf8(isolate, error)));
    return;
  }

  if (!info[2]->IsNumber()) {
    isolate->ThrowException(Nan::TypeError(
          String::NewFromUtf8(isolate, "expected msgid to be a number")));
    return;
  }

  if (!info[3]->IsString()) {
    const char* error = std::string("expected context to be a string, got " + get_constructor_name(info[3])).c_str();
    isolate->ThrowException(Nan::TypeError(
          String::NewFromUtf8(isolate, error)));
    return;
  }


  std::string message = local_string_to_string(info[0]->ToString());

  Local<Uint8Array> keyLocal = info[1].As<Uint8Array>();
  Nan::TypedArrayContents<uint8_t> keyBuffer(keyLocal);
  if (keyBuffer.length() != hydro_secretbox_KEYBYTES) {
    isolate->ThrowException(Nan::TypeError(
          String::NewFromUtf8(isolate, "illegal key, size mismatch")));
  }

  uint64_t msgid = info[2]->NumberValue();
  std::string context = local_string_to_string(info[3]->ToString());

  if (context.length() != hydro_secretbox_CONTEXTBYTES) {
    const char* error = std::string("invalid context length").c_str();
    isolate->ThrowException(Nan::TypeError(
          String::NewFromUtf8(isolate, error)));
    return;
  }


  size_t ciphertext_len = hydro_secretbox_HEADERBYTES + message.length();
  uint8_t * ciphertext = new uint8_t[ciphertext_len];
  hydro_secretbox_encrypt(ciphertext, message.c_str(), message.length(), msgid, context.c_str(), *keyBuffer);

  auto result = Nan::NewBuffer((char*) ciphertext, ciphertext_len).ToLocalChecked();
  info.GetReturnValue().Set(result);
}

NAN_METHOD(_hydro_secretbox_decrypt) {
  Isolate* isolate = info.GetIsolate();

  // ciphertext, key, msgId, context

  if (info.Length() != 4) {
    isolate->ThrowException(Nan::TypeError(
        String::NewFromUtf8(isolate, "Wrong number of arguments, expected 4")));
    return;
  }

  if (!info[0]->IsUint8Array()) {
    const char* error = std::string("expected ciphertext to be a Uint8Array, got '" + get_constructor_name(info[0]) + "'").c_str();
    isolate->ThrowException(Nan::TypeError(
          String::NewFromUtf8(isolate, error)));
    return;
  }

  if (!info[1]->IsUint8Array()) {
    const char* error = std::string("expected key to be a Uint8Array, got '" + get_constructor_name(info[1]) + "'").c_str();
    isolate->ThrowException(Nan::TypeError(
          String::NewFromUtf8(isolate, error)));
    return;
  }

  if (!info[2]->IsNumber()) {
    isolate->ThrowException(Nan::TypeError(
          String::NewFromUtf8(isolate, "expected msgid to be a number")));
    return;
  }

  if (!info[3]->IsString()) {
    const char* error = std::string("expected context to be a string, got " + get_constructor_name(info[3])).c_str();
    isolate->ThrowException(Nan::TypeError(
          String::NewFromUtf8(isolate, error)));
    return;
  }

  Local<Uint8Array> ciphertextLocal = info[0].As<Uint8Array>();
  Nan::TypedArrayContents<uint8_t> ciphertext(ciphertextLocal);

  Local<Uint8Array> keyLocal = info[1].As<Uint8Array>();
  Nan::TypedArrayContents<uint8_t> keyBuffer(keyLocal);
  if (keyBuffer.length() != hydro_secretbox_KEYBYTES) {
    isolate->ThrowException(Nan::TypeError(
          String::NewFromUtf8(isolate, "illegal key, size mismatch")));
  }

  uint64_t msgid = info[2]->NumberValue();
  std::string context = local_string_to_string(info[3]->ToString());

  if (context.length() != hydro_secretbox_CONTEXTBYTES) {
    const char* error = std::string("invalid context length").c_str();
    isolate->ThrowException(Nan::TypeError(
          String::NewFromUtf8(isolate, error)));
    return;
  }

  size_t decrypted_len = ciphertext.length() - hydro_secretbox_HEADERBYTES;
  uint8_t * decrypted = new uint8_t[decrypted_len + 1];

  if (hydro_secretbox_decrypt(decrypted, *ciphertext, ciphertext.length(), msgid, context.c_str(), *keyBuffer) != 0) {
      isolate->ThrowException(Nan::TypeError(
            String::NewFromUtf8(isolate, "message forged")));
      return;
  }

  std::string resultstr((char*) decrypted, decrypted_len);
  info.GetReturnValue().Set(String::NewFromUtf8(isolate, resultstr.c_str()));
}

NAN_MODULE_INIT(Initialize) {
  Nan::Export(target, "init", _hydro_init);
  Nan::Export(target, "random_u32", _hydro_random_u32);
  Nan::Export(target, "random_uniform", _hydro_random_uniform);
  Nan::Export(target, "secretbox_keygen", _hydro_secretbox_keygen);
  Nan::SetAccessor(target, Nan::New("secretbox_keybytes_size").ToLocalChecked(), _hydro_secretbox_KEYBYTES);
  Nan::Export(target, "secretbox_encrypt", _hydro_secretbox_encrypt);
  Nan::Export(target, "secretbox_decrypt", _hydro_secretbox_decrypt);
}

NODE_MODULE(libhydrogennative, Initialize)

std::string get_constructor_name(v8::Local<v8::Value> val) {
  if (val->IsExternal()) {
     return "(external)";
  } else if(val->IsNull()) {
     return "(null)";
  } else if(val->IsUndefined()) {
    return "(undefined)";
  } else if(val->IsObject()) {
    auto constructorV8String = val->ToObject()->GetConstructorName();
    auto constructorName = local_string_to_string(constructorV8String);
    return constructorName;
  } else {
    return "unknown, possible primitive"; // TOOD
  }
}

std::string local_string_to_string(Local<String> val) {
    String::Utf8Value utf8value(val);
    return std::string(*utf8value);
}

void dbg(void* arr, size_t len, char* text) {
  printf("{ %s: ", text);
  for (int i = 0; i < len; i++) {
    printf("%02x ", ((uint8_t*)arr)[i]);
  }
  printf("}\n\n");
}
