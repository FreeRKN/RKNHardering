#include "native_curl_probe.h"

#include <curl/curl.h>
#include <jni.h>

#include <cctype>
#include <mutex>
#include <sstream>
#include <string>
#include <algorithm>
#include <vector>

namespace {

constexpr jint kResultSize = 6;

struct CurlExecutionResult {
  CURLcode curl_code = CURLE_OK;
  long http_code = 0;
  std::string body;
  std::string error_buffer;
  std::string resolved_addresses_csv;
  std::string local_error;
};

std::once_flag g_curl_init_once;

void EnsureCurlGlobalInit() {
  std::call_once(g_curl_init_once, []() { curl_global_init(CURL_GLOBAL_DEFAULT); });
}

std::string JStringToStdString(JNIEnv* env, jstring value) {
  if (value == nullptr) {
    return {};
  }
  const char* chars = env->GetStringUTFChars(value, nullptr);
  if (chars == nullptr) {
    return {};
  }
  std::string result(chars);
  env->ReleaseStringUTFChars(value, chars);
  return result;
}

void SetArrayValue(JNIEnv* env, jobjectArray array, jsize index, const std::string& value) {
  if (value.empty()) {
    return;
  }
  jstring string_value = env->NewStringUTF(value.c_str());
  env->SetObjectArrayElement(array, index, string_value);
  env->DeleteLocalRef(string_value);
}

size_t WriteCallback(char* ptr, size_t size, size_t nmemb, void* userdata) {
  auto* output = reinterpret_cast<std::string*>(userdata);
  output->append(ptr, size * nmemb);
  return size * nmemb;
}

long CurlIpResolveMode(jint mode) {
  switch (mode) {
    case 1:
      return CURL_IPRESOLVE_V4;
    case 2:
      return CURL_IPRESOLVE_V6;
    default:
      return CURL_IPRESOLVE_WHATEVER;
  }
}

long CurlProxyType(jint mode) {
  switch (mode) {
    case 1:
      return CURLPROXY_HTTP;
    case 2:
      return CURLPROXY_SOCKS5_HOSTNAME;
    default:
      return CURLPROXY_HTTP;
  }
}

std::string NormalizeMethod(const std::string& method) {
  if (method.empty()) {
    return "GET";
  }
  std::string normalized = method;
  std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](unsigned char ch) {
    return static_cast<char>(std::toupper(ch));
  });
  return normalized;
}

std::string AddressesFromResolveRule(const std::string& rule) {
  const size_t first = rule.find(':');
  if (first == std::string::npos) {
    return {};
  }
  const size_t second = rule.find(':', first + 1);
  if (second == std::string::npos || second + 1 >= rule.size()) {
    return {};
  }
  return rule.substr(second + 1);
}

CurlExecutionResult ExecuteRequest(
    const std::string& url,
    const std::string& interface_name,
    const std::string& method,
    const std::vector<std::string>& headers,
    const std::string& body,
    bool follow_redirects,
    const std::string& proxy_url,
    jint proxy_type,
    const std::vector<std::string>& resolve_rules,
    jint ip_resolve_mode,
    jint timeout_ms,
    jint connect_timeout_ms,
    const std::string& ca_bundle_path,
    bool debug_verbose) {
  CurlExecutionResult result;

  if (url.empty()) {
    result.local_error = "url is empty";
    return result;
  }
  if (ca_bundle_path.empty()) {
    result.local_error = "caBundlePath is empty";
    return result;
  }

  EnsureCurlGlobalInit();

  CURL* handle = curl_easy_init();
  if (handle == nullptr) {
    result.local_error = "curl_easy_init failed";
    return result;
  }

  curl_slist* resolve_list = nullptr;
  curl_slist* header_list = nullptr;
  for (const std::string& rule : resolve_rules) {
    resolve_list = curl_slist_append(resolve_list, rule.c_str());
    if (result.resolved_addresses_csv.empty()) {
      result.resolved_addresses_csv = AddressesFromResolveRule(rule);
    }
  }
  for (const std::string& header : headers) {
    header_list = curl_slist_append(header_list, header.c_str());
  }

  char error_buffer[CURL_ERROR_SIZE] = {0};
  std::string response_body;
  const std::string normalized_method = NormalizeMethod(method);
  const std::string interface_option = interface_name.empty() ? "" : "if!" + interface_name;

  curl_easy_setopt(handle, CURLOPT_URL, url.c_str());
  curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, follow_redirects ? 1L : 0L);
  curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(handle, CURLOPT_TIMEOUT_MS, static_cast<long>(timeout_ms));
  curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(connect_timeout_ms));
  curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, WriteCallback);
  curl_easy_setopt(handle, CURLOPT_WRITEDATA, &response_body);
  curl_easy_setopt(handle, CURLOPT_ERRORBUFFER, error_buffer);
  curl_easy_setopt(handle, CURLOPT_CAINFO, ca_bundle_path.c_str());
  curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 2L);
  curl_easy_setopt(handle, CURLOPT_IPRESOLVE, CurlIpResolveMode(ip_resolve_mode));
  curl_easy_setopt(handle, CURLOPT_VERBOSE, debug_verbose ? 1L : 0L);
  if (!interface_option.empty()) {
    curl_easy_setopt(handle, CURLOPT_INTERFACE, interface_option.c_str());
  }
  if (header_list != nullptr) {
    curl_easy_setopt(handle, CURLOPT_HTTPHEADER, header_list);
  }

  if (normalized_method == "GET") {
    curl_easy_setopt(handle, CURLOPT_HTTPGET, 1L);
  } else if (normalized_method == "POST") {
    curl_easy_setopt(handle, CURLOPT_POST, 1L);
    curl_easy_setopt(handle, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
  } else {
    curl_easy_setopt(handle, CURLOPT_CUSTOMREQUEST, normalized_method.c_str());
    if (!body.empty()) {
      curl_easy_setopt(handle, CURLOPT_POSTFIELDS, body.c_str());
      curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
    }
  }

  if (!proxy_url.empty()) {
    curl_easy_setopt(handle, CURLOPT_PROXY, proxy_url.c_str());
    curl_easy_setopt(handle, CURLOPT_PROXYTYPE, CurlProxyType(proxy_type));
  } else {
    curl_easy_setopt(handle, CURLOPT_PROXY, "");
    curl_easy_setopt(handle, CURLOPT_NOPROXY, "*");
  }

  if (resolve_list != nullptr) {
    curl_easy_setopt(handle, CURLOPT_RESOLVE, resolve_list);
  }

  result.curl_code = curl_easy_perform(handle);
  curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &result.http_code);

  char* primary_ip = nullptr;
  if (curl_easy_getinfo(handle, CURLINFO_PRIMARY_IP, &primary_ip) == CURLE_OK &&
      primary_ip != nullptr && result.resolved_addresses_csv.empty()) {
    result.resolved_addresses_csv = primary_ip;
  }

  result.body = response_body;
  result.error_buffer = error_buffer;
  if (result.error_buffer.empty() && result.curl_code != CURLE_OK) {
    result.error_buffer = curl_easy_strerror(result.curl_code);
  }

  curl_slist_free_all(header_list);
  curl_slist_free_all(resolve_list);
  curl_easy_cleanup(handle);
  return result;
}

}  // namespace

jobjectArray ExecuteNativeCurlRequest(
    JNIEnv* env,
    jstring url,
    jstring interface_name,
    jstring method,
    jobjectArray headers,
    jstring body,
    jboolean follow_redirects,
    jstring proxy_url,
    jint proxy_type,
    jobjectArray resolve_rules,
    jint ip_resolve_mode,
    jint timeout_ms,
    jint connect_timeout_ms,
    jstring ca_bundle_path,
    jboolean debug_verbose) {
  std::vector<std::string> parsed_rules;
  std::vector<std::string> parsed_headers;
  if (headers != nullptr) {
    const jsize header_count = env->GetArrayLength(headers);
    parsed_headers.reserve(static_cast<size_t>(header_count));
    for (jsize index = 0; index < header_count; ++index) {
      auto* header = static_cast<jstring>(env->GetObjectArrayElement(headers, index));
      parsed_headers.push_back(JStringToStdString(env, header));
      env->DeleteLocalRef(header);
    }
  }
  if (resolve_rules != nullptr) {
    const jsize rule_count = env->GetArrayLength(resolve_rules);
    parsed_rules.reserve(static_cast<size_t>(rule_count));
    for (jsize index = 0; index < rule_count; ++index) {
      auto* rule = static_cast<jstring>(env->GetObjectArrayElement(resolve_rules, index));
      parsed_rules.push_back(JStringToStdString(env, rule));
      env->DeleteLocalRef(rule);
    }
  }

  const CurlExecutionResult result = ExecuteRequest(
      JStringToStdString(env, url),
      JStringToStdString(env, interface_name),
      JStringToStdString(env, method),
      parsed_headers,
      JStringToStdString(env, body),
      follow_redirects == JNI_TRUE,
      JStringToStdString(env, proxy_url),
      proxy_type,
      parsed_rules,
      ip_resolve_mode,
      timeout_ms,
      connect_timeout_ms,
      JStringToStdString(env, ca_bundle_path),
      debug_verbose == JNI_TRUE);

  jclass string_class = env->FindClass("java/lang/String");
  jobjectArray output = env->NewObjectArray(kResultSize, string_class, nullptr);
  SetArrayValue(env, output, 0, result.curl_code == CURLE_OK ? "0" : std::to_string(result.curl_code));
  SetArrayValue(env, output, 1, result.http_code > 0 ? std::to_string(result.http_code) : "");
  SetArrayValue(env, output, 2, result.body);
  SetArrayValue(env, output, 3, result.error_buffer);
  SetArrayValue(env, output, 4, result.resolved_addresses_csv);
  SetArrayValue(env, output, 5, result.local_error);
  return output;
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_notcvnt_rknhardering_probe_NativeCurlBridge_nativeExecuteRaw(
    JNIEnv* env,
    jobject /* this */,
    jstring url,
    jstring interface_name,
    jstring method,
    jobjectArray headers,
    jstring body,
    jboolean follow_redirects,
    jstring proxy_url,
    jint proxy_type,
    jobjectArray resolve_rules,
    jint ip_resolve_mode,
    jint timeout_ms,
    jint connect_timeout_ms,
    jstring ca_bundle_path,
    jboolean debug_verbose) {
  return ExecuteNativeCurlRequest(
      env,
      url,
      interface_name,
      method,
      headers,
      body,
      follow_redirects,
      proxy_url,
      proxy_type,
      resolve_rules,
      ip_resolve_mode,
      timeout_ms,
      connect_timeout_ms,
      ca_bundle_path,
      debug_verbose);
}
