#include "P105Control.h"

#include "libb64/cencode.h"
#include "libb64/cdecode.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/cipher.h"
#include "mbedtls/pk.h"

#include "ArduinoJson.h"

namespace {

const String SESSIONID_KEY("TP_SESSIONID=");
const String TIMEOUT_KEY("TIMEOUT=");
const int SHA1_LENGTH = 20;
const char UUID[] = "74ac937ec5cbebd2cb79fec08b02ecbc47a0044a";

// Please overwrite PRIVATE_KEY and PUBLIC_KEY.
// Default keys are unsafe.
const unsigned char PRIVATE_KEY[] = R"EOF(
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDL6rXm8ezydArx27tT77WFp/0SWwJ8DMPiF/aLhjrpA1Vuk54L
56vNi6NsztSAHS5DrcyNod14KkAnPGrfiuq2ezuBomGZQl5VV6gxYVVtGqqr4/q5
tj6YqPcb7w/1gm0uOoHJdKTJ7GWtNek2C9+IGnjoens2aFQGT8MZ4ylw/wIDAQAB
AoGBALjHNJHTQzzoPkqvK+6BVmGIud/6LCQwhQfJYxVHSvZ+mNmcVii/g4S8NhiQ
yypURun5AVSOClurHXrwWn+6J7gZmMdQNhFXRAb4yxQK/r1qD9cL8iSi+9cRAKdg
nda/KUBCbZjNU1/+wO+iQVQya5rI3CfPbmn9s5FhxXIiYZ1hAkEA5hJRATuo/QGk
c6s+rHDIZd7rQMi/eicMpUn8pMxMNCnTc2mNW6vf3lmM65zEaqISt6XprM2LFs8Z
GoWoweeP6QJBAOLl0TFzLllbss9FLzz/k0u8netcdkbiVZ4HfeXKwV066qWm+gSX
Fp6Bl927VRooh2CR5k+1MsVyV6t7LDW8EKcCQHNSZwwpLXF0a0wXYBjrh2eYr28P
sPq3rB0F0v9/8AqNlJHbLKHwqww28u3+7G1Ow/cN0O1vMfLC6CBlMsvPGFECQQDZ
ajnP1nydJ17peXPQUV2E/xGbS5gSSCKeMLOUk3pBqYjafmuoJlaIP8mTsEPVsuw1
vtgfnJMv22bibD5qpvCVAkEA2e8a1mq5t0QPv/ai3kmqTcjkMEG7VvEHkaiod+ee
SaBSHcqmPot+WuNB3X76UXhct/hnBx+jHRxKfz+9fM4NeA==
-----END RSA PRIVATE KEY-----
)EOF";

const unsigned char PUBLIC_KEY[] = R"EOF(
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDL6rXm8ezydArx27tT77WFp/0S
WwJ8DMPiF/aLhjrpA1Vuk54L56vNi6NsztSAHS5DrcyNod14KkAnPGrfiuq2ezuB
omGZQl5VV6gxYVVtGqqr4/q5tj6YqPcb7w/1gm0uOoHJdKTJ7GWtNek2C9+IGnjo
ens2aFQGT8MZ4ylw/wIDAQAB
-----END PUBLIC KEY-----
)EOF";

void u8ToHex(uint8_t val, uint8_t *h, uint8_t *l){
  uint8_t hval = val >> 4;
  uint8_t lval = val & 0x0f;
  *h = hval < 10 ? hval + '0' : hval - 10 + 'a';
  *l = lval < 10 ? lval + '0' : lval - 10 + 'a';
}

// Find value corresponding to key from cookie
// example)
// cookie: String("TP_SESSIONID=359A969BAB8B728BEC8B088B4F8B358B;TIMEOUT=1440")
// key:    String("TP_SESSIONID=")
// return  String("359A969BAB8B728BEC8B088B4F8B358B");
String ParseCookie(const String &cookie, const String &key){
  auto head = cookie.indexOf(key);
  if(head < 0){
    return String();
  }

  auto tail = cookie.indexOf(';', head);
  return tail >= 0 ? cookie.substring(head + key.length(), tail) : cookie.substring(head + key.length());
}

} // anonymous namespace

//-----------------------------------------------------------------------

// Constructor fills 'm_login'.
P105Control::P105Control(const IPAddress p105_ip, const String username, const String password) {
  m_login.ip = p105_ip;

  uint8_t username_buf1[64];
  mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), (const unsigned char*)username.c_str(), username.length(), (unsigned char*)username_buf1);

  char username_buf2[SHA1_LENGTH*2];
  for(int i=0; i < SHA1_LENGTH; i++){
    uint8_t h,l;
    u8ToHex(username_buf1[i], &h, &l);
    username_buf2[2*i] = h;
    username_buf2[2*i+1] = l;
  }

  uint8_t username_buf3[64];
  auto username_buf3_len = base64_encode_chars(username_buf2, SHA1_LENGTH*2, (char *)username_buf3);
  m_login.username = String(username_buf3, username_buf3_len);

  uint8_t password_buf[64];
  auto password_buf_len = base64_encode_chars(password.c_str(), password.length(), (char *)password_buf);
  m_login.password = String(password_buf, password_buf_len);
}

P105Control::~P105Control(){}

//-----------------------------------------------------------------------

P105Control::CipherInfo P105Control::ParseKey(const String &key) {
  mbedtls_pk_context       pk;
  mbedtls_entropy_context  entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  uint8_t buf1[256];
  uint8_t buf2[256];
  size_t  buf1_len = base64_decode_chars(key.c_str(), key.length(), (char *)buf1);
  size_t  buf2_len = 0;

  mbedtls_pk_init(&pk);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
  mbedtls_pk_parse_key(&pk, PRIVATE_KEY, sizeof(PRIVATE_KEY), NULL, 0);
  mbedtls_pk_decrypt(&pk, buf1, buf1_len, buf2, &buf2_len, 256, mbedtls_ctr_drbg_random, &ctr_drbg);

  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  mbedtls_pk_free(&pk);

  CipherInfo cipherInfo;
  memcpy(cipherInfo.key, buf2,      16);
  memcpy(cipherInfo.iv,  buf2 + 16, 16);
  return cipherInfo;
}

//-----------------------------------------------------------------------

size_t P105Control::Cipher(mbedtls_operation_t operation, const uint8_t *input, size_t ilen, uint8_t *output) {
  size_t olen1, olen2;
  mbedtls_cipher_context_t cipher;
  mbedtls_cipher_init(&cipher);

  mbedtls_cipher_setup(&cipher, mbedtls_cipher_info_from_values(MBEDTLS_CIPHER_ID_AES, 128, MBEDTLS_MODE_CBC));
  mbedtls_cipher_set_padding_mode(&cipher, MBEDTLS_PADDING_PKCS7);
  mbedtls_cipher_set_iv(&cipher, m_cipher.iv, 16);
  mbedtls_cipher_setkey(&cipher, m_cipher.key, 128, operation);
  mbedtls_cipher_update(&cipher, input, ilen, output, &olen1);
  mbedtls_cipher_finish(&cipher, output + olen1, &olen2);
  mbedtls_cipher_free(&cipher);
  return olen1 + olen2;
}

//-----------------------------------------------------------------------

String P105Control::Encrypt(const String &str) {
  uint8_t buf1[1024];
  uint8_t buf2[1024];
  auto buf1_len = Cipher(MBEDTLS_ENCRYPT, (uint8_t *)str.c_str(), str.length(), buf1);
  auto buf2_len = base64_encode_chars((const char *)buf1, buf1_len, (char *)buf2);
  return String(buf2, buf2_len);
}

//-----------------------------------------------------------------------

String P105Control::Decrypt(const String &str) {
  uint8_t buf1[1024];
  uint8_t buf2[1024];
  auto buf1_len = base64_decode_chars(str.c_str(), str.length(), (char *)buf1);
  auto buf2_len = Cipher(MBEDTLS_DECRYPT, buf1, buf1_len, buf2);
  return String(buf2, buf2_len);
}

//-----------------------------------------------------------------------

P105Control::httpResponse P105Control::Request(const String &url, const String &payload) {
  int retrycount = 0;
  while(retrycount < 3){
    HTTPClient  http;
    if(!http.begin(url)){
      return httpResponse();
    }

    const static char *headers[] = {"Set-Cookie"};
    http.collectHeaders(headers, sizeof(headers) / sizeof(headers[0]));
    if (!m_session.id.isEmpty()){
      http.addHeader("Cookie", (SESSIONID_KEY + m_session.id).c_str(), false, true);
    }
    
    if(http.POST(payload) != HTTP_CODE_OK){
      http.end();
      retrycount++;
      continue;
    }

    httpResponse ret;
    ret.header_set_cookie = http.header("Set-Cookie");
    ret.body = http.getString();
    http.end();
    return ret;
  }

  return httpResponse();
}

//-----------------------------------------------------------------------

bool P105Control::HasActiveSession() {
  if(m_session.id.isEmpty() || m_session.token.isEmpty()){
    return false;
  }
  uint32_t current_ms = millis();
  const uint32_t max_uint32_t = 0xffffffff;
  uint32_t spent_ms = current_ms > m_session.start_ms ? current_ms - m_session.start_ms : max_uint32_t - m_session.start_ms + current_ms;
  return spent_ms < m_session.timeout_ms;
}

//-----------------------------------------------------------------------

bool P105Control::Handshake() {
  m_session.id.clear();
  m_session.token.clear();
  m_session.start_ms = millis();

  DynamicJsonDocument doc(1024);
  doc["method"] = "handshake";
  doc["params"]["key"] = PUBLIC_KEY;
  doc["requestTimeMils"] = millis();

  String payload;
  serializeJson(doc, payload);

  String url = String("http://") + m_login.ip.toString() + String("/app");
  auto response = Request(url, payload);
  if(response.body.isEmpty()){
    return false;
  }

  auto sessionId = ParseCookie(response.header_set_cookie, SESSIONID_KEY);
  if(sessionId.isEmpty()){
    return false;
  }
  m_session.id = sessionId;

  auto timeout   = ParseCookie(response.header_set_cookie, TIMEOUT_KEY);
  if(!timeout.isEmpty()){
    m_session.start_ms = millis();
    m_session.timeout_ms = timeout.toInt() * 1000;
  }

  DynamicJsonDocument res(1024);
  deserializeJson(res, response.body);
  int error_code = res["error_code"];
  if(error_code){
    return false;
  }

  String key = res["result"]["key"].as<String>();
  m_cipher = ParseKey(key);
  return true;
}

//-----------------------------------------------------------------------

bool P105Control::Login() {
  DynamicJsonDocument req(1024);
  req["method"] = "login_device";
  req["params"]["username"] = m_login.username.c_str();
  req["params"]["password"] = m_login.password.c_str();
  req["requestTimeMils"] = millis();
  String req_serialized;
  serializeJson(req, req_serialized);

  DynamicJsonDocument doc(1024);
  doc["method"] = "securePassthrough";
  doc["params"]["request"] = Encrypt(req_serialized);
  String payload;
  serializeJson(doc, payload);

  String url = String("http://") + m_login.ip.toString() + String("/app");
  auto response = Request(url, payload);
  if(response.body.isEmpty()){
    return false;
  }

  DynamicJsonDocument res1(1024);
  deserializeJson(res1, response.body);

  int error_code1 = res1["error_code"];
  if(error_code1){
    return false;
  }

  String result = Decrypt(res1["result"]["response"].as<String>());

  DynamicJsonDocument res2(1024);
  deserializeJson(res2, result);

  int error_code2 = res2["error_code"];
  if(error_code2){
    return false;
  }

  m_session.token = res2["result"]["token"].as<String>();
  return !m_session.token.isEmpty();
}

//-----------------------------------------------------------------------

String P105Control::GetDeviceInfo() {
  DynamicJsonDocument req(1024);
  req["method"] = "get_device_info";
  req["requestTimeMils"] = millis();
  String req_serialized;
  serializeJson(req, req_serialized);

  DynamicJsonDocument doc(1024);
  doc["method"] = "securePassthrough";
  doc["params"]["request"] = Encrypt(req_serialized);

  String payload;
  serializeJson(doc, payload);

  String url = String("http://") + m_login.ip.toString() + String("/app?token=") + m_session.token;
  auto response = Request(url, payload);
  if(response.body.isEmpty()){
    return String();
  }

  DynamicJsonDocument res(2048); // more than 1KB
  deserializeJson(res, response.body);

  int error_code = res["error_code"];
  if(error_code == 0){
    String res2 = res["result"]["response"].as<String>();
    return Decrypt(res2);
  }

  return String();
}

//-----------------------------------------------------------------------

bool P105Control::SetDeviceState(bool on) {
  DynamicJsonDocument req(1024);
  req["method"] = "set_device_info";
  req["params"]["device_on"] = on;
  req["terminalUUID"] = UUID;
  req["requestTimeMils"] = millis();
  String req_serialized;
  serializeJson(req, req_serialized);

  DynamicJsonDocument doc(1024);
  doc["method"] = "securePassthrough";
  doc["params"]["request"] = Encrypt(req_serialized);

  String payload;
  serializeJson(doc, payload);

  String url = String("http://") + m_login.ip.toString() + String("/app?token=") + m_session.token;
  auto response = Request(url, payload);
  if(response.body.isEmpty()){
    return false;
  }

  DynamicJsonDocument res(1024);
  deserializeJson(res, response.body);
  int error_code = res["error_code"];
  if (error_code == 0){
    return true;
  }

  return false;
}

