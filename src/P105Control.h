// P105Control class controls TP-Link P105 Smart plug.
// This class could spend much time because of blocking communication.
//
// Usage:
// 1. Create an instance
//   P105Control p105(IPAddress(192,168,xxx,xxx), "username@mail.com", "password");
// 2. Handshake and login to create a session
//   p105.Handshake();
//   p105.Login();
// 3. Call APIs
//   p105.SetDeviceState(true);
// 4. Reconnect
// // Please check validity of the session if an application keeps connection long time (>24min.)
//   if(!p105.HasActiveSession()){
//     p105.Handshake();
//     p105.Login();
//   }
//
// DeviceInfo example:
//   {
//     "error_code": 0,
//     "result": {
//       "device_id": "6C885191F528F4F0902C8E649D57A7D669372170",
//       "fw_ver": "1.x.x Build 2023xxxx Rel. xxxxx",
//       "hw_ver": "1.x.x",
//       "type": "SMART.TAPOPLUG",
//       "model": "P105",
//       "mac": "XX-XX-XX-XX-XX-XX",
//       "hw_id": "49D1A268E029E0B6d4CB00DDE21D6FC0",
//       "fw_id": "AFA7FB61578BF6175835058AF4A78F88",
//       "oem_id": "311829EC8CB33BD720A1C40B7C6E8491",
//       "specs": "JP",
//       "device_on": false,
//       "on_time": 0,
//       "overheated": false,
//       "nickname": "44K544Oe44O844OI44OX44Op44Kw",
//       "location": "",
//       "avatar": "plug",
//       "longitude": 1234567,
//       "latitude": 345678,
//       "has_set_location_info": true,
//       "ip": "192.168.xxx.xxx",
//       "ssid": "Nqlzixwq2Vc9gkJ3dXY=",
//       "signal_level": 2,
//       "rssi": -64,
//       "region": "Asia/Tokyo",
//       "time_diff": 540,
//       "lang": "ja_JP",
//       "default_states": {
//         "type": "last_states",
//         "state": {}
//       },
//       "auto_off_status": "off",
//       "auto_off_remain_time": 0
//     }
//   }
//
// Communication Sequence:
//   P105      Client
//    | handshake |
//    |<----------| ; key
//    |---------->| ; key, sessionID and timeout
//    |           |
//    |   login   |
//    |<----------| ; username(sha1), password and sessionID
//    |---------->| ; token
//    |           |
//    | API calls |
//    |<----------| ; token
//    |---------->|
//    |    ...    |

#include "HTTPClient.h"
#include "mbedtls/cipher.h"

class P105Control {

public:
  P105Control() = delete;
  P105Control(const IPAddress p105_ip, const String username, const String password);
  ~P105Control();

  bool HasActiveSession();

  /// @return true if succeeded
  bool Handshake();

  /// @return true if succeeded
  bool Login();

  /// @return true if succeeded
  bool SetDeviceState(bool on);

  /// @return DeviceInfo json formatted
  String GetDeviceInfo();

private:
  struct httpResponse{
    String    header_set_cookie;
    String    body;
  };

  struct SessionInfo {
    String    id;
    String    token;
    uint32_t  timeout_ms = 1440 * 1000;
    uint32_t  start_ms = 0;
  };
  
  struct LoginInfo {
    IPAddress ip;
    String    username;
    String    password;
  };

  struct CipherInfo {
    uint8_t   key[16];
    uint8_t   iv[16];
  };

  CipherInfo ParseKey(const String &key);
  size_t Cipher(mbedtls_operation_t operation, const uint8_t *input, size_t ilen, uint8_t *output);

  // length of str must be 1K or less.
  String Encrypt(const String &str);
  String Decrypt(const String &str);
  httpResponse Request(const String &url, const String &payload);

private:
  // 'm_login' holds parameters to login to P105
  // username and password are not plain text.
  LoginInfo m_login;

  // 'm_session' holds parameters to keep a session with P105
  SessionInfo m_session;

  // 'm_cipher' holds parameters to encrypt/decrypt strings
  CipherInfo m_cipher;

};
