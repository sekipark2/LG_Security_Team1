#include <atlstr.h>
#include <cpprest/http_client.h>
#include <cpprest/filestream.h>

#include "RESTful.h"
#include "Resource.h"
#include "VoipVoice.h"
#include "LgVideoChatDemo.h"
#include "Crypto.h"

using namespace web;
using namespace web::http;
using namespace web::http::client;

static utility::string_t serverUri;
static utility::string_t sessionId;
static utility::string_t hashId;

int LoginFromApp(HWND hDlg)
{
    HWND hWnd;
    WCHAR uri[512];
    WCHAR buffer[512];
    json::value data;
    json::value json_return;

    hWnd = GetDlgItem(hDlg, IDC_EDIT_URI);
    GetWindowTextW(hWnd, uri, sizeof(uri));

    hWnd = GetDlgItem(hDlg, IDC_EDIT_EMAIL);
    GetWindowTextW(hWnd, buffer, sizeof(buffer));
    data[U("email")] = json::value::string(buffer, false);

    hWnd = GetDlgItem(hDlg, IDC_EDIT_PASSWORD);
    GetWindowTextW(hWnd, buffer, sizeof(buffer));
    data[U("password")] = json::value::string(buffer, false);

    hWnd = GetDlgItem(hDlg, IDC_EDIT_TOKEN);
    GetWindowTextW(hWnd, buffer, sizeof(buffer));
    data[U("token")] = json::value::string(buffer, false);

    hWnd = GetDlgItem(hDlg, IDC_EDIT_IP);
    GetWindowTextW(hWnd, buffer, sizeof(buffer));
    data[U("ip_address")] = json::value::string(buffer, false);

    std::string b64_enc_key;
    GetEncodedPublicKey(b64_enc_key);
    data[U("rsa_public_key")] = json::value::string(utility::conversions::to_string_t(b64_enc_key));
    std::cout << "@@@ ENC value : " << utility::conversions::to_utf8string(data[U("rsa_public_key")].as_string()) << std::endl;

    try
    {
        http_client_config config;
        config.set_validate_certificates(false);

        http_client client(uri, config);

        client.request(methods::POST, U("/login_from_app"), data.serialize(), U("application/json"))
            .then([](http_response response)
        {
            if (response.status_code() == status_codes::OK)
            {
                return response.extract_json();
            }
            else
            {
                throw std::runtime_error("HTTP request failed");
            }
        })
            .then([&json_return](json::value responseBody)
        {
            json_return = responseBody;
        })
            .wait();
    }
    catch (const std::exception& e)
    {
        CString cstring(e.what());
        MessageBox(hDlg,
            cstring, U("Login Failed"),
            MB_ICONEXCLAMATION | MB_OK);
        return -1;
    }

    int errorCode = json_return[U("errorCode")].as_integer();
    if (errorCode == 0)
    {
        serverUri = uri;
        sessionId = json_return[U("session_id")].as_string();
        hashId = json_return[U("hash_id")].as_string();
    }
    else
    {
        MessageBox(hDlg,
            json_return[U("msg")].as_string().c_str(), U("Login Failed"),
            MB_ICONEXCLAMATION | MB_OK);
        return 1;
    }

    return 0;
}

typedef struct
{
    utility::string_t name;
    utility::string_t ip;
} CONTACT;

static std::vector<CONTACT> contacts;

int Contacts(HWND hDlg)
{
    json::value data;
    json::value json_return;

    contacts.clear();

    data[U("hash_id")] = json::value::string(hashId);
    data[U("session")] = json::value::string(sessionId);

    try
    {
        http_client_config config;
        config.set_validate_certificates(false);

        http_client client(serverUri, config);

        client.request(methods::POST, U("/contacts"), data.serialize(), U("application/json"))
            .then([](http_response response)
        {
            if (response.status_code() == status_codes::OK)
            {
                return response.extract_json();
            }
            else
            {
                throw std::runtime_error("HTTP request failed");
            }
        })
            .then([&json_return](json::value responseBody)
        {
            json_return = responseBody;
        })
            .wait();
    }
    catch (const std::exception& e)
    {
        std::cout << "Error: " << e.what() << std::endl;
        return -1;
    }

    int errorCode = json_return[U("errorCode")].as_integer();
    if (errorCode != 0)
    {
        return -1;
    }

    json::array array = json_return[U("msg")].as_array();
    HWND hWnd = GetDlgItem(hDlg, IDC_LIST_CONTACTS);
    for (json::array::iterator it = array.begin(); it != array.end(); ++it)
    {
        json::value data = *it;

        if (!data[U("is_server")].as_bool())
        {
            continue;
        }

        CONTACT contact;
        contact.name = data[U("first_name")].as_string() + U(" ") + data[U("last_name")].as_string()
            + U(" (") + data[U("email")].as_string() + U(")");
        contact.ip = data[U("ip_address")].as_string();

        int pos = SendMessage(hWnd, LB_ADDSTRING, 0, (LPARAM)contact.name.c_str());
        SendMessage(hWnd, LB_SETITEMDATA, pos, (LPARAM)contacts.size());

        contacts.push_back(contact);
    }

    return 0;
}

const char* GetContactIp(int index)
{
    const WCHAR* ip = contacts.at(index).ip.c_str();
    CStringA cstring(ip);
    return cstring.GetBuffer();
}

int SetServer(bool isServer)
{
    json::value data;
    json::value json_return;

    data[U("hash_id")] = json::value::string(hashId);
    data[U("session")] = json::value::string(sessionId);
    data[U("is_server")] = json::value::boolean(isServer);

    try
    {
        http_client_config config;
        config.set_validate_certificates(false);

        http_client client(serverUri, config);

        client.request(methods::POST, U("/set_server"), data.serialize(), U("application/json"))
            .then([](http_response response)
        {
            if (response.status_code() == status_codes::OK)
            {
                return response.extract_json();
            }
            else
            {
                throw std::runtime_error("HTTP request failed");
            }
        })
            .then([&json_return](json::value responseBody)
        {
            json_return = responseBody;
        })
            .wait();
    }
    catch (const std::exception& e)
    {
        std::cout << "Error: " << e.what() << std::endl;
        return -1;
    }

    int errorCode = json_return[U("errorCode")].as_integer();
    if (errorCode != 0)
    {
        return -1;
    }

    return 0;
}
