#include <atlstr.h>
#include <cpprest/http_client.h>
#include <cpprest/filestream.h>

#include "RESTful.h"
#include "Resource.h"
#include "VoipVoice.h"
#include "LgVideoChatDemo.h"

using namespace web;
using namespace web::http;
using namespace web::http::client;

static utility::string_t serverUri;
static utility::string_t email;
static utility::string_t sessionId;

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
        std::cout << "Error: " << e.what() << std::endl;
        return -1;
    }

    int errorCode = json_return[U("errorCode")].as_integer();
    if (errorCode == 0)
    {
        serverUri = uri;
        email = data[U("email")].as_string();
        sessionId = json_return[U("session_id")].as_string();
    }
    SendMessage(hWndMain, WM_LOGIN, (WPARAM)errorCode, 0);

    return 0;
}

typedef struct
{
    utility::string_t email;
    utility::string_t ip;
} CONTACT;

static std::vector<CONTACT> contacts;

int Contacts(HWND hDlg)
{
    json::value json_return;

    contacts.clear();

    try
    {
        http_client_config config;
        config.set_validate_certificates(false);

        http_client client(serverUri, config);

        uri_builder builder(U("/contacts"));
        builder.append_query(U("email"), email);
        builder.append_query(U("session_id"), sessionId);

        client.request(methods::GET, builder.to_string())
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
        CONTACT contact;
        contact.email = data[U("email")].as_string();
        contact.ip = data[U("ip_address")].as_string();

        int pos = SendMessage(hWnd, LB_ADDSTRING, 0, (LPARAM)contact.email.c_str());
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
