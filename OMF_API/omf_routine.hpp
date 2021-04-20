#ifndef OMF_ROUTINE_HPP
#define OMF_ROUTINE_HPP

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/json.hpp>
#include <boost/algorithm/string.hpp>
#include <cppcodec/base64_rfc4648.hpp>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <string>
#include <ctime>
#include <map>

#define OMFVERSION "1.1"
#define TYPE_OCS "OCS"
#define TYPE_EDS "EDS"
#define TYPE_PI "PI"

namespace beast = boost::beast;          // from <boost/beast.hpp>
namespace http = beast::http;            // from <boost/beast/http.hpp>
namespace net = boost::asio;             // from <boost/asio.hpp>
namespace ssl = net::ssl;                // from <boost/asio/ssl.hpp>
namespace json = boost::json;            // from <boost/json.hpp>
using tcp = net::ip::tcp;                // from <boost/asio/ip/tcp.hpp>
using base64 = cppcodec::base64_rfc4648; // from <cppcodec/base64_rfc4648.hpp>

enum ENDPOINTS { OCS, EDS, PI };

json::value httpRequest(http::verb verb, std::string endpoint, std::map<std::string, std::string> request_headers = {}, std::string request_body = "", std::map<http::field, std::string> authentication = {});

json::value httpsRequest(http::verb verb, std::string endpoint, std::map<std::string, std::string> request_headers = {}, std::string request_body = "", std::string root_cert_path = "", std::map<http::field, std::string> authentication = {});

std::string getToken(json::object& endpoint);

void sendMessageToOmfEndpoint(json::object& endpoint, std::string message_type, std::string omf_message, std::string action = "create");

json::value getJsonFile(std::string path);

json::array getAppSettings();

std::string getCurrentTime();

void getData(json::object& data);

bool omf_routine(json::array& sent_data, bool test = false);

#endif