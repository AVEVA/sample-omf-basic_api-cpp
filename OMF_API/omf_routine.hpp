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
#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <sstream>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <string>
#include <ctime>
#include <map>

#define OMFVERSION "1.2"
#define TYPE_CDS "CDS"
#define TYPE_EDS "EDS"
#define TYPE_PI "PI"
#define SEND_DELAY 1

namespace beast = boost::beast;          // from <boost/beast.hpp>
namespace http = beast::http;            // from <boost/beast/http.hpp>
namespace net = boost::asio;             // from <boost/asio.hpp>
namespace ssl = net::ssl;                // from <boost/asio/ssl.hpp>
namespace json = boost::json;            // from <boost/json.hpp>
namespace ios = boost::iostreams;        // from <boost/iostreams>
using tcp = net::ip::tcp;                // from <boost/asio/ip/tcp.hpp>

enum ENDPOINTS { CDS, EDS, PI };

json::value httpRequest(http::verb verb, const std::string& endpoint, const std::map<std::string, std::string>& request_headers = {}, const std::string& request_body = "", const std::map<http::field, std::string>& authentication = {});

json::value httpsRequest(http::verb verb, const std::string& endpoint, const std::map<std::string, std::string>& request_headers = {}, const std::string& request_body = "", const std::string& root_cert_path = "", const std::map<http::field, std::string>& authentication = {});

json::value request(http::verb verb, const std::string& endpoint, const std::map<std::string, std::string>& request_headers = {}, const std::string& request_body = "", const std::string& root_cert_path = "", const std::map<http::field, std::string>& authentication = {});

std::string getToken(json::object& endpoint);

std::string gzipCompress(const std::string& request_body);

std::string urlEncode(const std::string& body);

std::string base64_encode(const std::string& body);

void sendMessageToOmfEndpoint(json::object& endpoint, const std::string& message_type, const std::string& omf_message, const std::string& action = "create");

json::value getJsonFile(const std::string& path);

json::array getAppSettings();

std::string getCurrentTime();

void getData(json::object& data);

bool omfRoutine(json::array& sent_data, bool test = false);

#endif
