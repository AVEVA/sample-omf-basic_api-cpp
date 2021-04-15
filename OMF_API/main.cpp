#include "root_certificates.hpp"

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/json/src.hpp>
#include <boost/algorithm/string.hpp>
#include <cppcodec/base64_rfc4648.hpp>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <string>
#include <ctime>
#include <map>

namespace beast = boost::beast;          // from <boost/beast.hpp>
namespace http = beast::http;            // from <boost/beast/http.hpp>
namespace net = boost::asio;             // from <boost/asio.hpp>
namespace ssl = net::ssl;                // from <boost/asio/ssl.hpp>
namespace json = boost::json;            // from <boost/json.hpp>
using tcp = net::ip::tcp;                // from <boost/asio/ip/tcp.hpp>
using base64 = cppcodec::base64_rfc4648; // from <cppcodec/base64_rfc4648.hpp>


#define OMFVERSION "1.1"
#define TYPE_OCS "OCS"
#define TYPE_EDS "EDS"
#define TYPE_PI "PI"

enum ENDPOINTS { OCS, EDS, PI };


bool value1 = false;
bool value2 = false;


json::value httpRequest(http::verb verb, std::string endpoint, std::map<std::string, std::string> request_headers = {}, std::string request_body = "", std::map<http::field, std::string> authentication = {})
{
    // parse endpoint
    std::vector<std::string> split_endpoint;
    boost::split(split_endpoint, endpoint, boost::is_any_of("/"));
    std::string host = split_endpoint.at(2);
    // determine if SSL is needed
    bool ssl = true;
    if (split_endpoint.at(0) != "https:")
        ssl = false;
    // parse host
    std::vector<std::string> split_host;
    boost::split(split_host, host, boost::is_any_of(":"));
    host = split_host.at(0);
    // parse port
    std::string port = "443";
    if (split_host.size() == 2)
        port = split_host.at(1);
    // parse path
    std::string path = "";
    for (int i = 3; i < split_endpoint.size(); i++)
        path += "/" + split_endpoint.at(i);

    // The io_context is required for all I/O
    net::io_context ioc;

    // These objects perform our I/Ok
    tcp::resolver resolver(ioc);

    // Declare a container to hold the response
    http::response<http::string_body> res;

    if (ssl)
    {
        ssl::context ctx(ssl::context::tlsv12_client);

        // This holds the root certificate used for verification
        //load_root_certificates(ctx);

        // Verify the remote server's certificate
        //ctx.set_verify_mode(ssl::verify_peer);
        ctx.set_verify_mode(boost::asio::ssl::context::verify_none);

        beast::ssl_stream<beast::tcp_stream> stream(ioc, ctx);

        // Set SNI Hostname (many hosts need this to handshake successfully)
        SSL_set_tlsext_host_name(stream.native_handle(), &host);

        // Look up the domain name
        auto const results = resolver.resolve(host, port);

        // Make the connection on the IP address we get from a lookup
        beast::get_lowest_layer(stream).connect(results);
        
        // Perform the SSL handshake if needed
        stream.handshake(ssl::stream_base::client);

        // Set up an HTTP GET request message
        http::request<http::string_body> req{ verb, path, 11 };
        req.set(http::field::host, host);
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

        // Set body if applicable
        if (!request_body.empty())
            req.body() = request_body;

        // Set headers
        for (auto const& x : request_headers)
            req.set(x.first, x.second);

        // Set authentication
        for (auto const& x : authentication)
            req.set(x.first, x.second);

        // Prepare the payload
        req.prepare_payload();

        // Send the HTTP request to the remote host
        http::write(stream, req);

        // This buffer is used for reading and must be persisted
        beast::flat_buffer buffer;

        // Receive the HTTP response
        http::read(stream, buffer, res);
    }
    else
    {
        beast::tcp_stream stream(ioc);

        // Look up the domain name
        auto const results = resolver.resolve(host, port);

        // Make the connection on the IP address we get from a lookup
        beast::get_lowest_layer(stream).connect(results);

        // Set up an HTTP GET request message
        http::request<http::string_body> req{ verb, path, 11 };
        req.set(http::field::host, host);
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

        // Set body if applicable
        if (!request_body.empty())
            req.body() = request_body;

        // Set headers
        for (auto const& x : request_headers)
            req.set(x.first, x.second);

        // Set authentication
        for (auto const& x : authentication)
            req.set(x.first, x.second);

        // Prepare the payload
        req.prepare_payload();

        // Send the HTTP request to the remote host
        http::write(stream, req);

        // This buffer is used for reading and must be persisted
        beast::flat_buffer buffer;

        // Receive the HTTP response
        http::read(stream, buffer, res);
    }

    /*
    // Gracefully close the stream (this can hand the thread)
    beast::error_code ec;
    stream.shutdown(ec);
    if (ec == net::error::eof)
        ec = {};
    if (ec != boost::asio::ssl::error::stream_truncated)
        throw beast::system_error{ ec };
    */

    if (res.result() == http::int_to_status(409))
        return NULL;
    
    // response code in 200s if the request was successful!
    if (res.result() < http::int_to_status(200) || res.result() >= http::int_to_status(300))
    {
        std::cout << "Response from relay was bad " << std::endl << res << std::endl;
        throw http::error{};
    }

    std::string res_body = res.body();
    
    // Check if body empty
    if (res_body.size() == 0)
        return json::parse("{}");

    // Remove endianness information if present
    if (res_body[0] != '{')
        res_body = res_body.erase(0, 3);

    // Parse the response body as json
    std::cout << res_body << std::endl;
    return json::parse(res_body);
}

std::string getToken(json::object& endpoint)
{
    if (endpoint["endpoint_type"] != TYPE_OCS)
        return "";

    // check for an existing token and check that it is not expired
    auto time = std::chrono::system_clock::now().time_since_epoch();
    long long seconds = std::chrono::duration_cast<std::chrono::seconds>(time).count();
    if (endpoint.contains("expiration") && (json::value_to<long long>(endpoint.at("expiration")) - seconds) > 5 * 60)
        return json::value_to<std::string>(endpoint["token"]);

    std::string client_secret = json::value_to<std::string>(endpoint.at("client_secret"));
    std::string client_id = json::value_to<std::string>(endpoint.at("client_id"));

    // We can't short circuit it, so we must go retrieve the token

    // Get Token Endpoint
    std::string open_id_endpoint = "https://dat-b.osisoft.com/identity/.well-known/openid-configuration";
    std::map<std::string, std::string> request_headers = { {"Accept", "application/json",} };
    json::value response_body = httpRequest(http::verb::get, open_id_endpoint, request_headers);
    std::string token_url = json::value_to<std::string>(response_body.at("token_endpoint"));

    // Get the token endpoint
    std::string request_body = "client_id=" + client_id +
        "&client_secret=" +  client_secret +
        "&grant_type=client_credentials";
    request_headers = { {"Content-Type", "application/x-www-form-urlencoded",}, {"Accept", "*/*",} };
    json::value token = httpRequest(http::verb::post, token_url, request_headers, request_body);

    // store the token to save on unecessary calls
    time = std::chrono::system_clock::now().time_since_epoch();
    seconds = std::chrono::duration_cast<std::chrono::seconds>(time).count();
    endpoint["expiration"] = json::value_to<long long>(token.at("expires_in")) + seconds;
    endpoint["token"] = token.at("access_token");

    // TODO Validate URL
    return json::value_to<std::string>(endpoint.at("token"));
}

void sendMessageToOmfEndpoint(json::object& endpoint, std::string message_type, std::string omf_message, std::string action = "create")
{

    // Compress json omf payload, if specified
    std::string compression = "none";
    if (endpoint.at("use_compression").as_bool())
    { 
        // TODO compressy things
        compression = "gzip";
    }

    // Create message headers and authentication field
    std::map<std::string, std::string> request_headers = { 
        {"messagetype", message_type,},
        {"action", action,},
        {"messageformat", "JSON",},
        {"omfversion", OMFVERSION}
    };

    std::map<http::field, std::string> authentication = {};

    if (compression == "gzip")
        request_headers.insert({"compression", "gzip",});

    if (endpoint.at("endpoint_type").as_string() == TYPE_OCS)
        request_headers.insert({ "Authorization", "Bearer " + getToken(endpoint) });
    else if (endpoint.at("endpoint_type").as_string() == TYPE_PI)
    {
        request_headers.insert({"x-requested-with", "xmlhttprequest",});
        std::string credentials = json::value_to<std::string>(endpoint.at("username")) + ":" + json::value_to<std::string>(endpoint.at("password"));
        std::string base64_encoded_credentials = "Basic " + base64::encode(credentials);
        authentication = { { http::field::authorization, base64_encoded_credentials, } };
    }

    // TODO validate headers

    // Send message to OMF endpoint
    json::value response;

    response = httpRequest(
        http::verb::post, 
        json::value_to<std::string>(endpoint.at("omf_endpoint")),
        request_headers,
        omf_message,
        authentication
        );
    
}

json::value getJsonFile(std::string path)
{
    json::value json_content;

    try
    {
        std::ifstream ifs(path);
        std::string content((std::istreambuf_iterator<char>(ifs)),
            (std::istreambuf_iterator<char>()));

        json_content = json::parse(content);
    }
    catch (std::exception const& e)
    {
        std::cerr << "Unable to open or parse file: "
            << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return json_content;
}

json::array getAppSettings()
{
    // try to open the configuration file
    json::array app_settings = getJsonFile("appsettings.json").at("endpoints").as_array();

    // for each endpoint construct the check base and OMF endpoint and populate default values
    for (int i = 0; i < app_settings.size(); i++)
    {
        // add the base_endpoint and omf_endpoint to the endpoint configuration
        json::object endpoint = app_settings.at(i).get_object();
        std::string type = json::value_to<std::string>(endpoint.at("endpoint_type"));
        std::string resource = json::value_to<std::string>(endpoint.at("resource"));

        if (type == TYPE_OCS)
        {
            std::string api_version = json::value_to<std::string>(endpoint.at("api_version"));
            std::string tenant = json::value_to<std::string>(endpoint.at("tenant"));
            std::string namespace_name = json::value_to<std::string>(endpoint.at("namespace_name"));
            endpoint["base_endpoint"] = resource + "/api/" + api_version +
                "/tenants/" + tenant + "/namespaces/" + namespace_name;
        }
        else if (type == TYPE_EDS)
        {
            std::string api_version = json::value_to<std::string>(endpoint.at("api_version"));
            endpoint["base_endpoint"] = resource + "/api/" + api_version +
                "/tenants/default/namespaces/default";
        }
        else if (type == TYPE_PI)
        {
            endpoint["base_endpoint"] = resource;
        }

        endpoint["omf_endpoint"] = json::value_to<std::string>(endpoint.at("base_endpoint")) + "/omf";

        // check for optional/nullable parameters
        if (!endpoint.contains("verify_ssl"))
            endpoint["verify_ssl"] = true;

        if (!endpoint.contains("use_compression"))
            endpoint["use_compression"] = false;

        app_settings.at(i) = endpoint;
    }
   
    return app_settings;
}

std::string getCurrentTime()
{
    using namespace boost::posix_time;
    ptime current_time = microsec_clock::universal_time();
    return to_iso_extended_string(current_time) + "Z";
}

void getData(json::object& data) 
{
    std::string container_id = json::value_to<std::string>(data.at("containerid"));

    json::array* values = &data.at("values").as_array();
    json::object* value = &values->at(0).as_object();

    if (container_id == "Container1" || container_id == "Container2")
    {
        value->at("IntegerProperty") = rand() % 100;
        value->at("timestamp") = getCurrentTime();  
    }
    else if (container_id == "Container3")
    {
        value2 = !value2;
        value->at("timestamp") = getCurrentTime();
        value->at("NumberProperty1") = static_cast <float> (rand()) / (static_cast <float> (RAND_MAX / 100));
        value->at("NumberProperty2") = static_cast <float> (rand()) / (static_cast <float> (RAND_MAX / 100));
        if (value2)
            value->at("StringEnum") = "True";
        else
            value->at("StringEnum") = "False";
    }
    else if (container_id == "Container4")
    {
        value1 = !value1;
        value->at("timestamp") = getCurrentTime();
        value->at("IntegerEnum") = static_cast <int> (value1);
    }
    else
        std::cout << "Container " << container_id << " not recognized";
}

int main(bool test = false)
{
    // Step 1 - Read endpoint configurations from config.json
    json::array endpoints = getAppSettings();

    // Step 2 - Get OMF Types
    json::array omf_types = getJsonFile("OMF-Types.json").as_array();

    // Step 3 - Get OMF Containers
    json::array omf_containers = getJsonFile("OMF-Containers.json").as_array();

    // Step 4 - Get OMF Data
    json::array omf_data = getJsonFile("OMF-Data.json").as_array();

    // Send messages and check for each endpoint in config.json

    try
    {
        //Send out the messages that only need to be sent once
        for (auto& endpoint : endpoints)
        {
            /*if (!json::value_to<bool>(endpoint.at("verify_ssl")))
            {
                std::cout << "You are not verifying the certificate of the end point. ";
                std::cout << "This is not advised for any system as there are security issues with doing this." << std::endl;
            }*/
            
            // Step 5 - Send OMF Types
            for (auto& omf_type : omf_types)
            {
                sendMessageToOmfEndpoint(endpoint.as_object(), "type", "[" + json::serialize(omf_type) + "]");
            }

            // Step 6 - Send OMF Containers
            for (auto& omf_container : omf_containers)
            {
                sendMessageToOmfEndpoint(endpoint.as_object(), "container", "[" + json::serialize(omf_container) + "]");
            }

        }

        // Step 7 - Send OMF Data
        uint32_t count = 0;
        // send data to all endpoints forever if this is not a test
        while (!test || count < 2)
        {
            /*
            * This is where custom loop logic should go. 
            * The get_data call should also be customized to populate omf_data with relevant data.
            */

            for (auto& omf_datum : omf_data)
            {
                getData(omf_datum.as_object());
                
                for (auto& endpoint : endpoints)
                {
                    sendMessageToOmfEndpoint(endpoint.as_object(), "data", "[" + json::serialize(omf_datum) + "]");
                }

                std::cout << omf_datum << std::endl;
            }

            std::chrono::seconds timespan(1);
            std::this_thread::sleep_for(timespan);
        }
      
        std::cout << endpoints.at(0) << std::endl;
    }
    catch (std::exception const& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;

}