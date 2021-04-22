#include "omf_routine.hpp"

bool value1 = false;
bool value2 = false;

/// <summary>Makes http requests via the boost.beast library</summary>
/// <param name="verb">The http verb</param>
/// <param name="endpoint">URL to send request to</param>
/// <param name="request_headers">(optional) Request headers to be sent as part of the request</param>
/// <param name="request_body">(optional) Plain text body of the request</param>
/// <param name="authentication">(optional) Authentication credentials used for basic authentication</param>
/// <returns>Json representation of the response body</returns>
json::value httpRequest(http::verb verb, std::string endpoint, std::map<std::string, std::string> request_headers, std::string request_body, std::map<http::field, std::string> authentication)
{
    // parse endpoint
    std::vector<std::string> split_endpoint;
    boost::split(split_endpoint, endpoint, boost::is_any_of("/"));
    std::string host = split_endpoint.at(2);

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

    beast::tcp_stream stream(ioc);

    // Look up the domain name
    auto const results = resolver.resolve(host, port);

    // Make the connection on the IP address we get from a lookup
    beast::get_lowest_layer(stream).connect(results);

    // Set up an HTTP GET request message
    http::request<http::string_body> req{ verb, path, 11 };
    req.set(http::field::host, host);
    req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

    // Set headers and compress the request_body if applicable
    for (auto const& x : request_headers)
    {
        req.set(x.first, x.second);
        if (x.first == "compression")
            request_body = gzipCompress(request_body);
    }

    // Set authentication
    for (auto const& x : authentication)
        req.set(x.first, x.second);

    // Set body if applicable
    if (!request_body.empty())
        req.body() = request_body;

    // Prepare the payload
    req.prepare_payload();

    // Send the HTTP request to the remote host
    http::write(stream, req);

    // This buffer is used for reading and must be persisted
    beast::flat_buffer buffer;

    // Receive the HTTP response
    http::read(stream, buffer, res);

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

/// <summary>Makes https requests via the boost.beast library</summary>
/// <param name="verb">The http verb</param>
/// <param name="endpoint">URL to send request to</param>
/// <param name="request_headers">(optional) Request headers to be sent as part of the request</param>
/// <param name="request_body">(optional) Plain text body of the request</param>
/// <param name="root_cert_path">(optional) The path to the base64 encoded root certificate for the endpoint. 
/// This is used in ssl certificate verification</param>
/// <param name="authentication">(optional) Authentication credentials used for basic authentication</param>
/// <returns>Json representation of the response body</returns>
json::value httpsRequest(http::verb verb, std::string endpoint, std::map<std::string, std::string> request_headers, std::string request_body, std::string root_cert_path, std::map<http::field, std::string> authentication)
{
    // parse endpoint
    std::vector<std::string> split_endpoint;
    boost::split(split_endpoint, endpoint, boost::is_any_of("/"));
    std::string host = split_endpoint.at(2);

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

    ssl::context ctx(ssl::context::tlsv12_client);

    if (root_cert_path != "")
    {
        try
        {
            // Load a certificate from the specified path
            std::ifstream ifs(root_cert_path);
            std::string cert((std::istreambuf_iterator<char>(ifs)),
                (std::istreambuf_iterator<char>()));

            // Add the ssl context
            ctx.add_certificate_authority(
                boost::asio::buffer(cert.data(), cert.size()));
        }
        catch (std::exception const& e)
        {
            std::cerr << "Unable to open or parse file: "
                << e.what() << std::endl;
            return EXIT_FAILURE;
        }

        // Verify the remote server's certificate
        ctx.set_verify_mode(ssl::verify_peer);
    }
    else
        ctx.set_verify_mode(ssl::verify_none);

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

    // Set headers and compress the request_body if applicable
    for (auto const& x : request_headers)
    {
        req.set(x.first, x.second);
        if (x.first == "compression")
            request_body = gzipCompress(request_body);
    }

    // Set authentication
    for (auto const& x : authentication)
        req.set(x.first, x.second);

    // Set body if applicable
    if (!request_body.empty())
        req.body() = request_body;

    // Prepare the payload
    req.prepare_payload();

    // Send the HTTP request to the remote host
    http::write(stream, req);

    // This buffer is used for reading and must be persisted
    beast::flat_buffer buffer;

    // Receive the HTTP response
    http::read(stream, buffer, res);

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

/// <summary>Makes requests via the boost.beast library. This function decides on an http request or https request automatically.</summary>
/// <param name="verb">The http verb</param>
/// <param name="endpoint">URL to send request to</param>
/// <param name="request_headers">(optional) Request headers to be sent as part of the request</param>
/// <param name="request_body">(optional) Plain text body of the request</param>
/// <param name="root_cert_path">(optional) The path to the base64 encoded root certificate for the endpoint. 
/// This is used in ssl certificate verification</param>
/// <param name="authentication">(optional) Authentication credentials used for basic authentication</param>
/// <returns>Json representation of the response body</returns>
json::value request(http::verb verb, std::string endpoint, std::map<std::string, std::string> request_headers, std::string request_body, std::string root_cert_path, std::map<http::field, std::string> authentication)
{
    // determine if SSL is needed
    std::vector<std::string> split_endpoint;
    boost::split(split_endpoint, endpoint, boost::is_any_of("/"));
    bool ssl = true;
    if (split_endpoint.at(0) != "https:")
        ssl = false;

    if (ssl)
    {
        return httpsRequest(
            verb,
            endpoint,
            request_headers,
            request_body,
            root_cert_path,
            authentication
        );
    }

    return httpRequest(
        verb,
        endpoint,
        request_headers,
        request_body,
        authentication
    );
}

/// <summary>Retrieves the bearer token used for OCS requests</summary>
/// <param name="endpoint">Json endpoint object for determining what endpoint to retrieve the token for 
/// and to store the token after it has been retrieved</param>
/// <returns>Bearer token for OCS</returns>
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

    json::value response_body = {};

    std::string certificate_path = json::value_to<std::string>(endpoint.at("verify_ssl"));
    response_body = httpsRequest(http::verb::get, open_id_endpoint, request_headers, "", certificate_path);

    std::string token_url = json::value_to<std::string>(response_body.at("token_endpoint"));

    // Validate token URL
    std::vector<std::string> split_token;
    boost::split(split_token, token_url, boost::is_any_of("/"));
    assert(split_token.at(0) == "https:");
    assert(split_token.at(0) + "//" + split_token.at(2) == endpoint.at("resource").as_string());

    // Get the token endpoint
    std::string request_body = "client_id=" + client_id +
        "&client_secret=" + client_secret +
        "&grant_type=client_credentials";
    request_headers = { {"Content-Type", "application/x-www-form-urlencoded",}, {"Accept", "*/*",} };

    json::value token;
    token = httpsRequest(http::verb::post, token_url, request_headers, request_body, certificate_path);

    // store the token to save on unecessary calls
    time = std::chrono::system_clock::now().time_since_epoch();
    seconds = std::chrono::duration_cast<std::chrono::seconds>(time).count();
    endpoint["expiration"] = json::value_to<long long>(token.at("expires_in")) + seconds;
    endpoint["token"] = token.at("access_token");

    return json::value_to<std::string>(endpoint.at("token"));
}

/// <summary>Compresses a request body using gzip compression</summary>
/// <param name="request_body">Body of request to compress</param>
/// <returns>Compressed request body</returns>
std::string gzipCompress(std::string request_body)
{
    std::stringstream compressed_body, origin(request_body);

    ios::filtering_streambuf<ios::input> in;
    in.push(ios::gzip_compressor(ios::gzip_params(ios::gzip::best_compression)));
    in.push(origin);
    ios::copy(in, compressed_body);

    return compressed_body.str();
}

/// <summary>Sends OMF message to the specified endpoint</summary>
/// <param name="endpoint">Json endpoint object for constructing request</param>
/// <param name="message_type">The type of OMF message to send (type, container, data)</param>
/// <param name="omf_message">String representation of OMF message</param>
/// <param name="action">(optional) Action to take (i.e. create (default) or delete)</param>
void sendMessageToOmfEndpoint(json::object& endpoint, std::string message_type, std::string omf_message, std::string action)
{
    // Compress json omf payload, if specified
    std::string compression = "none";
    if (endpoint.at("use_compression").as_bool())
        compression = "gzip";

    // Create message headers and authentication field
    std::map<std::string, std::string> request_headers = {
        {"messagetype", message_type,},
        {"action", action,},
        {"messageformat", "JSON",},
        {"omfversion", OMFVERSION}
    };

    std::map<http::field, std::string> authentication = {};

    if (compression == "gzip")
        request_headers.insert({ "compression", "gzip", });

    if (endpoint.at("endpoint_type").as_string() == TYPE_OCS)
        request_headers.insert({ "Authorization", "Bearer " + getToken(endpoint) });
    else if (endpoint.at("endpoint_type").as_string() == TYPE_PI)
    {
        request_headers.insert({ "x-requested-with", "xmlhttprequest", });
        std::string credentials = json::value_to<std::string>(endpoint.at("username")) + ":" + json::value_to<std::string>(endpoint.at("password"));
        std::string base64_encoded_credentials = "Basic " + base64::encode(credentials);
        authentication = { { http::field::authorization, base64_encoded_credentials, } };
    }

    // validate headers to prevent injection attacks
    std::string valid_headers[7] = { "Authorization", "messagetype", "action", "messageformat", "omfversion", "x-requested-with", "compression" };
    std::map<std::string, std::string> validated_headers = {};
    for (auto const& header : request_headers)
    {
        for (int i = 0; i < 7; i++)
        {
            if (header.first == valid_headers[i])
                validated_headers.emplace(header);
        }
    }

    // Send message to OMF endpoint
    json::value response = request(
        http::verb::post,
        json::value_to<std::string>(endpoint.at("omf_endpoint")),
        validated_headers,
        omf_message,
        json::value_to<std::string>(endpoint.at("verify_ssl")),
        authentication
    );
}

/// <summary>Retrieves a json file from the specified path</summary>
/// <param name="path">Path to json file</param>
/// <returns>Json representation of file</returns>
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

/// <summary>Retrieves the appsettings.json file</summary>
/// <returns>Json representation of the appsettings file</returns>
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
            endpoint["verify_ssl"] = "";

        if (!endpoint.contains("use_compression"))
            endpoint["use_compression"] = false;

        app_settings.at(i) = endpoint;
    }

    return app_settings;
}

/// <summary>Retrieves ISO 8601 formatted date-time</summary>
/// <returns>String representation of ISO 8601 date-time</returns>
std::string getCurrentTime()
{
    using namespace boost::posix_time;
    ptime current_time = second_clock::universal_time();
    return to_iso_extended_string(current_time) + "Z";
}

/// <summary>Populates a data json object with data</summary>
/// <param name = "data">Pointer to data object to populate with data</param>
void getData(json::object& data)
{
    std::string container_id = json::value_to<std::string>(data.at("containerid"));

    json::array* values = &data.at("values").as_array();
    json::object* value = &values->at(0).as_object();

    if (container_id == "Container1" || container_id == "Container2")
    {
        value->at("IntegerProperty") = rand() % 100;
        value->at("Timestamp") = getCurrentTime();
    }
    else if (container_id == "Container3")
    {
        value2 = !value2;
        value->at("Timestamp") = getCurrentTime();
        value->at("NumberProperty1") = std::trunc(100 * static_cast <float> (rand()) / (static_cast <float> (RAND_MAX / 100))/100);
        value->at("NumberProperty2") = std::trunc(100 * static_cast <float> (rand()) / (static_cast <float> (RAND_MAX / 100))/100);
        if (value2)
            value->at("StringEnum") = "True";
        else
            value->at("StringEnum") = "False";
    }
    else if (container_id == "Container4")
    {
        value1 = !value1;
        value->at("Timestamp") = getCurrentTime();
        value->at("IntegerEnum") = static_cast <int> (value1);
    }
    else
        std::cout << "Container " << container_id << " not recognized";
}

/// <summary>Main routine that is called in both main.cpp and test.cpp</summary>
/// <param name="sent_data">A pointer to a json array that is used for storing the last values that were sent durring a test 
/// These values are later used to verify that the test was successful</param>
/// <param name = "test">(optional) Whether this function is being run as a test. By default this is false</param>.
/// <returns>If the routine was successful</returns>
bool omf_routine(json::array& sent_data, bool test)
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
            if (json::value_to<std::string>(endpoint.at("verify_ssl")) == "")
            {
                std::cout << "You are not verifying the certificate of the end point. "
                    << "This is not advised for any system as there are security issues with doing this." << std::endl;
            }

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

                if (test && count == 1)
                    sent_data.emplace_back(omf_datum);

                std::cout << omf_datum << std::endl;
            }

            std::chrono::seconds timespan(1);
            std::this_thread::sleep_for(timespan);
            count++;
        }

        std::cout << "Done" << std::endl;
    }
    catch (std::exception const& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return false;
    }
    return true;
}