#include <boost/json/src.hpp>
#include "omf_routine.hpp"
#define BOOST_TEST_MODULE tests
#include <boost/test/included/unit_test.hpp>

bool cleanup();
bool compare_pi_data(json::string container_name, json::object retrieved_data, json::array sent_data);
bool compare_sds_data(json::string container_id, json::object retrieved_data, json::array sent_data);
bool check_creations(json::array sent_data);

BOOST_AUTO_TEST_CASE(omf_routine_test)
{
	// Steps 1 to 7 - Run the main program
    json::array sent_data;
	BOOST_TEST(omf_routine(sent_data, true));
    std::cout << sent_data << std::endl;
	// Step 8 - Check Creations
    BOOST_TEST(check_creations(sent_data));
	// Step 9 - Cleanup
	BOOST_TEST(cleanup());
}

bool check_creations(json::array sent_data)
{
    bool success = true;

    json::array endpoints = getAppSettings();
    json::array omf_types = getJsonFile("OMF-Types.json").as_array();
    json::array omf_containers = getJsonFile("OMF-Containers.json").as_array();
    json::array omf_data = getJsonFile("OMF-Data.json").as_array();

    std::cout << "Check" << std::endl;
    
    for (auto& endpoint : endpoints)
    {
        
        try
        {
            json::value response;

            // form request headers
            std::map<std::string, std::string> request_headers = { {"Accept-Verbosity", "verbose",} };
            if (endpoint.at("endpoint_type").as_string() == TYPE_OCS)
                request_headers.insert({ "Authorization", "Bearer " + getToken(endpoint.as_object()) });      

            if (endpoint.at("endpoint_type").as_string() == TYPE_PI)
            {
                request_headers.insert({ "x-requested-with", "XMLHTTPRequest" });
                std::string credentials = json::value_to<std::string>(endpoint.at("username")) + ":" + json::value_to<std::string>(endpoint.at("password"));
                std::string base64_encoded_credentials = "Basic " + base64::encode(credentials);
                std::map<http::field, std::string> authentication = { { http::field::authorization, base64_encoded_credentials, } };

                // get point URLs
                std::string request_endpoint = json::value_to<std::string>(endpoint.at("base_endpoint")) +
                    "/dataservers?name=" + json::value_to<std::string>(endpoint.at("data_server_name"));

                response = httpsRequest(
                    http::verb::get,
                    request_endpoint,
                    request_headers,
                    "",
                    json::value_to<std::string>(endpoint.at("verify_ssl")),
                    authentication
                );

                json::object links = response.at("Links").as_object();
                std::string points_URL = json::value_to<std::string>(links.at("Points"));

                // get point data and check response
                for (auto& omf_container : omf_containers)
                {
                    request_endpoint = points_URL + "?nameFilter=" + 
                        json::value_to<std::string>(omf_container.at("id")) + "*";
                    
                    response = httpsRequest(
                        http::verb::get,
                        request_endpoint,
                        request_headers,
                        "",
                        json::value_to<std::string>(endpoint.at("verify_ssl")),
                        authentication
                    );

                    json::array items = response.at("Items").as_array();

                    // get end value URLs
                    for (auto& item : items)
                    {
                        json::object item_links = item.at("Links").as_object();
                        std::string end_value_URL = json::value_to<std::string>(item_links.at("Value"));

                        // retrieve data
                        response = httpsRequest(
                            http::verb::get,
                            end_value_URL,
                            request_headers,
                            "",
                            json::value_to<std::string>(endpoint.at("verify_ssl")),
                            authentication
                        );

                        std::cout << item << std::endl;
                        if (!compare_pi_data(item.at("Name").as_string(), response.as_object(), sent_data))
                            success = false;
                    }

                }

            }
            else
            {
                // retrieve types and check response
                for (auto& omf_type : omf_types)
                {
                    std::string request_endpoint = json::value_to<std::string>(endpoint.at("base_endpoint")) + 
                        "/Types/" + json::value_to<std::string>(omf_type.at("id"));

                    response = request(
                        http::verb::get,
                        request_endpoint,
                        request_headers,
                        "",
                        json::value_to<std::string>(endpoint.at("verify_ssl"))
                    );
                }
                
                // retrieve containers and check response
                for (auto& omf_container : omf_containers)
                {
                    std::string request_endpoint = json::value_to<std::string>(endpoint.at("base_endpoint")) +
                        "/Streams/" + json::value_to<std::string>(omf_container.at("id"));

                    response = request(
                        http::verb::get,
                        request_endpoint,
                        request_headers,
                        "",
                        json::value_to<std::string>(endpoint.at("verify_ssl"))
                    );
                }

                // retrieve the most recent data, check the response, and compare the data to what was sent
                for (auto& omf_datum : omf_data)
                {
                    std::string request_endpoint = json::value_to<std::string>(endpoint.at("base_endpoint")) +
                        "/Streams/" + json::value_to<std::string>(omf_datum.at("containerid")) + "/Data/last";

                    response = request(
                        http::verb::get,
                        request_endpoint,
                        request_headers,
                        "",
                        json::value_to<std::string>(endpoint.at("verify_ssl"))
                    );

                    // Check that the data retrieved matches what was sent
                    if (!compare_sds_data(omf_datum.at("containerid").as_string(), response.as_object(), sent_data))
                        success = false;
                }
            }
        }
        catch (std::exception const& e)
        {
            std::cerr << "Error: " << e.what() << std::endl;
            success = false;
        }
    }

    return success;
}

bool cleanup()
{
	bool success = true;

    json::array endpoints = getAppSettings();
    json::array omf_types = getJsonFile("OMF-Types.json").as_array();
    json::array omf_containers = getJsonFile("OMF-Containers.json").as_array();

    std::cout << "Deletes" << std::endl;

    for (auto& endpoint : endpoints)
    {
        try
        {
            for (auto& omf_type : omf_types)
            {
                sendMessageToOmfEndpoint(endpoint.as_object(), "type", "[" + json::serialize(omf_type) + "]", "delete");
            }

            for (auto& omf_container : omf_containers)
            {
                sendMessageToOmfEndpoint(endpoint.as_object(), "container", "[" + json::serialize(omf_container) + "]", "delete");
            }
        }
        catch (std::exception const& e)
        {
            std::cerr << "Error: " << e.what() << std::endl;
            success = false;
        }
    }

	return success;
}

bool compare_sds_data(json::string container_id, json::object retrieved_data, json::array sent_data)
{
    for (auto& sent_datum : sent_data)
    {
        if (container_id == sent_datum.at("containerid").as_string())
        {
            json::array values = sent_datum.at("values").as_array();
            json::object value = values[0].as_object();

            if (value == retrieved_data)
                return true;
            else
                return false;
        }
    }
    return false;
}

bool compare_pi_data(json::string container_name, json::object retrieved_data, json::array sent_data)
{
    // split properties from tag name if the container had multiple properties
    std::vector<std::string> split_name;
    boost::split(split_name, container_name, boost::is_any_of("."));
    json::string property = "";

    if (split_name.size() == 2)
    {
        property = split_name[1];
        container_name = split_name[0];
    }
   
    for (auto& sent_datum : sent_data)
    {
        if (container_name == sent_datum.at("containerid").as_string())
        {
            json::array values = sent_datum.at("values").as_array();
            json::object value = values[0].as_object();

            if (property == "")
            {
                auto it = value.begin();
                for (;;)
                {
                    if (it->key() != "Timestamp")
                    { 
                        property = it->key();
                        break;
                    }
                        
                    if (++it == value.end())
                        break;
                }
            }

            if (value.at(property) == retrieved_data.at("Value"))
                return true;
            else
            {
                std::cout << value.at(property) << std::endl;
                std::cout << retrieved_data.at("Value") << std::endl;
            }
                
        }
    }

    return false;
}