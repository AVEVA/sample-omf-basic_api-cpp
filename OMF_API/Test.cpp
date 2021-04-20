#include <boost/json/src.hpp>
#include "omf_routine.hpp"
#define BOOST_TEST_MODULE tests
#include <boost/test/included/unit_test.hpp>

bool cleanup();
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
            if (endpoint.at("endpoint_type").as_string() == TYPE_PI)
            {

            }
            else
            {
                json::value response;

                // form request headers
                std::map<std::string, std::string> request_headers = { {"Accept-Verbosity", "verbose",} };
                if (endpoint.at("endpoint_type").as_string() == TYPE_OCS)
                    request_headers.insert({ "Authorization", "Bearer " + getToken(endpoint.as_object()) });

                // determine if SSL is needed
                std::vector<std::string> split_endpoint;
                boost::split(split_endpoint, endpoint.at("base_endpoint").as_string(), boost::is_any_of("/"));
                bool ssl = true;
                if (split_endpoint.at(0) != "https:")
                    ssl = false;

                // retrieve types and check response
                for (auto& omf_type : omf_types)
                {
                    std::string request_endpoint = json::value_to<std::string>(endpoint.at("base_endpoint")) + 
                        "/Types/" + json::value_to<std::string>(omf_type.at("id"));

                    if (ssl)
                    {
                        response = httpsRequest(
                            http::verb::get,
                            request_endpoint,
                            request_headers,
                            "",
                            json::value_to<std::string>(endpoint.at("verify_ssl"))
                        );
                    }
                    else
                    {
                        response = httpRequest(
                            http::verb::get,
                            request_endpoint,
                            request_headers
                        );
                    }
                }
                
                // retrieve containers and check response
                for (auto& omf_container : omf_containers)
                {
                    std::string request_endpoint = json::value_to<std::string>(endpoint.at("base_endpoint")) +
                        "/Streams/" + json::value_to<std::string>(omf_container.at("id"));

                    if (ssl)
                    {
                        response = httpsRequest(
                            http::verb::get,
                            request_endpoint,
                            request_headers,
                            "",
                            json::value_to<std::string>(endpoint.at("verify_ssl"))
                        );
                    }
                    else
                    {
                        response = httpRequest(
                            http::verb::get,
                            request_endpoint,
                            request_headers
                        );
                    }
                }

                // retrieve the most recent data, check the response, and compare the data to what was sent
                for (auto& omf_datum : omf_data)
                {
                    std::string request_endpoint = json::value_to<std::string>(endpoint.at("base_endpoint")) +
                        "/Streams/" + json::value_to<std::string>(omf_datum.at("containerid")) + "/Data/last";

                    if (ssl)
                    {
                        response = httpsRequest(
                            http::verb::get,
                            request_endpoint,
                            request_headers,
                            "",
                            json::value_to<std::string>(endpoint.at("verify_ssl"))
                        );
                    }
                    else
                    {
                        response = httpRequest(
                            http::verb::get,
                            request_endpoint,
                            request_headers
                        );
                    }

                    // Check that the data retrieved matches what was sent
                    
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