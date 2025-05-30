# Building a C++ sample to send OMF to PI or Cds

**Version**: 1.1.0

| Cds Test Status                                                                                                                                                                                                                                                                                                                                           | EDS Test Status                                                                                                                                                                                                                                                                                                                                           | PI Test Status                                                                                                                                                                                                                                                                                                                                               |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [![Build Status](https://dev.azure.com/AVEVA-VSTS/Cloud%20Platform/_apis/build/status%2Fproduct-readiness%2FOMF%2FAVEVA.sample-omf-basic_api-cpp?branchName=main&jobName=Tests_ADH)](https://dev.azure.com/AVEVA-VSTS/Cloud%20Platform/_build/latest?definitionId=16178&branchName=main) | [![Build Status](https://dev.azure.com/AVEVA-VSTS/Cloud%20Platform/_apis/build/status%2Fproduct-readiness%2FOMF%2FAVEVA.sample-omf-basic_api-cpp?branchName=main&jobName=Tests_EDS)](https://dev.azure.com/AVEVA-VSTS/Cloud%20Platform/_build/latest?definitionId=16178&branchName=main) | [![Build Status](https://dev.azure.com/AVEVA-VSTS/Cloud%20Platform/_apis/build/status%2Fproduct-readiness%2FOMF%2FAVEVA.sample-omf-basic_api-cpp?branchName=main&jobName=Tests_PI)](https://dev.azure.com/AVEVA-VSTS/Cloud%20Platform/_build/latest?definitionId=16178&branchName=main) |

## Building a sample with the rest calls directly

This sample doesn't help build the JSON strings for OMF messages. This works for simple examples, and for set demos, but if building something more complex it may be easier to form the JSON messages programatically.

[OMF documentation](https://docs.aveva.com/bundle/connect-data-services/page/1263258.html)

## Prerequisites
Install Visual Studio with C++ support. See [Install C and C++ support in Visual Studio](https://docs.microsoft.com/en-us/cpp/build/vscpp-step-0-installation?view=msvc-160)

## To run this sample in Visual Studio:

1. Clone the GitHub repository
2. Open the solution file in Microsoft Visual Studio, [OMF_API.sln](OMF_API.sln)
3. Rename the file [appsettings.placeholder.json](OMF_API/appsettings.placeholder.json) to appsettings.json
4. Update appsettings.json with the credentials for the enpoint(s) you want to send to. See [Configure endpoints and authentication](#configure-endpoints-and-authentication) below for additional details
5. Select the solution configuration "Release" and desired solution platform (x86 or x64) in the ribbon
6. Click **Debug** > **Start Debugging** (or F5)

## To test this sample in Visual Studio:

1. Follow steps 1-4 from the section above
2. Select the solution configuration "Debug UnitTests" and desired solution platform (x86 or x64) in the ribbon
3. Click **Debug** > **Run All Tests** (or F5)

## Customizing the application

This application can be customized to send your own custom types, containers, and data by modifying the [OMF-Types.json](OMF_API/OMF-Types.json), 
[OMF-Containers.json](OMF_API/OMF-Containers.json), and [OMF-Data.json](OMF_API/OMF-Data.json) files respectively. Each one of these files contains an array of OMF json objects, which are
created in the endpoints specified in [config.json](OMF_API/config-placeholder.json) when the application is run. For more information on forming OMF messages, please refer to our 
[OMF version 1.1 documentation](https://docs.aveva.com/search?labelkey=OSIsoft-Message-Format_1.1).  
  
In addition to modifying the json files mentioned above, the get_data function in [program.py](OMF_API/program.py) should be updated to populate the OMF data messages specified in 
[OMF-Data.json](OMF_API/OMF-Data.json) with data from your data source.  
  
Finally, if there are any other activities that you would like to be running continuously, this logic can be added under the while loop in the main() function of 
[program.py](OMF_API/program.py).

## Configure endpoints and authentication

The sample is configured using the file [appsettings.placeholder.json](OMF_API/appsettings.placeholder.json). Before editing, rename this file to `appsettings.json`. This repository's `.gitignore` rules should prevent the file from ever being checked in to any fork or branch, to ensure credentials are not compromised.

The application can be configured to send to any number of endpoints specified in the endpoints array within appsettings.json. In addition, there are three types of endpoints: CONNECT data services [Cds](#cds-endpoint-configuration), [EDS](#eds-endpoint-configuration), and [PI](#pi-endpoint-configuration). Each of the 3 types of enpoints are configured differently and their configurations are explained in the sections below.

### Cds endpoint configuration
The format of the configuration for an Cds endpoint is shown below along with descriptions of each parameter. Replace all parameters with appropriate values.

```json
{
  "EndpointType": "CDS",
  "Resource": "https://uswe.datahub.connect.aveva.com",
  "NamespaceId": "PLACEHOLDER_REPLACE_WITH_NAMESPACE_NAME",
  "TenantId": "PLACEHOLDER_REPLACE_WITH_TENANT_ID",
  "ClientId": "PLACEHOLDER_REPLACE_WITH_APPLICATION_IDENTIFIER",
  "ClientSecret": "PLACEHOLDER_REPLACE_WITH_APPLICATION_SECRET",
  "ApiVersion": "v1",
  "VerifySSL": "PLACEHOLDER_REPLACE_WTIH_CERTIFICATE_PATH",
  "UseCompression": false
}
```

| Parameters                  | Required | Type    | Description                                                                                                                                                      |
| --------------------------- | -------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Selected                    | required | boolean | Tells the application if the endpoint should be sent to                                                                                                          |
| EndpointType                | required | string  | The endpoint type. For Cds this will always be "CDS"                                                                                                             |
| Resource                    | required | string  | The endpoint for Cds if the namespace. If the tenant/namespace is located in NA, it is https://uswe.datahub.connect.aveva.com and if in EMEA, it is https://euno.datahub.connect.aveva.com  |
| NamespaceId                 | required | string  | The name of the Namespace in Cds that is being sent to                                                                                                           |
| TenantId                    | required | string  | The Tenant ID of the Tenant in Cds that is being sent to                                                                                                         |
| ClientId                    | required | string  | The client ID that is being used for authenticating to Cds                                                                                                       |
| ClientSecret                | required | string  | The client secret that is being used for authenticating to Cds                                                                                                   |
| ApiVersion                  | required | string  | The API version of the Cds endpoint                                                                                                                              |
| VerifySSL                   | optional | string  | The path to a base 64 encoded root certificate (.cer) for verifying the endpoint's certificate. If this is empty "", the certificate will not be verified.       |
| UseCompression              | optional | boolean | A feature flag for enabling compression on messages sent to the Cds endpoint                                                                                     |

### EDS endpoint configuration
The format of the configuration for an EDS endpoint is shown below along with descriptions of each parameter. Replace all parameters with appropriate values.

```json
{
  "EndpointType": "EDS",
  "Resource": "http://localhost:5590",
  "ApiVersion": "v1",
  "UseCompression": false
}
```

| Parameters                  | Required | Type    | Description                                                                                                                                       |
| --------------------------- | -------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| Selected                    | required | boolean | Tells the application if the endpoint should be sent to                                                                                           |
| EndpointType                | required | string  | The endpoint type. For EDS this will always be "EDS"                                                                                              |
| Resource                    | required | string  | The endpoint for EDS if the namespace. If EDS is being run on your local machine with the default configuration, it will be http://localhost:5590 |
| ApiVersion                  | required | string  | The API version of the EDS endpoint                                                                                                               |
| UseCompression              | optional | boolean | A feature flag for enabling compression on messages sent to the EDS endpoint                                                                      |

### PI Endpoint Configuration
The format of the configuration for a PI endpoint is shown below along with descriptions of each parameter. Replace all parameters with appropriate values.

```json
{
  "EndpointType": "PI",
  "Resource": "PLACEHOLDER_REPLACE_WITH_PI_WEB_API_URL",
  "DataArchiveName": "PLACEHOLDER_REPLACE_WITH_DATA_ARCHIVE_NAME",
  "Username": "PLACEHOLDER_REPLACE_WITH_USERNAME",
  "Password": "PLACEHOLDER_REPLACE_WITH_PASSWORD",
  "VerifySSL": "PLACEHOLDER_REPLACE_WTIH_CERTIFICATE_PATH",
  "UseCompression": false
}
```

| Parameters                  | Required | Type    | Description                                                                                                                                                |
| --------------------------- | -------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Selected                    | required | boolean | Tells the application if the endpoint should be sent to                                                                                                    |
| EndpointType                | required | string  | The endpoint type. For PI this will always be "PI"                                                                                                         |
| Resource                    | required | string  | The URL of the PI Web API                                                                                                                                  |
| DataArchiveName             | required | string  | The name of the PI Data Archive that is being sent to                                                                                                      |
| Username                    | required | string  | The username that is being used for authenticating to the PI Web API                                                                                       |
| Password                    | required | string  | The password that is being used for authenticating to the PI Web API                                                                                       |
| VerifySSL                   | optional | string  | The path to a base 64 encoded root certificate (.cer) for verifying the endpoint's certificate. If this is empty "", the certificate will not be verified. |
| UseCompression              | optional | boolean | A feature flag for enabling compression on messages sent to the PI endpoint                                                                               |

---

For the general steps or switch languages see the Task [ReadMe](https://github.com/AVEVA/AVEVA-Samples-OMF/blob/main/docs/OMF_BASIC.md)  
For the main OMF page [ReadMe](https://github.com/AVEVA/AVEVA-Samples-OMF)  
For the main AVEVA samples page [ReadMe](https://github.com/AVEVA/AVEVA-Samples)
