

#include <iostream>
#include "../httpclient.h"

bool stringStartsWith(const std::string& str, const std::string& character)
{
    return str.find(character) != std::string::npos;
}

void requestCallback(const HttpClient::HttpResponse_ptr& response)
{
    std::cout << "HTTP Response received: " << response->statusCode << " (" << response->responseTimeMs << "ms) id " << response->requestId << std::endl;

    // Print the string to the console
    std::cout << response->headerData << std::endl;
    std::cout << response->bodyData << std::endl;

}

void failureCallback(const HttpClient::HttpResponse_ptr& response)
{
    std::cout << "HTTP Response failed (" << response->errorMessage << ")" << std::endl;
}

int main()
{
    HttpClient::Request request(requestCallback, failureCallback);
    bool running = true;
    int counterInner = 0;

    std::cout << "Command input \n\t 'S' for send message in secure mode \n\t 'P' for send message in plain mode \n\t 'T' for terminate" << std::endl;

    while(running) {

        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        std::string line;
        std::getline(std::cin, line);
        boost::algorithm::to_lower(line);


        // GET method examples
        if(stringStartsWith(line, "gsa")) {
            std::cout << "sending GET in secure mode with Bearer Auth" << std::endl;

            std::string token = "abcDefgHijkLmnOpqrS";
            std::string url = "https://httpbin.org/bearer";

            std::unordered_map<std::string, std::string> headers = {
                {"Authorization", "Bearer " + token},
                {"Accept", "application/json"}
            };

            request.get(url, headers);
        }
        else if(stringStartsWith(line, "gpa")) {
            std::cout << "sending GET in plain mode" << std::endl;

            std::string token = "abcDefgHijkLmnOpqrS";
            std::string url = "http://httpbin.org/bearer";

            std::unordered_map<std::string, std::string> headers = {
                {"Authorization", "Bearer " + token},
                {"Accept", "application/json"}
            };

            request.get(url, headers);
        }
        else if(stringStartsWith(line, "gs")) {
            std::cout << "sending GET in secure mode" << std::endl;

            std::string url = "https://httpbin.org/get";

            request.get(url);
        }
        else if(stringStartsWith(line, "gp")) {
            std::cout << "sending GET in plain mode" << std::endl;

            std::string url = "http://httpbin.org/get";

            request.get(url);
        }
        
        
        // HEAD method examples
        if(stringStartsWith(line, "hs")) {
            std::cout << "sending HEAD in secure mode" << std::endl;

            std::string url = "https://httpbin.org/get";

            request.head(url);
        }
        else if(stringStartsWith(line, "hp")) {
            std::cout << "sending HEAD in plain mode" << std::endl;

            std::string url = "http://httpbin.org/get";

            request.head(url);
        }
        
        
        // OPTIONS method example
        if(stringStartsWith(line, "os")) {
            std::cout << "sending OPTIONS in secure mode" << std::endl;

            std::string url = "https://httpbin.org";

            request.options(url);
        }
        else if(stringStartsWith(line, "op")) {
            std::cout << "sending OPTIONS in plain mode" << std::endl;

            std::string url = "http://httpbin.org";

            request.options(url);
        }
        

        // TRACE method example
        if(stringStartsWith(line, "ts")) {
            std::cout << "sending TRACE in secure mode" << std::endl;

            std::string url = "https://www.example.com";

            request.trace(url);
        }
        else if(stringStartsWith(line, "tp")) {
            std::cout << "sending TRACE in plain mode" << std::endl;

            std::string url = "http://www.example.com";

            request.trace(url);
        }
        
        // CONNECT method example
        if(stringStartsWith(line, "cs")) {
            std::cout << "sending CONNECT in secure mode" << std::endl;

            std::string url = "https://www.example.com";

            request.connect(url);
        }
        else if(stringStartsWith(line, "cp")) {
            std::cout << "sending CONNECT in plain mode" << std::endl;

            std::string url = "http://www.example.com";
            request.connect(url);
        }
        
        if(stringStartsWith(line, "u")) {
            std::cout << "terminating" << std::endl;
            running = false;
        }

        
        std::cout << "invalid command input" << std::endl;
    }
}

