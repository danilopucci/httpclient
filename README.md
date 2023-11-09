# httpclient
A C++ single header-only lib to handle async HTTP requests in plain or secure mode.

The following HTTP methods are supported: GET, POST, PUT, PATCH, DELETE, TRACE, CONNECT, HEAD, OPTIONS.

- it is based on [Boost.Beast](https://github.com/boostorg/beast) library
- was developed based on Boost.Beast [http_client_async](https://www.boost.org/doc/libs/1_82_0/libs/beast/example/http/client/async/http_client_async.cpp)
- also based on [Richard Hodges](https://cppalliance.org/richard/2021/01/01/RichardsNewYearUpdate.html) blog post

### How to install

#### Ubuntu
```bash
$ sudo apt-get install libboost-all-dev libssl-dev
```

#### Windows
```shell
$ vcpkg install boost-beast:x64-windows
```

### Basic code usage

- include the library header
- define requestCallback and failureCallback(optional) functions
- create an instance of HttpClient::Request
- call HTTP request methods

All methods have overloads to handle custom headers:
```cpp
bool get(const std::string& url);
bool get(const std::string& url, std::unordered_map<std::string, std::string>& fields);
```

You can find more examples in examples folder 

```cpp
#include "httpclient.h"

void requestCallback(const HttpClient::HttpResponse_ptr& response)
{
    std::cout << "HTTP Response received: " << response->statusCode << " (" << response->responseTimeMs << "ms)" << std::endl;
}

void failureCallback(const HttpClient::HttpResponse_ptr& response)
{
    std::cout << "HTTP Response failed (" << response.errorMessage << ")" << std::endl;
}

int main()
{
  HttpClient::Request request(requestCallback, failureCallback);

  request.get("www.example.com");
  std::this_thread::sleep_for(std::chrono::milliseconds(10000));

  std::unordered_map<std::string, std::string> headers = {
      {"Authorization", "Bearer abcDefgHijkLmnOpqrS"},
      {"Accept", "application/json"}
  };

  request.get("https://httpbin.org/bearer", headers);
  std::this_thread::sleep_for(std::chrono::milliseconds(10000));
}
```

### URLs
It can handle multiple URL formats, both on HTTP and HTTPS. In case of hiding "https://" or "http://" it assumes that it is http and use the plain mode request.

Some examples are:
```
Basic HTTP URL:
http://www.example.com 

Basic HTTP URL with Port:
https://www.example.com:8080

HTTP URL with Path:
http://www.example.com/path/to/resource

HTTP URL with Query Parameters:
http://www.example.com/resource?param1=value1&param2=value2

HTTP URL with Fragment:
http://www.example.com/resource#section2

HTTPS URL with Path, Query, and Fragment:
https://www.example.com/path/resource?param=value#section3
```



