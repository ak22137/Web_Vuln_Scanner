from boofuzz import Session, s_initialize, s_string, s_delim, s_static, TCPSocketConnection, Target, FuzzLoggerText

def main():
    # List of paths to fuzz; these could be collected from a sitemap or other source
    urls = [
        "/",
        "/about",
        "/contact",
        "/login",
    ]

    # Setup logging so that all fuzz results are saved to a file
    logger = FuzzLoggerText(file_handle=open("fuzz_results.txt", "w"))

    # Target configuration: specify the hostname and the port
    target = Target(connection=TCPSocketConnection("https://abhilekhborah.github.io/", 80))

    # Initialize a fuzzing session
    session = Session(target=target, fuzz_loggers=[logger])

    # Loop through each URL and setup a fuzz case
    for url in urls:
        s_initialize(name="FuzzHTTP")
        
        s_string("GET", fuzzable=False)  # Method is not fuzzable
        s_delim(" ", fuzzable=False)
        s_string(url, fuzzable=True)     # Fuzz the URL path
        s_delim(" ", fuzzable=False)
        s_string("HTTP/1.1", fuzzable=False)
        s_delim("\r\n", fuzzable=False)
        s_string("Host:", fuzzable=False)
        s_delim(" ", fuzzable=False)
        s_string("example.com")          # Set the Host header
        s_delim("\r\n", fuzzable=False)
        s_static("\r\n")                 # End of headers
        
        # Add the fuzz case to the session
        session.connect(s_get("FuzzHTTP"))

    # Start the fuzzing process
    session.fuzz()

if __name__ == "__main__":
    main()
