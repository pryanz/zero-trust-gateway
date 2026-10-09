local token = os.getenv("BENCHMARK_JWT") or ""

if token == "" then
    print("Error: BENCHMARK_JWT environment variable is not set!")
    os.exit()
end

request = function()
    headers = {}
    headers["Authorization"] = "Bearer " .. token
    return wrk.format("GET", "/api/v1/service-a/test", headers)
end