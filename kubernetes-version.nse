local shortport =  require "shortport"
local json = require "json"
local http = require "http"
local nmap = require "nmap"

description = [[Detects the Kubernetes service version.]]

---
-- @output
-- PORT     STATE SERVICE VERSION
-- 8443/tcp open  kubernetes  Kubernetes 1.10
-- |   Major: 1
-- |   Minor: 10
-- |   GitVersion: v1.10.0
-- |   GitCommit: fc32d2f3698e36b93322a3465f63a14e9f0eaead
-- |   GitTreeState: clean
-- |   BuildDate: 2018-03-26T16:44:10Z
-- |   GoVersion: go1.9.3
-- |   Compiler: gc
-- |   Platform: linux/amd64

author = "Jeremy Pruitt"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"version"}

portrule = shortport.version_port_or_service({8443}, {"kubernetes"}, "tcp")

action = function(host, port)

  local http_response = http.get(host, port, "/version")
  if not http_response or not http_response.status or
    http_response.status ~= 200 or not http_response.body then
    return
  end

  local ok_json, response = json.parse(http_response.body)
  if ok_json and response["gitVersion"] and response["goVersion"] then
    ---Detected
    port.version.name = 'kubernetes'
    port.version.version = response["gitVersion"]
    port.version.product = "Kubernetes"
    nmap.set_port_version(host, port)
    return response
  end
  return
end
