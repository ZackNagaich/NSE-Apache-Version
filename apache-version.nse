local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Grabs the HTTP header for apache off of '/'. Checks the server version to ensure it is relatively current
]]

author = "Zack Nagaich"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe","vuln"}

portrule = shortport.http

action = function(host, port)
  local status = false
  local result
  local path = "/"

  status,result = http.can_use_head(host, port,nil,path)

  if(result and result.header == nil) then
    return "Failed to obtain header"
  else
    local version = result.header['server']
    if version ~= nil then
	x,y,z = string.match(version,'Apache/(%d+)%.(%d+)%.(%d+)')
	if tonumber(x) < 2 and tonumber(y) < 2 then
		return string.format("Apache Server is running %s and is out of date.\nVulnerable",version)
        else
		return string.format("Apache Server is running %s and is current.",version)
	end
    end
  end


 
 
end
