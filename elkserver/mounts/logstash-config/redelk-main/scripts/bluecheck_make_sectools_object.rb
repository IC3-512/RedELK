#
# Part of RedELK
# Script to make a json object to be stored as nested object of all found security tools
#
# Author: Outflank B.V. / Marc Smeets
#

# The BLUECHECK output is plain text; it is massaged into JSON here. Anything unexpected in that
# text produces invalid JSON, so a parse failure must leave the original string in place instead
# of taking the pipeline worker down with it.
def filter(event)
	string = event.get("[bluecheck][sectools]")
	if string.nil? || !string.is_a?(String)
		event.tag("_rubyparsefailure")
		return [event]
	end

	string2 = string.gsub("ProcessID","{ \"ProcessID\"")
	string3 = string2.gsub(" Vendor",", \"Vendor\"")
	string4 = string3.gsub(" Product",", \"Product\"")
	string5 = string4.gsub(",{","},{")
	string6 = string5.gsub(": ",": \"")
	string7 = string6.gsub(", ","\", ")
	string8 = string7.gsub("},","\"},")
	string9 = "["+string8+"\" }]"

	begin
		json = JSON.parse(string9)
	rescue JSON::ParserError
		event.tag("_rubyparsefailure")
		return [event]
	end

	event.tag("_rubyparseok")
	event.set("[bluecheck][sectools]", json)
	return [event]
end
