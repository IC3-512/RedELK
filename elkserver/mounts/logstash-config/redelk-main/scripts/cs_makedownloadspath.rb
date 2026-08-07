#
# Part of RedELK
# Script to have logstash insert an extra field pointing to the Cobalt Strike downloaded file
#
# Author: Outflank B.V. / Marc Smeets
#

# downloads.log holds the teamserver-local path of the harvested blob, e.g.
# /root/cobaltstrike/server/downloads/2914cdfa8. On disk the file is stored as <blob id>_<name>.
# Anchoring on '/cobaltstrike' keeps the '/server' part that a 4.x teamserver has and that
# getremotelogs.sh reproduces under /c2logs/<agent name>/.
def filter(event)
	host = event.get("[agent][name]")
	filename = event.get("[file][name]")
	file_path = event.get("[file][directory_local]")
	index = file_path.nil? ? nil : file_path.rindex("/cobaltstrike")

	if host.nil? || filename.nil? || index.nil?
		event.tag("_rubyparsefailure")
		return [event]
	end

	downloadsurl = "/c2logs/" + "#{host}" + file_path[index..-1] + "_" + "#{filename}"
	event.tag("_rubyparseok")
	event.set("[file][url]", downloadsurl)
	return [event]
end
