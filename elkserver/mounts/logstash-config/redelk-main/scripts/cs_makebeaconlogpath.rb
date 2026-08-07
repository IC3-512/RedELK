#
# Part of RedELK
# Script to have logstash insert an extra field pointing to the full beacon log file of Cobalt Strike
#
# Author: Outflank B.V. / Marc Smeets
#

# getremotelogs.sh rsyncs the C2 server's home directory into /var/www/html/c2logs/<agent name>,
# so everything from '/cobaltstrike' onwards is reproduced verbatim below that URL. Anchoring on
# that instead of on a fixed prefix keeps this correct for both the pre-4.2 layout
# (<home>/cobaltstrike/logs/) and the 4.2 and later one (<home>/cobaltstrike/server/logs/).
def filter(event)
	host = event.get("[agent][name]")
	logpath = event.get("[log][file][path]")
	index = logpath.nil? ? nil : logpath.rindex("/cobaltstrike")

	if host.nil? || index.nil?
		event.tag("_rubyparsefailure")
		return [event]
	end

	implantlogpath = "/c2logs/" + "#{host}" + logpath[index..-1]
	event.tag("_rubyparseok")
	event.set("[implant][log_file]", implantlogpath)
	return [event]
end
