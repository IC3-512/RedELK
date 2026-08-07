#
# Part of RedELK
# Script to have logstash insert an extra field pointing to the full TXT file of a Cobalt Strike keystrokes file
# Cobalt Strike 4.2 and higher
#
# Author: Outflank B.V. / Marc Smeets
#

# Same anchoring as cs_makebeaconlogpath.rb: keep everything from '/cobaltstrike' onwards, which
# is exactly what getremotelogs.sh reproduces under /c2logs/<agent name>/. Splitting on
# '/cobaltstrike/server' and then re-prefixing '/cobaltstrike' used to drop the '/server'
# directory from the URL, so on a 4.x teamserver every keystrokes link 404'd.
def filter(event)
	host = event.get("[agent][name]")
	logpath = event.get("[log][file][path]")
	index = logpath.nil? ? nil : logpath.rindex("/cobaltstrike")

	if host.nil? || index.nil?
		event.tag("_rubyparsefailure")
		return [event]
	end

	keystrokespath = "/c2logs/" + "#{host}" + logpath[index..-1]
	event.tag("_rubyparseok")
	event.set("[keystrokes][url]", keystrokespath)
	return [event]
end
