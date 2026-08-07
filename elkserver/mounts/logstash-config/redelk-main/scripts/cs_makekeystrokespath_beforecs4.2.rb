#
# Part of RedELK
# Script to have logstash insert an extra field pointing to the full TXT file of a Cobalt Strike keystrokes file
# Before Cobalt Strike 4.2
#
# Author: Outflank B.V. / Marc Smeets
#

# Before 4.2 the harvested file is named after the beacon id rather than after the log file we
# are reading, so rebuild the file name from implant.id. The directory part is anchored on
# '/cobaltstrike' exactly like the 4.2+ variant.
def filter(event)
	host = event.get("[agent][name]")
	logpath = event.get("[log][file][path]")
	implant_id = event.get("[implant][id]")
	index = logpath.nil? ? nil : logpath.rindex("/cobaltstrike")

	if host.nil? || implant_id.nil? || index.nil?
		event.tag("_rubyparsefailure")
		return [event]
	end

	logdir = File.dirname(logpath[index..-1])
	keystrokespath = "/c2logs/" + "#{host}" + "#{logdir}" + "/keystrokes_" + "#{implant_id}" + ".txt"
	event.tag("_rubyparseok")
	event.set("[keystrokes][url]", keystrokespath)
	return [event]
end
