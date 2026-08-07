#
# Part of RedELK
# Script to have logstash insert an extra field pointing to the full TXT file of a Outflank Stage 1 C2 implant log file
#
# Author: Outflank B.V. / Marc Smeets
#

# The implant logs live under <stage1 root>/shared/logs/api/implant_logs/. Everything from the
# first '/logs/' onwards is kept, so the URL stays stable across Stage1 layouts. A path without
# '/logs/' (or a Filebeat event without log.file.path at all) used to blow up this script.
def filter(event)
	host = event.get("[agent][name]")
	logpath = event.get("[log][file][path]")
	index = logpath.nil? ? nil : logpath.index("/logs/")

	if host.nil? || index.nil?
		event.tag("_rubyparsefailure")
		return [event]
	end

	implantlogpath = "/c2logs/" + "#{host}" + "/stage1" + logpath[index..-1]
	event.tag("_rubyparseok")
	event.set("[implant][log_file]", implantlogpath)
	return [event]
end
