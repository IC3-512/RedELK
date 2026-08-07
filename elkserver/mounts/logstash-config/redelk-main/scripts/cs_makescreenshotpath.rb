#
# Part of RedELK
# Script to have logstash insert extra fields pointing to the Cobalt Strike screenshots
# Cobalt Strike 4.2 and higher
#
# Author: Outflank B.V. / Marc Smeets
#

# The screenshots live in a 'screenshots' subdirectory next to the screenshots.log we are reading.
# Anchoring on '/cobaltstrike' matches what getremotelogs.sh reproduces under /c2logs/<agent name>/;
# splitting on '/cobaltstrike/server' and re-prefixing '/cobaltstrike' used to drop the '/server'
# directory, so on a 4.x teamserver every screenshot link 404'd.
def filter(event)
  host = event.get("[agent][name]")
  logpath = event.get("[log][file][path]")
  filename = event.get("[screenshot][file_name]")
  index = logpath.nil? ? nil : logpath.rindex("/cobaltstrike")

  if host.nil? || filename.nil? || index.nil?
    event.tag("_rubyparsefailure")
    return [event]
  end

  logdir = File.dirname(logpath[index..-1])
  screenshoturl = "/c2logs/" + "#{host}" + "#{logdir}" + "/screenshots/" + "#{filename}"
  event.tag("_rubyparseok")
  event.set("[screenshot][full]", screenshoturl)
  event.set("[screenshot][thumb]", screenshoturl + ".thumb.jpg")
  return [event]
end
