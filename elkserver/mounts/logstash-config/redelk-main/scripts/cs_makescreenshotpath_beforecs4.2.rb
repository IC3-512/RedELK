#
# Part of RedELK
# Script to have logstash insert extra fields pointing to the Cobalt Strike screenshots
# before Cobalt Strike 4.2
#
# Author: Outflank B.V. / Marc Smeets
#

# Before 4.2 there is no screenshots.log; the file name has to be reconstructed from the beacon
# log's timestamp and the beacon id. The directory part is anchored on '/cobaltstrike', the same
# way as the 4.2+ variant, so both produce URLs below /c2logs/<agent name>/cobaltstrike/...
def filter(event)
  require 'time'
  host = event.get("[agent][name]")
  logpath = event.get("[log][file][path]")
  implant_id = event.get("[implant][id]")
  timestamp = event.get("[c2][timestamp]")
  index = logpath.nil? ? nil : logpath.rindex("/cobaltstrike")

  if host.nil? || implant_id.nil? || timestamp.nil? || index.nil?
    event.tag("_rubyparsefailure")
    return [event]
  end

  begin
    timestring = Time.parse("#{timestamp} UTC").strftime("%I%M%S")
  rescue ArgumentError
    event.tag("_rubyparsefailure")
    return [event]
  end

  logdir = File.dirname(logpath[index..-1])
  screenshoturl = "/c2logs/" + "#{host}" + "#{logdir}" + "/screenshots/screen_" + "#{timestring}" + "_" + "#{implant_id}" + ".jpg"
  event.tag("_rubyparseok")
  event.set("[screenshot][full]", screenshoturl)
  event.set("[screenshot][thumb]", screenshoturl + ".thumb.jpg")
  return [event]
end
