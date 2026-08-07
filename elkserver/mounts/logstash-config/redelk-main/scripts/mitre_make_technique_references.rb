#
# Part of RedELK
# Script to turn MITRE ATT&CK technique IDs into threat.technique.reference URLs
#
# Author: Outflank B.V. / Marc Smeets
#

# ATT&CK publishes a sub-technique underneath its parent, so T1055.012 lives at
# /techniques/T1055/012/ and not at /techniques/T1055.012/.
def filter(event)
  ids = event.get("[threat][technique][id]")
  return [event] if ids.nil?

  ids = [ids] unless ids.is_a?(Array)

  references = ids.map do |id|
    next nil unless id.is_a?(String)

    technique, subtechnique = id.strip.split(".", 2)
    next nil unless technique =~ /\AT\d{4}\z/

    if subtechnique =~ /\A\d{3}\z/
      "https://attack.mitre.org/techniques/#{technique}/#{subtechnique}/"
    else
      "https://attack.mitre.org/techniques/#{technique}/"
    end
  end.compact.uniq

  return [event] if references.empty?

  event.tag("_rubyparseok")
  event.set("[threat][technique][reference]", references)
  return [event]
end
