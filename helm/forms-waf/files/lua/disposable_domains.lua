--[[
    Disposable Email Domains Module
    Contains a list of known disposable/temporary email providers
    Used to flag or block submissions from throwaway email addresses
]]

local _M = {}

-- Common disposable email domains (hash table for O(1) lookup)
-- This list includes the most common disposable email services
local DISPOSABLE_DOMAINS = {
    -- Major disposable email providers
    ["10minutemail.com"] = true,
    ["10minutemail.net"] = true,
    ["10minmail.com"] = true,
    ["20minutemail.com"] = true,
    ["33mail.com"] = true,
    ["guerrillamail.com"] = true,
    ["guerrillamail.org"] = true,
    ["guerrillamail.net"] = true,
    ["guerrillamail.biz"] = true,
    ["guerrillamailblock.com"] = true,
    ["sharklasers.com"] = true,
    ["grr.la"] = true,
    ["guerrillamail.de"] = true,
    ["tempmail.com"] = true,
    ["temp-mail.org"] = true,
    ["temp-mail.io"] = true,
    ["tempmailo.com"] = true,
    ["tempr.email"] = true,
    ["tempinbox.com"] = true,
    ["throwaway.email"] = true,
    ["throwawaymail.com"] = true,
    ["mailinator.com"] = true,
    ["mailinator.net"] = true,
    ["mailinator.org"] = true,
    ["mailinator2.com"] = true,
    ["mailinater.com"] = true,
    ["maildrop.cc"] = true,
    ["getairmail.com"] = true,
    ["getnada.com"] = true,
    ["nada.email"] = true,
    ["yopmail.com"] = true,
    ["yopmail.fr"] = true,
    ["yopmail.net"] = true,
    ["cool.fr.nf"] = true,
    ["jetable.fr.nf"] = true,
    ["nospam.ze.tc"] = true,
    ["nomail.xl.cx"] = true,
    ["mega.zik.dj"] = true,
    ["speed.1s.fr"] = true,
    ["courriel.fr.nf"] = true,
    ["moncourrier.fr.nf"] = true,
    ["monemail.fr.nf"] = true,
    ["monmail.fr.nf"] = true,
    ["fakeinbox.com"] = true,
    ["fakemailgenerator.com"] = true,
    ["emailondeck.com"] = true,
    ["dispostable.com"] = true,
    ["trashmail.com"] = true,
    ["trashmail.net"] = true,
    ["trashmail.org"] = true,
    ["trashmail.me"] = true,
    ["trashemail.de"] = true,
    ["wegwerfmail.de"] = true,
    ["wegwerfmail.net"] = true,
    ["wegwerfmail.org"] = true,
    ["spamgourmet.com"] = true,
    ["spamgourmet.net"] = true,
    ["spamgourmet.org"] = true,
    ["mailnesia.com"] = true,
    ["mailcatch.com"] = true,
    ["mailscrap.com"] = true,
    ["mailnull.com"] = true,
    ["spambox.us"] = true,
    ["spamfree24.org"] = true,
    ["spamfree24.de"] = true,
    ["spamfree24.eu"] = true,
    ["spamfree24.info"] = true,
    ["spamfree24.net"] = true,
    ["incognitomail.com"] = true,
    ["incognitomail.net"] = true,
    ["incognitomail.org"] = true,
    ["anonymbox.com"] = true,
    ["mintemail.com"] = true,
    ["tempail.com"] = true,
    ["emailfake.com"] = true,
    ["generator.email"] = true,
    ["mohmal.com"] = true,
    ["crazymailing.com"] = true,
    ["tempmailaddress.com"] = true,
    ["burnermail.io"] = true,
    ["discard.email"] = true,
    ["discardmail.com"] = true,
    ["discardmail.de"] = true,
    ["spamherelots.com"] = true,
    ["spamavert.com"] = true,
    ["spamcero.com"] = true,
    ["inboxalias.com"] = true,
    ["mytrashmail.com"] = true,
    ["mailexpire.com"] = true,
    ["tempsky.com"] = true,
    ["dropmail.me"] = true,
    ["getonemail.com"] = true,
    ["harakirimail.com"] = true,
    ["kurzepost.de"] = true,
    ["objectmail.com"] = true,
    ["proxymail.eu"] = true,
    ["rcpt.at"] = true,
    ["trash-mail.at"] = true,
    ["trashdevil.com"] = true,
    ["trashdevil.de"] = true,
    ["twinmail.de"] = true,
    ["uggsrock.com"] = true,
    ["veryrealemail.com"] = true,
    ["viditag.com"] = true,
    ["whatpaas.com"] = true,
    ["emkei.cz"] = true,
    ["tempemailco.com"] = true,
    ["1chuan.com"] = true,
    ["1secmail.com"] = true,
    ["1secmail.net"] = true,
    ["1secmail.org"] = true,
    ["ezehe.com"] = true,
    ["icznn.com"] = true,
    ["vjuum.com"] = true,
    ["lroid.com"] = true,
    -- Additional popular services
    ["guerilla-mail.com"] = true,
    ["mailsac.com"] = true,
    ["moakt.com"] = true,
    ["moakt.co"] = true,
    ["moakt.ws"] = true,
    ["inboxkitten.com"] = true,
    ["tempmailer.com"] = true,
    ["tempmailer.net"] = true,
    ["mohmal.im"] = true,
    ["mohmal.in"] = true,
    ["mohmal.tech"] = true,
    ["emailnax.com"] = true,
    ["clonemymail.com"] = true,
    ["mailtemp.org"] = true,
    ["fakemail.net"] = true,
    ["email-fake.com"] = true,
    ["fakemailbox.com"] = true,
    ["gmailnator.com"] = true,
    ["smailpro.com"] = true,
    ["emaildrop.io"] = true,
    ["emailsensei.com"] = true,
    ["email-temp.com"] = true,
    ["mytemp.email"] = true,
    ["tempemailgen.com"] = true,
    ["luxusmail.org"] = true,
    ["tempmailgen.com"] = true,
    ["gxmxil.com"] = true,
    ["mailpoof.com"] = true,
    ["mvrht.net"] = true,
    ["privymail.de"] = true,
    ["sneakemail.com"] = true,
    ["sogetthis.com"] = true,
    ["spamex.com"] = true,
    ["tempemail.net"] = true,
    ["tempomail.fr"] = true,
    ["tmpbox.net"] = true,
    ["tmpmail.net"] = true,
    ["tmpmail.org"] = true,
    ["yep.it"] = true,
    ["mailhazard.com"] = true,
    ["mailhazard.us"] = true,
    ["mailhz.me"] = true,
    ["mailimate.com"] = true,
    ["mailmetrash.com"] = true,
    ["mailmoat.com"] = true,
    ["mailnator.com"] = true,
    ["mailquack.com"] = true,
    ["mailseal.de"] = true,
    ["mailshell.com"] = true,
    ["mailslapping.com"] = true,
    ["mailslite.com"] = true,
    ["mailtemp.info"] = true,
    ["mailtothis.com"] = true,
    ["mailzilla.com"] = true,
    ["mailzilla.org"] = true,
    ["mbx.cc"] = true,
    ["meltmail.com"] = true,
    ["messagebeamer.de"] = true,
    ["mierdamail.com"] = true,
    ["nervmich.net"] = true,
    ["nervtmansen.de"] = true,
    ["netmails.com"] = true,
    ["netmails.net"] = true,
    ["netzidiot.de"] = true,
    ["neverbox.com"] = true,
    ["no-spam.ws"] = true,
    ["nobulk.com"] = true,
    ["noclickemail.com"] = true,
    ["nogmailspam.info"] = true,
    ["nomail.xl.cx"] = true,
    ["nomail2me.com"] = true,
    ["nomorespamemails.com"] = true,
    ["notmailinator.com"] = true,
    ["nowmymail.com"] = true,
    ["nurfuerspam.de"] = true,
    ["nus.edu.sg"] = false,  -- Not disposable, example of exclusion
    ["nwldx.com"] = true,
    ["oopi.org"] = true,
    ["ordinaryamerican.net"] = true,
    ["otherinbox.com"] = true,
    ["owlpic.com"] = true,
    ["pookmail.com"] = true,
    ["privacy.net"] = true,
    ["privatdemail.net"] = true,
    ["quickinbox.com"] = true,
    ["rcpt.at"] = true,
    ["rejectmail.com"] = true,
    ["rklips.com"] = true,
    ["rmqkr.net"] = true,
    ["rppkn.com"] = true,
    ["safe-mail.net"] = true,
    ["safersignup.de"] = true,
    ["safetymail.info"] = true,
    ["safetypost.de"] = true,
    ["sandelf.de"] = true,
    ["saynotospams.com"] = true,
    ["selfdestructingmail.com"] = true,
    ["sendspamhere.com"] = true,
    ["shiftmail.com"] = true,
    ["shortmail.net"] = true,
    ["sibmail.com"] = true,
    ["sinnlos-mail.de"] = true,
    ["siteposter.net"] = true,
    ["slopsbox.com"] = true,
    ["smellfear.com"] = true,
    ["snakemail.com"] = true,
    ["sofort-mail.de"] = true,
    ["sogetthis.com"] = true,
    ["soodonims.com"] = true,
    ["spam4.me"] = true,
    ["spamail.de"] = true,
    ["spamarrest.com"] = true,
    ["spamavert.com"] = true,
    ["spambob.com"] = true,
    ["spambob.net"] = true,
    ["spambob.org"] = true,
    ["spambog.com"] = true,
    ["spambog.de"] = true,
    ["spambog.net"] = true,
    ["spambog.ru"] = true,
}

-- Check if an email domain is disposable
-- @param email string The email address to check
-- @return boolean True if the domain is disposable
function _M.is_disposable(email)
    if not email or email == "" then
        return false
    end

    -- Extract domain from email
    local domain = email:lower():match("@([%w%.%-]+)$")
    if not domain then
        return false
    end

    -- Direct lookup
    if DISPOSABLE_DOMAINS[domain] then
        return true
    end

    -- Check subdomain (e.g., mail.guerrillamail.com)
    local parent_domain = domain:match("%.([%w]+%.[%w]+)$")
    if parent_domain and DISPOSABLE_DOMAINS[parent_domain] then
        return true
    end

    return false
end

-- Get the domain from an email
-- @param email string The email address
-- @return string|nil The domain portion, or nil if invalid
function _M.get_domain(email)
    if not email or email == "" then
        return nil
    end
    return email:lower():match("@([%w%.%-]+)$")
end

-- Check if a domain is in the custom block list (from Redis)
-- This allows runtime additions without code changes
local custom_disposable = ngx.shared.keyword_cache

function _M.is_custom_disposable(domain)
    if not custom_disposable or not domain then
        return false
    end
    return custom_disposable:get("disposable:" .. domain:lower()) == true
end

-- Combined check: built-in list + custom list
function _M.check_email(email)
    if _M.is_disposable(email) then
        return true, "builtin"
    end

    local domain = _M.get_domain(email)
    if domain and _M.is_custom_disposable(domain) then
        return true, "custom"
    end

    return false, nil
end

-- Get count of built-in domains (for stats)
function _M.get_builtin_count()
    local count = 0
    for _ in pairs(DISPOSABLE_DOMAINS) do
        count = count + 1
    end
    return count
end

return _M
