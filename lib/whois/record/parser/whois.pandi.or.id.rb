#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2015 Simone Carletti <weppos@weppos.net>
#++


require 'whois/record/parser/base'
require 'whois/record/parser/whois.centralnic.com.rb'


module Whois
  class Record
    class Parser

      # Parser for the whois.pandi.or.id server.
      #
      # It aliases the whois.centralnic.com parser because
      # it looks like the response is the same of Centralnic.
      class WhoisPandiOrId < WhoisCentralnicCom
      end

    end
  end
end
