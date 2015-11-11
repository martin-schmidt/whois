#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2015 Simone Carletti <weppos@weppos.net>
#++


require 'whois/record/parser/base'
require 'whois/record/scanners/whois.ripe.net.rb'


module Whois
  class Record
    class Parser

      # Parser for the whois.ripe.net server.
      class WhoisRipeNet < Base
        include Scanners::Scannable

        self.scanner = Scanners::WhoisRipeNet

        property_supported :domain do
          node('domain')['domain:'] if node('domain')
        end

        property_supported :status do
          if available?
            :available
          else
            :registered
          end
        end

        property_supported :available? do
          !!(content_for_scanner =~ /%ERROR:101: no entries found/)
        end

        property_supported :registered? do
          !available?
        end

        property_supported :registrant_contacts do
          build_contact("organisation", Whois::Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :admin_contacts do
          build_contact("administrative", Whois::Record::Contact::TYPE_ADMINISTRATIVE)
        end

        property_supported :technical_contacts do
          build_contact("technical", Whois::Record::Contact::TYPE_TECHNICAL)
        end

        property_supported :created_on do
          node('domain') { |raw| Time.parse(raw['created:']) } if node('domain')
          node('inetnum') { |raw| Time.parse(raw['created:']) } if node('inetnum')
        end

        property_supported :updated_on do
          node('domain') { |raw| Time.parse(raw['last-modified:']) } if node('domain')
          node('inetnum') { |raw| Time.parse(raw['last-modified:']) } if node('inetnum')
        end

        property_not_supported :expires_on

        property_supported :nameservers do
          node("domain") do |raw|
            (raw["nserver:"] || "").split("\n").map do |line|
              name, ipv4 = line.downcase.split(/\s+/)
              Record::Nameserver.new(:name => name, :ipv4 => ipv4)
            end
          end
        end

        property_supported :inetnum do
          node('inetnum')['inetnum:'] if node('inetnum')
        end

        private
        def build_contact(element, type)
          node(element) do |raw|
            if raw["organisation:"] != "Not assigned"
              Record::Contact.new(
                type:         type,
                name:         raw["org-name:"],
                organization: raw["organisation:"],
                address:      raw['address:'],
                phone:        raw["phone:"],
                fax:          raw["fax-no:"],
                email:        raw["e-mail:"],
                created_on:   raw['created:'],
                updated_on:   raw['last-modified:']
              )
            end
          end
        end
      end
    end
  end
end
