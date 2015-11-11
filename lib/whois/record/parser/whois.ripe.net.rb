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

        property_not_supported :expires_on

        property_supported :domain do
          ast.first[1]['domain:']
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

        property_supported :admin_contacts do
          node(ast.first[0]) do |raw|
            (raw['admin-c:'] || '').split("\n").map do |handle|
              build_contact(handle, Whois::Record::Contact::TYPE_ADMINISTRATIVE)
            end
          end
        end

        property_supported :technical_contacts do
          node(ast.first[0]) do |raw|
            (raw['tech-c:'] || '').split("\n").map do |handle|
               build_contact(handle, Whois::Record::Contact::TYPE_TECHNICAL)
            end
          end
        end

        property_supported :zone_contacts do
          node(ast.first[0]) do |raw|
            (raw['zone-c:'] || '').split("\n").map do |handle|
              build_contact(handle, Whois::Record::Contact::TYPE_ZONE)
            end
          end
        end

        property_supported :created_on do
          Time.parse(ast.first[1]['created:'])
        end

        property_supported :updated_on do
          Time.parse(ast.first[1]['last-modified:'])
        end

        property_supported :description do
          ast.first[1]['descr:']
        end

        property_supported :country do
          ast.first[1]['country:']
        end

        property_supported :source do
          ast.first[1]['source:']
        end

        # for domains under .e164.arpa
        property_supported :nameservers do
          node(ast.first[0]) do |raw|
            (raw['nserver:'] || '').split("\n").map do |line|
              name, ipv4 = line.downcase.split(/\s+/)
              Record::Nameserver.new(:name => name, :ipv4 => ipv4)
            end
          end
        end

        property_supported :inetnum do
          ast.first[1]['inetnum:']
        end

        property_supported :handle do
          ast.first[1]['netname:']
        end

        property_supported :organization do
          ast.first[1]['org:']
        end

        private
        def build_contact(handle, type)
          section, hash = ast.find{|k,v| v['nic-hdl:'] == handle}
          role = section =~ /^role-\d+/ ? true : false
          Record::Contact.new(
            type:         type,
            role:         role,
            id:           hash['nic-hdl:'],
            name:         hash['person:'],
            organization: hash['organisation:'],
            address:      hash['address:'],
            phone:        hash['phone:'],
            fax:          hash['fax-no:'],
            email:        hash['e-mail:'] || hash['abuse-mailbox:'],
            created_on:   Time.parse(hash['created:']),
            updated_on:   Time.parse(hash['last-modified:'])
          )
        end
      end
    end
  end
end
