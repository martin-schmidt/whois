require 'whois/record/parser/base'
require 'whois/record/scanners/whois.arin.net.rb'

module Whois
  class Record
    class Parser

      # Parser for the whois.arin.net server.
      class WhoisArinNet < Base
        include Scanners::Scannable

        self.scanner = Scanners::WhoisArinNet

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

        property_supported :handle do
          node('NetRange')['NetHandle']
        end

        property_supported :registrant_contacts do
          build_contact('OrgName', Whois::Record::Contact::TYPE_REGISTRANT)
        end

        property_not_supported :admin_contacts
        property_not_supported :technical_contacts
        property_not_supported :created_on
        property_not_supported :updated_on

        property_supported :created_on do
          node('NetRange') { |raw| Time.parse(raw['RegDate']) }
        end

        property_supported :updated_on do
          node('NetRange') { |raw| Time.parse(raw['Updated']) }
        end

        property_not_supported :expires_on

        property_supported :inetnum do
          node('NetRange')['NetRange']
        end

        property_supported :cidr do
          node('NetRange')['CIDR']
        end

        property_supported :organization do
          node('NetRange')['Organization']
        end

        private
        def build_contact(element, type)
          node(element) do |raw|
            if raw['OrgName'] != "Not assigned" #TODO find unasigned and put value here
              Record::Contact.new(
                type:         type,
                id:           raw['OrgId'],
                organization: raw['OrgName'],
                address:      raw['Address'],
                city:         raw['City'],
                zip:          raw['PostalCode'],
                state:        raw['StateProv'],
                country_code: raw['Country'],
                created_on:   raw['RegDate'],
                updated_on:   raw['Updated'],
                url:          raw['Ref'],
              )
            end
          end
        end
      end
    end
  end
end
