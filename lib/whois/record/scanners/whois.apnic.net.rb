#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2015 Simone Carletti <weppos@weppos.net>
#++


require 'whois/record/scanners/base'


module Whois
  class Record
    module Scanners

      class WhoisApnicNet < Base

        self.tokenizers += [
          :skip_empty_line,
          :skip_comment,
          :scan_section,
        ]


        tokenizer :skip_comment do
          @input.skip(/^\%(.*?)\n/)
        end

        tokenizer :scan_section do
          if @input.scan(/^(.+:)(\s.+)\n/)
            # Since there can be more than one section with the same first key
            # (see `whois 5.8.5.5`), we need an identifier.
            section = "#{@input[1].strip.chomp(':')}-#{Time.now.to_f.to_s.delete('.')}"

            content = parse_section_pairs
            @input.match?(/\n+/) || error("Unexpected end of section")
            @ast[section] = content
          end
        end


        private

        def parse_section_pairs
          # Sets by default the firsts values found in the section parsing bellow
          section_name, section_value = @input[1].strip, @input[2].strip
          #contents = {section_name =>  section_value}

          contents = {}

          while content = parse_section_pair
            contents.merge!(content)
          end

          if contents.has_key? section_name
            contents[section_name].insert(0, "#{section_value}\n")
          else
            contents[section_name] = section_value
          end

          if !contents.empty?
            contents
          else
            false
          end
        end

        def parse_section_pair
          if @input.scan(/(^\S+:\s+|^\s{2,})(.+)\n/)
            key       =  @input[1].strip
            values    = [@input[2].strip]
            while value = parse_section_pair_newlinevalue(key)
              values << value
            end
            { key => values.join("\n") }
          end
        end

        def parse_section_pair_newlinevalue(key)
          if @input.scan(/^#{key}\s+(.+)\n/)
            @input[1].strip
          end
        end

      end
    end
  end
end
