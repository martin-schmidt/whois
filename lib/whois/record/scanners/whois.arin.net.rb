require 'whois/record/scanners/base'
module Whois
  class Record
    module Scanners

      class WhoisArinNet < Base

        self.tokenizers += [
          :skip_empty_line,
          :skip_comment,
          :scan_section,
        ]

        tokenizer :skip_comment do
          @input.skip(/^#.*\n/)
        end

        tokenizer :scan_section do
          if @input.scan(/^(\w+):(.+)\n/)
            # Adapt the section's name depending on the first line
            section = @input[1].strip.chomp
            content = parse_section_pairs
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
          if @input.scan(/^(\w+):(.+)\n/)
            key       =  @input[1].strip
            values    = [@input[2].strip]
            while value = parse_section_pair_newlinevalue(key)
              values << value
            end
            { key => values.join("\n") }
          end
        end

        def parse_section_pair_newlinevalue(key)
          if @input.scan(/^#{key}:\s+(.+)\n/)
            @input[1].strip
          end
        end

      end
    end
  end
end
