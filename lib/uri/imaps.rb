# frozen_string_literal: true
# shareable_constant_value: literal

#
# = uri/imaps.rb
#
# Author:: Nicholas Evans
# License:: You can redistribute it and/or modify it under the same term as Ruby.
#
# See URI for general documentation
#

require_relative "imap"

module URI

  # The default port for IMAPS URIs is 993, and the scheme is 'imaps:' rather
  # than 'imap:'. Other than that, IMAPS URIs are identical to IMAP URIs.
  #
  # See URI::IMAP.
  class IMAPS < IMAP
    # A Default port of 993 for URI::IMAPS
    DEFAULT_PORT = 993
  end

  register_scheme "IMAPS", IMAPS
end
