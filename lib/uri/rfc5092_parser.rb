# frozen_string_literal: true
# shareable_constant_value: literal

module URI

  module RFC5092Parser # :nodoc:

    # See §11: ABNF for IMAP URL Schema
    module RFC5092Regexps # :nodoc:

      # TODO: move this to RFC3986_Parser
      # RFC3986 §2.3:
      #   unreserved      = ALPHA / DIGIT / "-" / "." / "_" / "~"
      UNRESERVED          = /[a-zA-Z0-9\-._~]/

      # Defined by RFC3501 and RFC9051
      NZ_NUMBER           = /[1-9]\d*/

      # sub-delims-sh     = "!" / "$" / "'" / "(" / ")" /
      #                     "*" / "+" / ","
      #                        ;; Same as [URI-GEN] sub-delims,
      #                        ;; but without ";", "&" and "=".
      SUB_DELIMS_SH       = /[!$'()*+,]/

      # uchar             = unreserved / sub-delims-sh / pct-encoded
      UCHAR_SAFE          = /[#{UNRESERVED.source}#{SUB_DELIMS_SH.source}]/
      UCHAR               = /(?:%\h\h|#{UCHAR_SAFE})/

      # achar             = uchar / "&" / "="
      #                     ;; Same as [URI-GEN] 'unreserved / sub-delims /
      #                     ;; pct-encoded', but ";" is disallowed.
      ACHAR_SAFE          = /[#{UCHAR_SAFE.source}&=]/
      ACHAR_SPECIALS      = /[^#{ACHAR_SAFE.source}]/
      ACHAR               = /(?:%\h\h|#{ACHAR_SAFE})/

      # bchar             = achar / ":" / "@" / "/"
      BCHAR_SAFE          = %r{[#{ACHAR_SAFE.source}:@/]}
      BCHAR_SPECIALS      = /[^#{BCHAR_SAFE.source}]/
      BCHAR               = /(?:%\h\h|#{BCHAR_SAFE})/
      BCHAR_EXCEPT_SLASH  = /(?:%\h\h|[#{ACHAR_SAFE.source}:@])/

      # iua-verifier      = ":" uauth-mechanism ":" enc-urlauth
      # uauth-mechanism   = "INTERNAL" / 1*(ALPHA / DIGIT / "-" / ".")
      #                        ; Case-insensitive.
      #                        ; New mechanisms MUST be registered with IANA.
      # enc-urlauth       = 32*HEXDIG
      IUA_VERIFIER        = /
      (?:
        : (?<uauth-mechanism> [a-zA-Z0-9.-]+ )
        : (?<enc-urlauth>     \h{32,}        )
      )/ix

      #   access          = ("submit+" enc-user) / ("user+" enc-user) /
      #                      "authuser" / "anonymous"
      ACCESS              = /
      (?:
        (?<access_app> [A-Z0-9]+ )
        (?: \+ (?<access_user> #{ACHAR}+) )?
      )/ix

      #   expire          = ";EXPIRE=" date-time
      #                      ; date-time is defined in [DATETIME]
      EXPIRE              = / ;EXPIRE= (?<expire_date_time>#{BCHAR}+) /ix

      #   iurlauth-rump   = [expire] ";URLAUTH=" access
      IURLAUTH_RUMP = /
      (?:
        (?<expire>#{EXPIRE})? ;URLAUTH= (?<access>#{ACCESS})
      )/ix

      # iurlauth = iurlauth-rump iua-verifier
      IURLAUTH = /
      (?:
        (?<iurlauth-rump>#{IURLAUTH_RUMP})
        (?<iua-verifier> #{IUA_VERIFIER} )
      )/x

      # partial-range     = number ["." nz-number]
      #                     ; partial FETCH.  The first number is
      #                     ; the offset of the first byte,
      #                     ; the second number is the length of
      #                     ; the fragment.
      PARTIAL_RANGE = /(\d+(?:\.[1-9]\d*)?)/

      # Mailbox specials aren't described by §11.  See RFC5092 §7
      INVALID_MAILBOX_SEGMENT = %r{
        \A(?: / | \./ |  \.\./ )
        | (?:    /\./ | /\.\./ )
        | (?:    /\.  | /\.\.  )\z
      }x

      # This regexp adds the requirement that enc-mailbox not start with "/".
      #
      #    enc-mailbox    = 1*bchar
      #                     ; %-encoded version of [IMAP4] "mailbox"
      ENC_MAILBOX = /#{BCHAR_EXCEPT_SLASH}#{BCHAR}*/

      #   uidvalidity     = ";UIDVALIDITY=" nz-number
      #                     ; See [IMAP4] for "nz-number" definition
      #
      UIDVALIDITY = /;UIDVALIDITY=(?<uidvalidity_num>#{NZ_NUMBER})/i

      # imailbox-ref = enc-mailbox [uidvalidity]
      IMAILBOX_REF = /
      (?:
        (?<enc-mailbox>#{ENC_MAILBOX})
        (?<uidvalidity>#{UIDVALIDITY})?
      )/x

      #   ipartial-only   = ";PARTIAL=" partial-range
      IPARTIAL_ONLY       = / ;PARTIAL= (?<enc_prt> #{PARTIAL_RANGE})/ix
      #   isection-only   = ";SECTION=" enc-section
      ISECTION_ONLY       = / ;SECTION= (?<enc_sec> #{BCHAR}+       )/ix
      #   iuid-only       = ";UID=" nz-number
      #                     ; See [IMAP4] for "nz-number" definition
      IUID_ONLY           = / ;UID=     (?<enc_uid> #{NZ_NUMBER}    )/ix

      #   ipartial        = "/" ipartial-only
      IPARTIAL            = %r{ / (?<ipartial-only> #{IPARTIAL_ONLY})}ix

      #   isection        = "/" isection-only
      ISECTION            = %r{ / (?<isection-only> #{ISECTION_ONLY})}ix

      #   iuid            = "/" iuid-only
      IUID                = %r{ / (?<iuid-only>     #{IUID_ONLY}    )}ix

      #   icommand        = imessagelist / imessagepart [iurlauth]
      #   imessagelist    = imailbox-ref [ "?" enc-search ]
      #   imessagepart    = imailbox-ref iuid [isection] [ipartial]
      #
      # Without the query component, imessagelist merely wraps +imailbox-ref+.
      # We can determine +list+ vs +part+ based on whether iuid is present.
      ICOMMAND = /
      (?<imessagelist>
        (?<imailbox-ref>#{IMAILBOX_REF})
      )
      | (?<imessagepart>
          \g<imailbox-ref>
          (?<iuid>    #{IUID}    )
          (?<isection>#{ISECTION})?
          (?<ipartial>#{IPARTIAL})?
        )
        (?<iurlauth>#{IURLAUTH})?
      /ix

      # Combining the path component of both +imapurl+ and +imapurl-rel+ while
      # ignoring non-path components (i.e: <tt>"imap://" iserver</tt>,
      # <tt>inetwork-path</tt>, and <tt>["?" query]</tt>).
      #
      #   imapurl         = "imap://" iserver ipath-query
      #                   ; Defines an absolute IMAP URL
      #
      #   ipath-query     = ["/" [ icommand ]]
      #                   ; Corresponds to "path-abempty [ "?" query ]"
      #                   ; in [URI-GEN]
      #
      #   imapurl-rel     = inetwork-path
      #                   / iabsolute-path
      #                   / irelative-path
      #                   / ipath-empty
      #
      #   iabsolute-path  = "/" [ icommand ]
      #                   ; icommand, if present, MUST NOT start with '/'.
      #                   ;
      #                   ; Corresponds to 'path-absolute [ "?" query ]'
      #                   ; in [URI-GEN]
      #
      #   irelative-path  = imessagelist /
      #                     imsg-or-part
      #                   ; Corresponds to 'path-noscheme [ "?" query ]'
      #                   ; in [URI-GEN]
      #
      #   imsg-or-part    = ( imailbox-ref "/" iuid-only ["/" isection-only]
      #                     ["/" ipartial-only] ) /
      #                   ( iuid-only ["/" isection-only]
      #                     ["/" ipartial-only] ) /
      #                   ( isection-only ["/" ipartial-only] ) /
      #                   ipartial-only
      #
      # +irelative-path+ and +imsg-or-part+ are defined inline, in order
      # to re-use +imessagelist+, +imailbox-ref+, etc from IABSOLUTE_PATH.
      PATH = %r{
      (?:
        (?<ipath-empty>)
      | (?<iabsolute-path> / (?<icommand>#{ICOMMAND})?)
      | (?<irelative-path>
          \g<imessagelist>
        | (?<imsg-or-part>
            \g<imailbox-ref>
            / \g<iuid-only> (?:/ \g<isection-only>)? (?:/ \g<ipartial-only>)?
          |   \g<iuid-only> (?:/ \g<isection-only>)? (?:/ \g<ipartial-only>)?
          |                      \g<isection-only>   (?:/ \g<ipartial-only>)?
          |                                               \g<ipartial-only>
          )
        )
      )}mix

    end
    include RFC5092Regexps

    VALID_ACHAR_STR   = /\A#{ACHAR}+\z/ # NOTE: doesn't match empty string
    VALID_BCHAR_STR   = /\A#{BCHAR}+\z/ # NOTE: doesn't match empty string
    PARTIAL_RANGE_STR = /\A#{PARTIAL_RANGE}\z/
    PATH_STR          = /\A#{PATH}\z/

    module_function

    def valid_achar_string?(str) VALID_ACHAR_STR =~ str end
    def valid_bchar_string?(str) VALID_BCHAR_STR =~ str end

    def valid_achar_nstring?(str) str.nil? || valid_achar_string?(str) end
    def valid_bchar_nstring?(str) str.nil? || valid_bchar_string?(str) end

    def encode_achar(str) pct_encode ACHAR_SPECIALS, str end
    def encode_bchar(str) pct_encode BCHAR_SPECIALS, str end

    #   enc-auth-type    = 1*achar
    #                   ; %-encoded version of [IMAP4] "auth-type"
    #
    # As a special case, +:*+ encodes to +:*+.  This simplifies handling of
    # +iauth+ when it is <tt>";AUTH=*"</tt>.
    def encode_auth_type(auth_type)
      return unless auth_type
      return :*    if auth_type == :*
      return "%2A" if auth_type == "a"
      encode_achar auth_type
    end

    def encode_iauth(auth_type)
      auth_type && ";AUTH=#{encode_auth_type auth_type}"
    end

    def decode_enc_auth_type(enc) enc.to_s == "*" ? :*  : pct_decode(enc) end
    def decode_enc_user(enc)      enc&.empty?     ? nil : pct_decode(enc) end

    # Inputs are the _decoded_ user and auth_type.
    #
    # >>>
    #   iuserinfo        = enc-user [iauth] / [enc-user] iauth
    #                            ; conforms to the generic syntax of
    #                            ; "userinfo" as defined in [URI-GEN].
    def encode_iuserinfo(user, auth_type)
      return unless user || auth_type
      [encode_user(user), encode_iauth(auth_type)].join
    end

    # See RFC5092 §7 for explanation of INVALID_MAILBOX_SEGMENT
    # >>>
    #   enc-mailbox      = 1*bchar
    #                  ; %-encoded version of [IMAP4] "mailbox"
    def encode_mailbox(mailbox)
      return unless mailbox
      mailbox.split("/", -1)
        .map {|segment| encode_bchar segment }
        .join("/")
        .gsub(INVALID_MAILBOX_SEGMENT) { pct_encode %r{[./]}, $& }
    end

    def valid_enc_mailbox?(enc)
      enc.nil? || enc.empty? || # for enc-mailbox, empty is equivalent to nil
        valid_bchar_string?(enc) && INVALID_MAILBOX_SEGMENT !~ enc
    end

    #   imailbox-ref     = enc-mailbox [uidvalidity]
    def encode_imailbox_ref(mailbox, uidvalidity)
      return unless mailbox || uidvalidity
      # validation is handled elsewhere
      [encode_mailbox(mailbox),
        uidvalidity && ";UIDVALIDITY=#{uidvalidity}"]
        .join
    end

    [self, singleton_class].each do |c|
      c.class_exec do

        # enc-user         = 1*achar
        #                ; %-encoded version of [IMAP4] authorization
        #                ; identity or "userid".
        alias_method :encode_user,          :encode_achar
        alias_method :valid_enc_user?,      :valid_achar_nstring?
        alias_method :valid_enc_auth_type?, :valid_achar_nstring?

        # enc-search       = 1*bchar
        #                         ; %-encoded version of [IMAPABNF]
        #                         ; "search-program".  Note that IMAP4
        #                         ; literals may not be used in
        #                         ; a "search-program", i.e., only
        #                         ; quoted or non-synchronizing
        #                         ; literals (if the server supports
        #                         ; LITERAL+ [LITERAL+]) are allowed.
        alias_method :encode_search,     :encode_bchar
        alias_method :valid_enc_search?, :valid_bchar_string?

        # enc-section      = 1*bchar
        #                ; %-encoded version of [IMAP4] "section-spec"
        alias_method :encode_section,     :encode_bchar
        alias_method :valid_enc_section?, :valid_bchar_string?

      end
    end

    # >>>
    #   partial-range    = number ["." nz-number]
    #                    ; partial FETCH.  The first number is
    #                    ; the offset of the first byte,
    #                    ; the second number is the length of
    #                    ; the fragment.
    def decode_partial_range(enc)
      enc =~ PARTIAL_RANGE_STR and
        $1.split(".").map {|number| Integer number }
    end

    def decode_iurlauth(match)
      if match["access"]
        access_app  = match["access_app"].downcase.to_sym
        access_user = (enc = match["access_user"]) && pct_decode(enc)
        access      = {access_app => access_user || true}
      end
      UrlAuthComponent.new(
        pct_decode(match["expire_date_time"]),
        access,
        match["uauth-mechanism"],
        match["enc_urlauth"],
      )
    end

    def encode_partial_range(partial); partial&.join(".") end
    def valid_partial_range?(enc) enc =~ PARTIAL_RANGE_STR || enc.nil?  end

    # NOTE: invalid inputs can generate invalid paths.
    # Validation is handled elsewhere.
    def encode_path(mailbox: nil, uidvalidity: nil,
                    uid: nil, section: nil, partial: nil,
                    urlauth: nil,
                    **)
      return unless mailbox || uidvalidity || uid || section || partial
      imailbox_ref = encode_imailbox_ref(mailbox, uidvalidity)
      parts = []
      parts << "" << imailbox_ref if imailbox_ref
      {
        uid:     uid,
        section: encode_section(section),
        partial: encode_partial_range(partial),
      }.compact.each do |k, v|
        parts << ";#{k.upcase}=#{v}"
      end
      urlauth and raise "TODO: encode urlauth"
      parts.join("/")
    end

    # Returns a hash of regexp named captures, if #path matches the RFC5092
    # grammar for <tt>iabsolute-path</tt>, <tt>irelative-path</tt> or
    # <tt>ipath-empty</tt>.  Groups are named according to rules in the
    # RFC5092 or RFC5593 formal syntax, with a few additional groups for
    # convenience: +uidvalidity_num+, +enc_uid+, +enc_sec+, +enc_prt+,
    # +access_user+.  Note: the RFC rules use "-" and the groups defined by
    # URI::IMAP use "_".
    #
    # We'll _attempt_ to give a nice error message when a path doesn't match.
    def split_rfc5092_path(path)
      begin
        path = path.to_str
      rescue NoMethodError
        bad_path path, "not a string"
      end
      path.ascii_only? or bad_path path, "must be ascii only"
      case path
      when PATH_STR
        $~.named_captures
      when %r{\A/?#{UIDVALIDITY}}i
        bad_path path, "UIDVALIDITY without a mailbox"
      when %r{\A/?#{IMAILBOX_REF}#{ISECTION}}i
        bad_path path, "mailbox-ref and section without a UID"
      when %r{\A/?#{IMAILBOX_REF}#{IPARTIAL}}i
        bad_path path, "mailbox-ref and partial without a UID"
      else
        bad_path path, "invalid"
      end
    end

    def bad_path(path, reason)
      raise InvalidComponentError, "invalid IMAP UID path (%s): %p" % [
        reason, path
      ]
    end

    def pct_encode(specials, str)
      return unless str
      URI.send :_encode_uri_component, specials, TBLENCURICOMP_, str, nil
    end
    private_class_method :pct_encode

    def pct_decode(str) str and URI.decode_uri_component str end
    private_class_method :pct_decode

  end
end
