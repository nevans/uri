# frozen_string_literal: true
# shareable_constant_value: literal

#
# = uri/imap.rb
#
# Author:: Nicholas Evans
# License:: You can redistribute it and/or modify it under the same term as Ruby.
#
# See URI for general documentation
#

require_relative "generic"
require_relative "rfc5092_parser"

module URI

  # The syntax of IMAP URIs is defined in RFC5092 and updated by RFC5593.
  #
  # An IMAP URL may refer to an IMAP server (see RFC 5092 §4), the contents of a
  # mailbox or a set of messages resulting from a search (see RFC5092 §5), or a
  # specific message or part of a message.
  #
  #    # IMAP server URIs
  #    uri = URI("imap://imap.example.com/")
  #    uri.port # => 143
  #    uri = URI("imaps://mail.example.com/")
  #    uri.port # => 993
  #
  #    # Contents of a mailbox, or the subset resulting from a search:
  #    uri = URI("imaps://mail.example.com/Inbox;UIDVALIDITY=1234")
  #    uri.mailbox     # => Inbox
  #    uri.uidvalidity # => 1234
  #    uri = URI("imaps://mail.example.com/%E3%83%A1%E3%83%BC%E3%83%AA%E3%83" \
  #              "%B3%E3%82%B0%E3%83%AA%E3%82%B9%E3%83%88")
  #    uri.mailbox     # => "メーリングリスト"
  #    uri = URI("imaps://mail.example.com/uri?SentSince%209-Aug-2020%20" \
  #              "(OR%20SUBJECT%20net-imap%20SUBJECT%20uri)")
  #    uri.search # => "SentSince 9-Aug-2020 (OR SUBJECT net-imap SUBJECT uri)"
  #
  #    # A specific message or part of a message
  #    uri = URI("imaps://example.com/inbox/;UID=5678")
  #    uri.uid # => 5678
  #    uri = URI("imaps://example.com/inbox/;UID=5678/;section=3.1.4/;partial=0.1024")
  #    uri.section # => "3.1.4"
  #    uri.partial # => [0, 1024]
  #
  # URI::IMAP attribute methods get and set the plain component values, parsed
  # and decoded from the URI.  Use #userinfo, #path, #query, or the +enc_*+
  # methods to get or set the pct-encoded values.
  #
  class IMAP < Generic
    # A Default port of 143 for URI::IMAP
    DEFAULT_PORT = 143

    # An Array of the available components for URI::IMAP.
    COMPONENT = %i[
      scheme
      user
      auth_type
      host
      port
      mailbox
      uidvalidity
      uid
      section
      partial
      urlauth
      search
    ].freeze

    # See RFC5092 §6.1.
    class UrlAuthComponent < Struct.new(:expire, :access, :mechanism, :token)

      ##
      # method: expire
      # :call-seq: expire -> nil or Time
      #
      # Returns the latest Time when the URL is valid, after which it has
      # expired.  Returns +nil+ if the URI has no specific expiration time.
      #
      # TODO: strptime/strftime to parse/format from/to a Time object.

      ##
      alias expires_at  expire
      alias valid_until expire

      ##
      # method: access
      # :call-seq: access -> { access type => user id or true }
      #
      # Returns the "Authorized Access Identifier" as a hash with exactly one
      # key/value pair.  The key is an access type and the value will be a user
      # id or +true+ (when the access type does not limit access by specific
      # user).  The access types defined in RFC5092 and RFC5593 are:
      #
      # <tt>:authuser</tt>::
      #   When set, the value will always be +true+.  Used to restrict access to
      #   IMAP sessions that are logged in as any non-anonymous user of that
      #   IMAP server.
      # <tt>:anonymous</tt>::
      #   When set, the value will always be +true+.  Indicates that use of this
      #   URL is not restricted by session authorization identity.
      # <tt>:stream</tt>::
      #   When set, the value will always be +true+.  Used by SIP Media Servers
      #   to retrieve attachments for streaming to email clients.
      # <tt>:submit</tt>::
      #   When set, the value is a _decoded_ user id string.  Used by message
      #   submission entities to retrieve attachments to be included in
      #   submitted messages.
      # <tt>:user</tt>::
      #   When set, the value is a _decoded_ user id string.  Used to restrict
      #   access to IMAP sessions that are logged in as the specified userid.
      #
      # Using the syntax in RFC5593, any new or unknown <tt>"<access>
      # identifier"</tt> or <tt>"<access> identifier prefix"</tt> will follow
      # the same pattern, with the lower-case identifier or prefix as a symbol
      # for the key and either +true+ or a user id for the value.
      #
      # See RFC5092 §6.1.2 and RFC5593.

      ##
      alias access_identifier  access

      ##
      # method: mechanism
      # :call-seq: mechanism -> String
      #
      # Returns the name of the algorithm by which the URLAUTH is generated and
      # subsequently verified.

      ##
      # method: token
      # :call_seq: token -> binary string
      #
      # Returns a _decoded_ _binary_ String of at least 128-bits long, that can
      # be used to verify the URL.

    end

    include RFC5092Parser

    #
    # == Description
    #
    # Creates a new URI::IMAP object from components, with syntax checking.
    #
    # The components accepted are +scheme+, +user+ +auth_type+, +host+, +port+,
    # +mailbox+, +uidvalidity+, +uid+, +section+, +partial+, +search+, and
    # +urlauth+.
    #
    # The components should be provided either as an Array, or as a Hash
    # with keys formed by preceding the component names with a colon.
    #
    # If an Array is used, the components must be passed in the
    # order <code>[user, auth_type, host, port, mailbox, uidvalidity, uid,
    # section, partial, urlauth, search]</code>.
    #
    # Example:
    #
    #     uri = URI::IMAP.build(host: "mail.example.com", mailbox: "INBOX",
    #                           uidvalidity: 12345, uid: 20)
    #     uri.to_s # => "imap://mail.example.com/INBOX;UIDVALIDITY=12345;UID=20"
    #
    def self.build(args)
      tmp = Util.make_components_hash(self, args)
      tmp[:userinfo] = RFC5092Parser.encode_iuserinfo tmp[:user], tmp[:auth_type]
      tmp[:path]     = RFC5092Parser.encode_path(**tmp)
      tmp[:query]    = RFC5092Parser.encode_search tmp[:search]
      super(tmp)
    end

    def initialize(*args)
      # Avoid "instance variable @ivarname not initialized warnings in ruby 2.x
      @auth_type   = nil
      @mailbox     = nil
      @uidvalidity = nil
      @section     = nil
      @partial     = nil
      @urlauth     = nil
      super
      check_userinfo    @user, @password
      check_path        @path
      check_mailbox     @mailbox
      check_uidvalidity @uidvalidity
      check_section     @section
      check_partial     @partial
      check_urlauth     @urlauth
      check_search      search
    end

    # disable invalid generic components
    %i[password opaque registry fragment].each do |component|
      %I[check_#{component} set_#{component} #{component}=].each do |m|
        define_method m do |value, *|
          if value
            raise URI::InvalidComponentError, "#{component} is invalid for IMAP URI"
          end
        end
      end

      # matching the visibility pattern established by Generic
      public    :"#{component}="
      protected :"set_#{component}"
      private   :"check_#{component}"
    end

    def absolute_path?(path = @path) path&.start_with?("/") end

    # Returns the encoded userinfo value, if either #user or #auth_type is set.
    #
    # See also #user, #enc_user, #auth_type, #enc_auth_type.
    def userinfo; encode_iuserinfo @user, @auth_type end

    protected

    # In Generic, userinfo is stored in @user and @password, which are stored in
    # encoded form.  In IMAP, userinfo is stored in @user and @auth_type, which
    # are stored in decoded form.  But userinfo and userinfo= will get/set the
    # encoded form.
    def set_userinfo(user, pass = nil)
      userinfo, pass  = super
      set_password pass # handles InvalidComponentError
      user, auth_type = split_iuserinfo userinfo
      user      &&= user.empty?      ? nil : pct_decode(user)
      auth_type &&= auth_type == "*" ? :*  : pct_decode(auth_type)
      @user       = user
      @auth_type  = auth_type
      [userinfo, nil]
    end

    private

    def check_userinfo(iuserinfo, password = nil)
      super # runs check_password, which raises if password is set
      enc_user, enc_auth_type = split_iuserinfo iuserinfo
      valid_enc_user?(enc_user) or enc_user&.empty? or
        raise InvalidComponentError, "bad enc-user: %p" % [enc_user]
      valid_enc_auth_type?(enc_auth_type) or
        raise InvalidComponentError, "bad enc-auth-type: %p" % [enc_auth_type]
      true
    end

    def split_iuserinfo(user)
      user&.split(";AUTH=", 2)
    end

    public

    ##
    # Returns the _decoded_ value of #enc_user.
    #
    # *NOTE*: IMAP#user breaks compatibility with Generic#user: it has been
    # split into #user and #auth_type, and both are _decoded_.  Use #enc_user or
    # #userinfo to get the encoded forms, and #enc_user= or #userinfo= to set
    # the encoded forms.
    #
    # From RFC5092 §3.2:
    # >>>
    #   Note that the user also defines a mailbox naming scope.
    #
    #   The IMAP user name and the authentication mechanism are used in the
    #   "LOGIN" or "AUTHENTICATE" commands after making the connection to the
    #   IMAP server.
    #
    # See also #enc_user, #auth_type, #enc_auth_type, #userinfo.
    #
    #--
    # TODO: should this be #userid instead, and compatbility can be preserved?
    #++
    attr_reader :user

    # Returns +enc-user+, the pct-encoded value for #user.
    #
    # See also #user, #auth_type, #enc_auth_type, #userinfo.
    def enc_user; encode_user @user end

    # Set #user using a pct-encoded +val+.
    #
    # See also #user, #enc_user, #auth_type, #enc_auth_type, #userinfo.
    def enc_user=(val)
      check_enc_user(val)
      self.user = decode_enc_user(val)
    end

    protected

    # Override the base class definition to simply set @user directly.
    def set_user(user)
      @user = user
    end

    private

    def check_user(user)
      super encode_user(user)
    end

    def check_enc_user(enc_user)
      check_user enc_user
      valid_enc_user? enc_user or
        raise InvalidComponentError, "invalid enc-user: %p" % [enc_user]
    end

    public

    ##
    # Returns the _decoded_ name of the SASL authentication mechanism (as used
    # by the IMAP AUTHENTICATE command) as a string.  Returns the symbol +:*+ to
    # indicate that the URL is not anonymous and the client should select an
    # appropriate authentication mechanism.
    #
    # Note that +:*+ corresponds to <tt>";AUTH=*"</tt> and <tt>"*"</tt>
    # corresponds to <tt>";AUTH=%2A"</tt>, and these are semantically different.
    #
    # See RFC5092 §3.
    #
    # See also #auth_type=, #user, #enc_user, #enc_auth_type, #userinfo.
    attr_reader :auth_type

    # Set #auth_type to +val+, with validation.
    #
    # For <tt>";AUTH=*"</tt>, set to <tt>:*</tt>.  Setting to <tt>"*"</tt> will
    # encode as <tt>";AUTH=%2A"</tt>.
    #
    # See also #user, #enc_user, #auth_type, #enc_auth_type, #userinfo.
    def auth_type=(val)
      check_auth_type(val)
      set_auth_type(val)
    end

    # Returns +enc-auth-type+, the pct-encoded value for #auth_type.
    #
    # See also #user, #enc_user, #auth_type, #userinfo.
    def enc_auth_type; encode_auth_type @auth_type end

    # Set #auth_type using a pct-encoded +val+.
    #
    # See also #user, #enc_user, #auth_type, #enc_auth_type, #userinfo.
    def enc_auth_type=(val)
      check_enc_auth_type(val)
      self.auth_type = decode_enc_auth_type(val)
    end

    protected

    def set_auth_type(auth_type)
      @auth_type = auth_type
    end

    private

    def check_enc_auth_type(enc_auth_type)
      check_user enc_auth_type
      valid_enc_auth_type? enc_auth_type or
        raise InvalidComponentError, "invalid enc-auth-type: %p" % [enc_auth_type]
    end

    def check_auth_type(auth_type)
      check_user encode_iauth(auth_type)
    end

    protected

    # Set #path to the given value, with minimal validation.  The inverse of
    # #rebuild_path.
    #
    # See also #path= and #rebuild_path.
    #
    # >>>
    #   *Note*: because +path+ must be parsed, IMAP#set_path does validate more
    #   than Generic#set_path.  Use #path= to invoke all path validations.
    def set_path(path)
      super
      # normalize the path
      return if ["/", "", nil].include?(path)
      m = split_rfc5092_path URI.normalize_path path
      # if split_rfc5092_path returned without error, the path is (probably)
      # valid, and none of the following should raise an exception either.
      @mailbox     = (enc = m["enc-mailbox"])     && pct_decode(enc)
      @uidvalidity = (enc = m["uidvalidity_num"]) && Integer(enc)
      @uid         = (enc = m["enc_uid"])         && Integer(enc)
      @section     = (enc = m["enc_sec"])         && pct_decode(enc)
      @partial     = (enc = m["enc_prt"])         && decode_partial_range(enc)
      @urlauth     =        m["iurlauth"]         && decode_iurlauth(m)
    end

    # Updates #path with the current component instance variable values, with
    # minimal validation.  Implicitly called when setting any components stored
    # in #path.  The inverse of #set_path.
    #
    # See also #set_path.
    def rebuild_path
      path = encode_path(
        mailbox:     @mailbox,
        uidvalidity: @uidvalidity,
        uid:         @uid,
        section:     @section,
        partial:     @partial,
        urlauth:     @urlauth
      )
      # check_path path
      @path = path
    end

    private

    def check_path(path)
      super
      split_rfc5092_path path
      true
    end

    public

    # Returns the encoded <tt>imailbox-ref</tt> path segments, which contain the
    # encoded #mailbox and the #uidvalidity.
    def mailbox_ref
      encode_imailbox_ref(@mailbox, @uidvalidity)
    end

    # Returns the _decoded_ mailbox name from the #path.
    #
    #   URI("imap://mail.example.com/foo/bar;UIDVALIDITY=1234").mailbox
    #   # => "foo/bar"
    #   URI("imap://minbari.example.org/gray%20council?FLAGGED").mailbox
    #   # => "gray council"
    #   URI("imap://psicorp.example.org/~peter/%E6%97%A5%E6%9C%AC%E8%AA%9E/" \
    #       "%E5%8F%B0%E5%8C%97").mailbox
    #   # => "~peter/日本語/台北"
    #
    # *Note*: +IMAP4rev1+ servers encode mailbox names using a modified form of
    # UTF7.  See Net::IMAP.encode_utf7 and Net::IMAP.decode_utf7.  +IMAP4rev2+
    # servers, or servers with the +UTF8=ACCEPT+ (or +UTF8=ONLY+) capability,
    # are able to send and recieve UTF-8 encoded mailbox names.
    attr_reader :mailbox

    # Sets the decoded mailbox name to +val+, with validation.
    #
    # #path will be set to the _encoded_ mailbox name, and dependant components
    # (#uidvalidity, #uid, #section, #partial, #urlauth) will be set to +nil+.
    def mailbox=(val)
      check_mailbox(val)
      set_mailbox(val)
    end

    protected

    # Set #mailbox with minimal validation, and remove dependant path segments.
    #
    # See also #mailbox=.
    def set_mailbox(mailbox)
      return unless mailbox
      @uidvalidity = @uid = @section = @partial = @urlauth = nil
      @mailbox = mailbox
      rebuild_path
      @mailbox
    end

    private

    def check_mailbox(mailbox)
      # nothing really to do here, is there?
    end

    public

    # Returns the UIDVALIDITY value for a mailbox_ref.
    #
    #   URI("imap://mail.example.com/foo/bar;UIDVALIDITY=1234").uidvalidity
    #   # => 1234
    attr_reader :uidvalidity

    # Sets the #uidvalidity to +val+, with validation.
    #
    # #path will be updated and dependant components (#uid, #section, #partial,
    # #urlauth) will be set to +nil+.
    def uidvalidity=(val)
      check_uidvalidity(val)
      set_uidvalidity(val)
    end

    protected

    # Set #uidvalidity with minimal validation, removing dependant path
    # segments.
    #
    # See also #uidvalidity=.
    def set_uidvalidity(uidvalidity)
      return unless uidvalidity
      @uid = @section = @partial = @urlauth = nil
      @uidvalidity = uidvalidity
      rebuild_path
      @uidvalidity
    end

    private

    def check_uidvalidity(uidvalidity)
      return unless uidvalidity
      if !(
          uidvalidity.is_a?(Integer) && uidvalidity.positive? ||
          uidvalidity.is_a?(String) && uidvalidity =~ /\A#{NZ_NUMBER}\z/
        )
        raise InvalidComponentError, "UIDVALIDITY must be a positive Integer"
      elsif !mailbox
        raise InvalidComponentError, "UIDVALIDITY requires a mailbox"
      end
    end

    public

    # Returns the UID for a message.
    attr_reader :uid

    # Sets the #uid to +val+, with validation.
    #
    # #path will be updated and dependant components (#uid, #section,
    # #partial, #urlauth) will be set to +nil+.
    def uid=(val)
      check_uid(val)
      set_uid(val)
    end

    protected

    # Set #uid with minimal validation, removing dependant path segments.
    #
    # See also #uid=.
    def set_uid(uid)
      return unless uid
      @section = @partial = @urlauth = nil
      @uid = uid
      rebuild_path
      @uid
    end

    private

    def check_uid(uid)
      return unless uid
      return unless absolute_path?
      return if     mailbox
      raise InvalidComponentError, "UID invalid " \
                                   "(absolute path is missing a mailbox)"
    end

    public

    # Returns the +section+ component from the +path+;
    attr_reader :section

    # Sets the #section to +val+, with validation.
    #
    # #path will be updated and dependant components (#partial, #urlauth) will
    # be set to +nil+.
    def section=(val)
      check_section(val)
      set_section(val)
    end

    protected

    # Set #section with minimal validation, removing dependant path segments.
    #
    # See also #section=.
    def set_section(section)
      return unless section
      @partial = @urlauth = nil
      @section = section
      rebuild_path
      @section
    end

    private

    def check_section(section)
      return unless section
      # check_path handles this so: TODO: delegate to check_path
      if mailbox && !uid && section
        raise InvalidComponentError, "message section invalid, " \
                                     "has a mailbox but missing a UID " \
                                     "(imailbox-ref iuid isection)"
      end
      return unless absolute_path?
      return if uid # let #check_uid handle missing mailbox
      raise InvalidComponentError, "message section invalid, " \
                                   "(absolute path is missing a UID)"
    end

    public

    # Returns the +partial+ as an array of <tt>[size, length]</tt>.
    attr_reader :partial

    # Sets the #partial to +val+, with validation.
    #
    # #path will be updated and dependant components (#urlauth) will be set to
    # +nil+.
    def partial=(val)
      check_partial(val)
      set_partial(val)
    end

    protected

    # Set #partial with minimal validation, removing dependant path segments.
    #
    # See also #partial=.
    def set_partial(partial)
      return unless partial
      @urlauth = nil
      @partial = partial
      rebuild_path
      @partial
    end

    private

    def check_partial(partial)
      return unless partial
      # check_path handles this so: TODO: delegate to check_path
      if mailbox && !uid
        raise InvalidComponentError, "message partial invalid, " \
                                     "has a mailbox but missing a UID " \
                                     "(imailbox-ref iuid isection)"
      end
      return unless absolute_path?
      return if uid # let #check_uid handle missing mailbox
      raise InvalidComponentError, "message partial invalid, " \
                                   "(absolute path is missing a UID)"
      # TODO: check for Integer, [Integer, Integer], /\d+(\.\d+)?/
    end

    public

    # When set, #urlauth returns a UrlAuthComponent object.
    #
    # See UrlAuthComponent for details.
    attr_reader :urlauth

    # Sets the #urlauth to +val+, with validation.
    #
    # +val+ should be a UrlAuthComponent object, or a string to set the path
    # component directly.
    def urlauth=(val)
      check_urlauth(val)
      set_urlauth(val)
    end

    protected

    # Set #urlauth with minimal validation.
    #
    # See also #urlauth=.
    def set_urlauth(urlauth)
      @urlauth.is_a?(UrlAuthComponent) or
        raise ArgumentError, "urlauth must be a string or UrlAuthComponent"
      @urlauth = urlauth
      rebuild_path
      @urlauth
    end

    private

    def check_urlauth(urlauth)
      # TODO... check that it's a UrlAuthComponent with approriate values
    end

    public

    # Returns the decoded mailbox #search string.
    #
    # #search is stored in #query, in encoded form.
    def search; pct_decode query if query end

    # Sets #query to the decoded +search+ string, with validations.
    #
    # #search is stored in #query, in encoded form.
    def search=(search)
      check_search(search)
      self.query = encode_search search&.empty? ? nil : search
    end

    private

    def check_search(search)
      return unless search
      if !mailbox || mailbox.empty?
        raise InvalidComponentError, "bad IMAP URI (search without mailbox)"
      elsif uid
        raise InvalidComponentError, "bad IMAP URI (search inside message part)"
      end
    end

  end

  register_scheme "IMAP", IMAP
end
