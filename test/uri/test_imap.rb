# frozen_string_literal: true

require "test/unit"
require "uri/imap"

module URI
  class TestIMAP < Test::Unit::TestCase

    def uri_to_ary(uri)
      uri.class.component.collect {|c| uri.send(c) }
    end

    def test_imap_in_schemes
      assert_include URI.scheme_list.keys, "IMAP"
    end

    def test_parse
      url = "imap://minbari.example.org/gray-council;UIDVALIDITY=385759045/" \
            ";UID=20/;PARTIAL=0.1024"
      u = URI.parse(url)
      assert_kind_of URI::IMAP, u
      assert_equal url, u.to_s
      assert_equal "gray-council", u.mailbox
      assert_equal    385_759_045, u.uidvalidity
      assert_equal             20, u.uid
      assert_equal      [0, 1024], u.partial
    end

    # The first group of examples come from RFC5092 §9, excluding §9.1.
    {
      "imap://minbari.example.org/gray-council;UIDVALIDITY=385759045/;" \
      "UID=20/;PARTIAL=0.1024" =>
      [
        "imap", nil, nil, "minbari.example.org", URI::IMAP::DEFAULT_PORT,
        "gray-council", 385_759_045, 20, nil, [0, 1024], nil, nil,
      ],
      "imap://psicorp.example.org/~peter/%E6%97%A5%E6%9C%AC%E8%AA%9E/" \
      "%E5%8F%B0%E5%8C%97" =>
      [
        "imap", nil, nil, "psicorp.example.org", URI::IMAP::DEFAULT_PORT,
        "~peter/日本語/台北", nil, nil, nil, nil, nil, nil,
      ],
      "imap://;AUTH=GSSAPI@minbari.example.org/gray-council/;uid=20/" \
      ";section=1.2" =>
      [
        "imap", nil, "GSSAPI", "minbari.example.org", URI::IMAP::DEFAULT_PORT,
        "gray-council", nil, 20, "1.2", nil, nil, nil,
      ],
      ";section=1.4" =>
      [
        nil, nil, nil, nil, nil,
        nil, nil, nil, "1.4", nil, nil, nil,
      ],
      "imap://;AUTH=*@minbari.example.org/gray%20council?SUBJECT%20shadows" =>
      [
        "imap", nil, :*, "minbari.example.org", URI::IMAP::DEFAULT_PORT,
        "gray council", nil, nil, nil, nil, nil, "SUBJECT shadows",
      ],
      "imap://john;AUTH=*@minbari.example.org/babylon5/personel?" \
      "charset%20UTF-8%20SUBJECT%20%7B14+%7D%0D%0A%D0%98%D0%B2%" \
      "D0%B0%D0%BD%D0%BE%D0%B2%D0%B0" =>
      [
        "imap", "john", :*, "minbari.example.org", URI::IMAP::DEFAULT_PORT,
        "babylon5/personel", nil, nil, nil, nil, nil,
        "charset UTF-8 SUBJECT {14+}\r\nИванова",
      ],
    }.each_with_index do |(url, ary), idx|
      next unless ary.first # skip the relative URL, at least for here and now

      define_method :"test_parse_rfc5092_section_9_example_#{idx}" do
        u = URI.parse(url)
        # pp url:, ary:;
        assert_equal(ary, uri_to_ary(u))
      end

      define_method :"test_build_rfc5092_section_9_example_#{idx}" do
        # pp url:, ary:;
        built = URI::IMAP.build(ary[1..-1]).to_s
        upcase_expected = url.gsub(/;(\w+)=/) { ";#{$1.upcase}=" }
        upcase_actual = built.gsub(/;(\w+)=/) { ";#{$1.upcase}=" }
        assert_equal upcase_expected, upcase_actual
      end
    end

    {
      opaque: ["imap:https://example.org", /opaque.*is invalid/i],
      password: ["imap://u:p@example.org", /password.*is invalid/i],
      uidvalidity_without_mailbox: ["imap://localhost/;UIDVALIDITY=1",
                                    "UIDVALIDITY without a mailbox"],
      section_without_uid: ["imap://localhost/mbox/;SECTION=1",
                            /mailbox.*section.*without.*UID/i],
      partial_without_uid: ["imap://localhost/mbox/;PARTIAL=1",
                            /mailbox.*partial.*without.*UID/i],
      query_without_mailbox: ["imap://localhost/?FLAGGED",
                              /search.*without.*mailbox/i],
    }.each do |name, (uri, msg)|
      define_method :"test_parse_invalid_#{name}" do
        err_msg = nil
        assert_raise(URI::InvalidComponentError) do
          parsed = URI.parse(uri)
          pp uri_to_ary parsed # for debugging failures
        rescue => err
          err_msg = err.message
          raise
        end
        assert_match msg, err_msg
      end
    end

    # Some of the following examples are from RFC5092, section 9.1.
    #
    # I chose one or more base URLs to use with each example, in order to
    # demonstrate.  This shows that path normalization (e.g. dot removal) also
    # applies to absolute paths, prior to path decoding and validation.

    def test_rfc5092_section_9_relative_section_url
      base = URI("imap://;AUTH=GSSAPI@minbari.example.org/gray-council/" \
                 ";uid=20/;section=1.2")
      rel = ";section=1.4"
      assert_equal("imap://;AUTH=GSSAPI@minbari.example.org/gray-council/" \
                   ";uid=20/;section=1.4", base.merge(rel).to_s)
      assert_equal [
        "imap", nil, "GSSAPI", "minbari.example.org", URI::IMAP::DEFAULT_PORT,
        "gray-council", nil, 20, "1.4", nil, nil, nil,
      ], uri_to_ary(base + rel)
    end

    # TODO: should enc-mailbox="foo" and enc-mailbox="foo/" be equivalent?
    def test_rfc5092_section_9_1_relative_uri_evaluates_dot_dot
      base = URI("imap://example.com/namespace/mbox/;uid=123")
      rel  = "/foo/;UID=20/.."
      components = [
        "imap", nil, nil, "example.com", 143,
        # "foo", # <--- equivalent value, according to RFC5092 §9.1
        "foo/",  # <--- imailbox-ref indicated by ABNF and RFC3986 §5
        nil, nil, nil, nil, nil, nil,
      ]
      uri  = base + rel
      assert_equal "imap://example.com/foo/", uri.to_s
      assert_equal components,                uri_to_ary(uri)
    end

    class TestRegexps < Test::Unit::TestCase

      find_regexps = ->(mod, modname = mod.name) {
        mod.constants.flat_map {|name|
          case (const = mod.const_get(name))
          when Module then find_regexps[const, name]
          when Regexp then [[name, const]]
          end
        }
          .map {|name, re| ["%s::%s" % [modname, name], re] }
      }

      regexps = find_regexps[URI::IMAP::RFC5092Regexps]
        .map {|name, re| [name, [name, re]] }
        .to_h
      data(regexps, keep: true)

      if Regexp.respond_to?(:linear_time?)
        def test_linear_time_regexps((name, regexp))
          return if [
            URI::IMAP::RFC5092Regexps::ICOMMAND, # TODO: show that \g<group> is linear
            URI::IMAP::RFC5092Regexps::PATH,     # TODO: same as above
          ].include?(regexp)
          assert(Regexp.linear_time?(regexp),
                 "#{name} should run in linear time")
        end
      end
    end

  end
end
