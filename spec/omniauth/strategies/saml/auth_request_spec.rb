require 'spec_helper'

describe OmniAuth::Strategies::SAML::AuthRequest do
  describe :create do
    let(:url) do
      described_class.new.create(
        {
          :idp_sso_target_url => 'example.com',
          :assertion_consumer_service_url => 'http://example.com/auth/saml/callback',
          :issuer => 'This is an issuer',
          :name_identifier_format => 'Some Policy'
        },
        {
          :some_param => 'foo',
          :some_other => 'bar'
        }
      )
    end
    let(:saml_request) { url.match(/SAMLRequest=(.*)/)[1] }

    describe "the url" do
      subject { url }

      it "should contain a SAMLRequest query string param" do
        subject.should match /^example\.com\?SAMLRequest=/
      end

      it "should contain any other parameters passed through" do
        subject.should match /^example\.com\?SAMLRequest=(.*)&some_param=foo&some_other=bar/
      end
    end

    describe "the saml request" do
      subject { saml_request }

      let(:decoded) do
        cgi_unescaped = CGI.unescape(subject)
        base64_decoded = Base64.decode64(cgi_unescaped)
        Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(base64_decoded)
      end

      let(:xml) { Nokogiri::XML::Document.parse(decoded) }
      let(:root_element) { xml.at_xpath('.//samlp:AuthnRequest', { 'samlp' => 'urn:oasis:names:tc:SAML:2.0:protocol' }) }

      it "should contain base64 encoded and zlib deflated xml" do
        decoded.should match /^<samlp:AuthnRequest/
      end

      it "should contain a uuid with an underscore in front" do
        UUID.any_instance.stub(:generate).and_return('MY_UUID')

        root_element.attributes['ID'].to_s.should == '_MY_UUID'
      end

      it "should contain the current time as the IssueInstant" do
        t = Time.now
        Time.stub(:now).and_return(t)

        root_element.attributes['IssueInstant'].to_s.should == t.utc.iso8601
      end

      it "should contain the callback url in the settings" do
        root_element.attributes['AssertionConsumerServiceURL'].to_s.should == 'http://example.com/auth/saml/callback'
      end

      it "should contain the issuer" do
        xml.at_xpath('.//saml:Issuer', { 'saml' => 'urn:oasis:names:tc:SAML:2.0:assertion' }).text.should == 'This is an issuer'
      end

      it "should contain the name identifier format" do
        xml.at_xpath('.//samlp:NameIDPolicy', { 'samlp' => 'urn:oasis:names:tc:SAML:2.0:protocol' }).attributes['Format'].to_s.should == 'Some Policy'
      end
    end
  end
end
