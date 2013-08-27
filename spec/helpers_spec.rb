# -*- encoding: utf-8 -*-

require File.expand_path('../spec_helper.rb', __FILE__)

class HelperTest
  attr_accessor :request
  include Rack::Policy::Helpers

  def initialize
    @request = HelperTest::Request.new
  end

  class Request
    attr_reader :env
    def initialize; @env = {}; end
  end
end

describe Rack::Policy::Helpers do

  let(:helper_test) { HelperTest.new }

  before do
    helper_test.request.env.stub(:has_key?).and_return true
  end

  it "guards against missing key" do
    helper_test.request.env.stub(:has_key?).and_return false
    helper_test.cookies_accepted?.should be_false
  end

  context "unset" do
    before do
      helper_test.request.env.stub(:[]).with('rack-policy.consent') { :unset }
    end

    it "doesn't accept cookies" do
      helper_test.cookies_accepted?.should be_false
    end

    it "reject cookies" do
      helper_test.cookies_rejected?.should be_false
    end
  end

  context "accepted" do
    before do
      helper_test.request.env.stub(:[]).with('rack-policy.consent') { :accepted }
    end

    it "doesn't accept cookies" do
      helper_test.cookies_accepted?.should be_true
    end

    it "reject cookies" do
      helper_test.cookies_rejected?.should be_false
    end

    it "yields to the block" do
      helper_test.request.env.stub(:[]).with('rack-policy.consent') { :accepted }
      block = Proc.new { 'Accepted'}
      helper_test.should_receive(:cookies_accepted?).and_yield(&block)
      helper_test.cookies_accepted?(&block)
    end
  end

  context "rejected" do
    before do
      helper_test.request.env.stub(:[]).with('rack-policy.consent') { :rejected }
    end

    it "doesn't accept cookies" do
      helper_test.cookies_accepted?.should be_false
    end

    it "reject cookies" do
      helper_test.cookies_rejected?.should be_true
    end

    it "yields to the block" do
      helper_test.request.env.stub(:[]).with('rack-policy.consent') { :rejected }
      block = Proc.new { 'Rejected'}
      helper_test.should_receive(:cookies_rejected?).and_yield(&block)
      helper_test.cookies_rejected?(&block)
    end
  end

end # Rack::Policy::Helpers
