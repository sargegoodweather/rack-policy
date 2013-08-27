# -*- encoding: utf-8 -*-

module Rack
  module Policy
    module Helpers

      def cookies_accepted?
        return false unless request.env.has_key? 'rack-policy.consent'
        accepted = request.env['rack-policy.consent'] == :accepted
        yield if block_given? && accepted
        accepted
      end

      def cookies_rejected?
        return false unless request.env.has_key? 'rack-policy.consent'
        rejected = request.env['rack-policy.consent'] == :rejected
        yield if block_given? && rejected
        rejected
      end

    end # Helpers
  end # Policy
end # Rack
