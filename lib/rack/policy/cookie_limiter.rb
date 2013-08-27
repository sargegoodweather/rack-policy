# -*- encoding: utf-8 -*-

module Rack
  module Policy
    # This is the class for limiting cookie storage on client machine.
    class CookieLimiter
      include ::Rack::Utils

      HTTP_COOKIE   = "HTTP_COOKIE".freeze
      SET_COOKIE    = "Set-Cookie".freeze
      CACHE_CONTROL = "Cache-Control".freeze
      CONSENT_TOKEN = "cookie_limiter".freeze
      WHITE_LIST = [].freeze

      attr_reader :app, :options

      # The environment of the request
      attr_reader :env

      # HTTP message
      attr_reader :status, :headers, :body

      # @option options [String] :consent_token
      #
      def initialize(app, options={})
        @app, @options = app, options
      end

      def consent_token
        @consent_token ||= options[:consent_token] || CONSENT_TOKEN
      end

      def white_list
        @white_list ||= options[:white_list] || WHITE_LIST
      end

      def expires
        Time.parse(options[:expires]) if options[:expires]
      end

      def call(env)
        dup.call!(env)
      end

      def call!(env)
        @env = env
        request = Rack::Request.new(env)
        accepts?(request)
        @status, @headers, @body = @app.call(env)
        response = Rack::Response.new body, status, headers
        clear_cookies!(request, response) unless allowed?(request)
        finish
      end

      # Identifies the approval of cookie policy inside rack app.
      #
      def accepts?(request)
        if ( request.cookies.has_key?(consent_token.to_s) )
          @env['rack-policy.consent'] = 'true'
        else
          if (cookie_string = @env[HTTP_COOKIE])
            @env[HTTP_COOKIE] = filtered_cookie_string cookie_string
          end
          @env['rack-policy.consent'] = nil
        end
      end

      # Returns `false` if the cookie policy disallows cookie storage
      # for a given request, or `true` otherwise.
      #
      def allowed?(request)
        if ( request.cookies.has_key?(consent_token.to_s) ||
             parse_cookies(headers[SET_COOKIE]).has_key?(consent_token.to_s) )
          true
        else
          false
        end
      end

      # Finish http response with proper headers
      def finish
        headers.delete(SET_COOKIE) if headers[SET_COOKIE] && headers[SET_COOKIE].empty?
        if [204, 304].include?(status.to_i) || (status.to_i / 100 == 1)
          headers.delete "Content-Length"
          headers.delete "Content-Type"
          [status.to_i, headers, []]
        elsif env['REQUEST_METHOD'] == 'HEAD'
          [status.to_i, headers, []]
        else
          [status.to_i, headers, body]
        end
      end

      protected

      # Returns the response cookies converted to Hash
      #
      def parse_cookies cookie_string
        cookies = {}
        if cookie_string
          cookie_string = cookie_string.split("\n") if cookie_string.respond_to?(:to_str)
          cookie_string.each do |cookie|
            if pair = cookie.split(';').first
              key, value = pair.split('=').map { |v| ::Rack::Utils.unescape(v) }
              cookies[key] = value
            end
          end
        end
        cookies
      end

      def filtered_cookie_string cookie_string
        parse_cookies(cookie_string).select do |key, _|
          white_list.include? key
        end.map do |key, value|
          "#{key}=#{value}"
        end.join ";"
      end

      def clear_cookies!(request, response)
        cookies = parse_cookies headers[SET_COOKIE]
        headers[SET_COOKIE] = filtered_cookie_string headers[SET_COOKIE]
        revalidate_cache!

        cookies.merge(request.cookies).each do |key, value|
          response.delete_cookie key.to_sym unless white_list.include? key.to_s
        end

        headers
      end

      def revalidate_cache!
        headers.merge!({ CACHE_CONTROL => 'must-revalidate, max-age=0' })
      end

      def set_cookie(key, value)
        ::Rack::Utils.set_cookie_header!(headers, key, value)
      end

      def delete_cookie(key, value)
        ::Rack::Utils.delete_cookie_header!(headers, key, value)
      end

    end # CookieLimiter
  end # Policy
end # Rack
